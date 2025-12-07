# Implementation Plan v3: `llm-fs-tools` (TOCTOU-Resistant Architecture)

## Overview
Standalone Python package providing **TOCTOU-resistant** filesystem access tools for LLMs with built-in security governance. Provider-agnostic, works with Ollama, OpenAI, Anthropic, etc.

**Key Improvements from v2:**
- **File descriptor-based validation** (eliminates TOCTOU)
- **O_NOFOLLOW enforcement** on Unix
- **Centralized security decorator** (non-global state)
- **Atomic open-validate-use pattern**
- **Platform-specific hardening** (Unix/Windows)

---

## Core Security Architecture

### TOCTOU Elimination Strategy

**Problem:** Classic TOCTOU attack:
```python
# BAD - Race condition
if is_safe(path):     # Check
    data = read(path)  # Use  <- File replaced here!
```

**Solution:** File descriptor-based validation:
```python
# GOOD - Atomic
fd = open(path, O_NOFOLLOW)  # Open with symlink protection
validate_fd(fd)              # Validate the SAME file
data = read_from_fd(fd)      # Use the SAME file
close(fd)
```

---

## Package Structure

```
llm-fs-tools/
├── pyproject.toml
├── README.md
├── LICENSE
├── SECURITY.md              # Threat model documentation
├── llm_fs_tools/
│   ├── __init__.py          # Public API exports
│   ├── core/
│   │   ├── __init__.py
│   │   ├── secure_file.py   # SecureFile wrapper (FD-based)
│   │   ├── tools.py         # Tool implementations
│   │   ├── security.py      # SecurityPolicy (stateless validator)
│   │   ├── schemas.py       # Dynamic schema generation
│   │   └── executor.py      # Tool execution engine
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── path_utils.py    # Path normalization
│   │   ├── fd_utils.py      # FD validation (Unix/Windows)
│   │   └── audit.py         # Audit logging
│   └── exceptions.py        # Custom exceptions
├── tests/
│   ├── unit/
│   │   ├── test_secure_file.py      # FD-based validation
│   │   ├── test_security_policy.py  # Policy engine
│   │   ├── test_tools.py
│   │   └── test_toctou_attacks.py   # TOCTOU attack scenarios
│   ├── integration/
│   │   ├── test_full_workflow.py
│   │   ├── test_provider_compat.py
│   │   └── test_cross_platform.py
│   └── fixtures/
│       ├── sample_codebase/
│       ├── symlink_maze/          # Symlink attack scenarios
│       └── toctou_simulator/      # TOCTOU simulation
└── examples/
    ├── ollama_integration.py
    ├── openai_integration.py
    └── secure_file_usage.py
```

---

## Phase 1: Secure File Abstraction (Week 1, Day 1-3)

### 1.1 SecureFile Class (`secure_file.py`)

```python
import os
import stat
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

class SecureFile:
    """
    TOCTOU-resistant file wrapper.

    Holds an open file descriptor and its validated metadata.
    All operations use the FD, never re-resolving paths.
    """

    def __init__(
        self,
        fd: int,
        original_path: Path,
        real_path: Path,
        stat_info: os.stat_result
    ):
        self.fd = fd
        self.original_path = original_path
        self.real_path = real_path  # Validated canonical path
        self.stat = stat_info

    def read_all(self, encoding: str = 'utf-8') -> str:
        """Read entire file using FD"""
        # Seek to beginning
        os.lseek(self.fd, 0, os.SEEK_SET)
        data = os.read(self.fd, self.stat.st_size)
        return data.decode(encoding, errors='replace')

    def read_lines(
        self,
        start: Optional[int] = None,
        end: Optional[int] = None
    ) -> list[str]:
        """Read lines with optional range"""
        content = self.read_all()
        lines = content.splitlines(keepends=True)

        if start is not None or end is not None:
            start_idx = (start - 1) if start else 0
            end_idx = end if end else len(lines)
            lines = lines[start_idx:end_idx]

        return lines

    def __enter__(self):
        return self

    def __exit__(self, *args):
        os.close(self.fd)

    def __repr__(self):
        return f"SecureFile(fd={self.fd}, path={self.real_path})"


@contextmanager
def secure_open(
    path: str | Path,
    policy: 'SecurityPolicy',
    flags: int = os.O_RDONLY
) -> SecureFile:
    """
    Atomically open and validate a file, preventing TOCTOU.

    Process:
    1. Pre-validate path structure (policy checks)
    2. Open with O_NOFOLLOW (Unix) or equivalent (Windows)
    3. Post-validate FD (verify file type, permissions, containment)
    4. Return validated SecureFile

    Raises:
        SecurityError: If any validation fails
    """
    from .security import SecurityError
    from .utils.fd_utils import secure_open_platform

    path = Path(path)

    # Step 1: Pre-validation (cheap checks before opening)
    validated_path = policy.pre_validate_path(path)

    # Step 2: Platform-specific secure open
    fd, real_path = secure_open_platform(validated_path, flags)

    try:
        # Step 3: Post-validation on FD
        stat_info = os.fstat(fd)

        # Verify it's a regular file
        if not stat.S_ISREG(stat_info.st_mode):
            raise SecurityError(
                f"Not a regular file: {path} "
                f"(mode: {stat.filemode(stat_info.st_mode)})"
            )

        # Verify size limit
        size_mb = stat_info.st_size / (1024 * 1024)
        if size_mb > policy.max_file_size_mb:
            raise SecurityError(
                f"File too large: {size_mb:.2f}MB > {policy.max_file_size_mb}MB"
            )

        # Verify containment (FD-based check)
        if not policy.verify_fd_containment(fd, real_path):
            raise SecurityError(f"FD verification failed: path outside allowed roots")

        # Verify no blocked patterns match
        if policy.matches_blocked_pattern(real_path):
            raise SecurityError(f"Path matches blocked pattern: {real_path}")

        # All checks passed - create SecureFile
        sfile = SecureFile(fd, path, real_path, stat_info)

        # Log audit trail
        if policy.audit:
            policy.audit.log_access("open", str(path), True)

        return sfile

    except Exception as e:
        # Clean up FD on validation failure
        os.close(fd)

        # Log security violation
        if hasattr(policy, 'audit') and policy.audit:
            policy.audit.log_access("open", str(path), False, str(e))

        raise
```

### 1.2 Platform-Specific FD Validation (`utils/fd_utils.py`)

```python
import os
import stat
from pathlib import Path

def secure_open_platform(path: Path, flags: int) -> tuple[int, Path]:
    """
    Platform-specific secure file opening.

    Returns:
        (file_descriptor, real_canonical_path)
    """
    if os.name == 'posix':
        return _secure_open_unix(path, flags)
    else:
        return _secure_open_windows(path, flags)


def _secure_open_unix(path: Path, flags: int) -> tuple[int, Path]:
    """
    Unix secure open with O_NOFOLLOW.

    O_NOFOLLOW prevents following symlinks during open,
    blocking symlink-based attacks.
    """
    # Resolve path strictly (must exist)
    real_path = path.resolve(strict=True)

    # Open with NOFOLLOW - fails if path is symlink
    fd = os.open(real_path, flags | os.O_NOFOLLOW)

    # Verify using /proc/self/fd (Linux) if available
    if Path('/proc/self/fd').exists():
        fd_path = Path(f'/proc/self/fd/{fd}').readlink()
        if fd_path != real_path:
            os.close(fd)
            raise OSError(f"FD path mismatch: expected {real_path}, got {fd_path}")

    return fd, real_path


def _secure_open_windows(path: Path, flags: int) -> tuple[int, Path]:
    """
    Windows secure open with symlink protection.

    Uses FILE_FLAG_OPEN_REPARSE_POINT to prevent symlink traversal.
    """
    real_path = path.resolve(strict=True)

    # Windows doesn't have O_NOFOLLOW, but we can check after opening
    fd = os.open(real_path, flags | os.O_BINARY)

    # Verify using GetFileInformationByHandle
    # (Could use ctypes to call Windows API if needed)
    stat_info = os.fstat(fd)

    # Basic verification - not a directory
    if stat.S_ISDIR(stat_info.st_mode):
        os.close(fd)
        raise OSError(f"Path is a directory: {real_path}")

    return fd, real_path
```

### 1.3 Stateless SecurityPolicy (`security.py`)

```python
from pathlib import Path
from typing import Optional, Callable
import fnmatch
import os

class SecurityPolicy:
    """
    Stateless security policy validator.

    No global state - each FileSystemTools instance has its own policy.
    """

    def __init__(
        self,
        allowed_roots: list[str],
        max_file_size_mb: int = 5,
        max_directory_entries: int = 10000,
        blocked_patterns: list[str] = None,
        blocked_extensions: list[str] = None,
        case_sensitive: Optional[bool] = None,
        custom_validator: Optional[Callable[[Path], bool]] = None,
        audit: Optional['AuditLogger'] = None
    ):
        # Resolve and store allowed roots
        self.allowed_roots = [Path(r).resolve(strict=True) for r in allowed_roots]
        self.max_file_size_mb = max_file_size_mb
        self.max_directory_entries = max_directory_entries
        self.blocked_patterns = blocked_patterns or self._default_blocked_patterns()
        self.blocked_extensions = [e.lower() for e in (blocked_extensions or [])]
        self.case_sensitive = case_sensitive if case_sensitive is not None else self._detect_case_sensitivity()
        self.custom_validator = custom_validator
        self.audit = audit

    def pre_validate_path(self, path: Path) -> Path:
        """
        Pre-validation before opening file.

        Cheap checks that don't require file to exist:
        - Unicode normalization
        - Blocked extensions
        - Custom validator

        Returns:
            Normalized path ready for opening
        """
        from unicodedata import normalize

        # Normalize unicode
        path_str = normalize('NFC', str(path))
        path_obj = Path(path_str)

        # Check extension
        if path_obj.suffix.lower() in self.blocked_extensions:
            raise SecurityError(f"Blocked extension: {path_obj.suffix}")

        # Custom validator
        if self.custom_validator and not self.custom_validator(path_obj):
            raise SecurityError(f"Custom validation failed: {path_obj}")

        return path_obj

    def verify_fd_containment(self, fd: int, real_path: Path) -> bool:
        """
        Verify file descriptor points to file within allowed roots.

        Uses FD-based verification to prevent TOCTOU.
        """
        # Check if real_path is within any allowed root
        for root in self.allowed_roots:
            try:
                real_path.relative_to(root)
                return True  # Path is within this root
            except ValueError:
                continue  # Try next root

        return False  # Not within any allowed root

    def matches_blocked_pattern(self, path: Path) -> bool:
        """Check if path matches any blocked pattern"""
        path_str = str(path)
        if not self.case_sensitive:
            path_str = path_str.lower()

        for pattern in self.blocked_patterns:
            pattern_str = pattern if self.case_sensitive else pattern.lower()
            if fnmatch.fnmatch(path_str, pattern_str):
                return True

        return False

    @staticmethod
    def _detect_case_sensitivity() -> bool:
        """Auto-detect filesystem case sensitivity"""
        import tempfile
        with tempfile.NamedTemporaryFile(prefix='TeSt') as tmp:
            return not Path(tmp.name.lower()).exists()

    @staticmethod
    def _default_blocked_patterns() -> list[str]:
        """Default security patterns (case variants included)"""
        return [
            "*.env", "*.ENV",
            "*.key", "*.KEY",
            "*.pem", "*.PEM",
            "*.secret", "*.SECRET",
            ".git/*", ".Git/*",
            "node_modules/*",
            "__pycache__/*",
            ".venv/*", "venv/*",
            ".DS_Store", "Thumbs.db"
        ]


class SecurityError(Exception):
    """Security policy violation"""
    pass
```

---

## Phase 2: Tool Implementations with Instance-Based Registry (Week 1-2)

### 2.1 Instance-Based Tool Registry (`tools.py`)

```python
from typing import Callable, Any, Optional
import inspect
from functools import wraps

class ToolRegistry:
    """
    Instance-based tool registry (non-global).

    Each FileSystemTools instance has its own registry.
    """

    def __init__(self):
        self.tools = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: dict
    ):
        """Decorator to register a tool"""
        def decorator(func: Callable) -> Callable:
            self.tools[name] = {
                'function': func,
                'description': description,
                'parameters': parameters
            }
            return func
        return decorator

    def get_schemas(self, format: str, enabled_tools: Optional[list[str]] = None) -> list[dict]:
        """Generate schemas for enabled tools"""
        from .schemas import format_tool_schema

        tools_to_export = enabled_tools or list(self.tools.keys())
        schemas = []

        for name in tools_to_export:
            if name in self.tools:
                tool_info = self.tools[name]
                schema = format_tool_schema(
                    name=name,
                    description=tool_info['description'],
                    parameters=tool_info['parameters'],
                    format=format
                )
                schemas.append(schema)

        return schemas


class FileSystemTools:
    """Filesystem tools with FD-based security"""

    def __init__(
        self,
        security_policy: SecurityPolicy,
        enabled_tools: Optional[list[str]] = None
    ):
        self.policy = security_policy
        self.registry = ToolRegistry()
        self.enabled_tools = enabled_tools

        # Register tools on init (instance-specific)
        self._register_tools()

    def _register_tools(self):
        """Register all available tools"""

        @self.registry.register(
            name="read_file",
            description="Reads file content with optional line ranges",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File to read"},
                    "start_line": {"type": "integer", "description": "First line (1-indexed)"},
                    "end_line": {"type": "integer", "description": "Last line (inclusive)"}
                },
                "required": ["path"]
            }
        )
        def read_file_impl(path: str, start_line: Optional[int] = None, end_line: Optional[int] = None) -> dict:
            """Implementation using SecureFile"""
            from .secure_file import secure_open

            try:
                with secure_open(path, self.policy) as sfile:
                    lines = sfile.read_lines(start_line, end_line)

                    # Format with line numbers
                    numbered = [f"{i+1:4d} | {line}" for i, line in enumerate(lines)]
                    content = ''.join(numbered)

                    return {
                        "success": True,
                        "data": {
                            "content": content,
                            "lines": len(lines),
                            "path": str(sfile.real_path)
                        },
                        "error": None,
                        "metadata": {
                            "tool": "read_file",
                            "size_bytes": sfile.stat.st_size
                        }
                    }
            except Exception as e:
                return self._error_response("read_file", str(e))

        # Additional tools registered similarly...

    def get_tool_definitions(self, format: str = "openai") -> list[dict]:
        """Get tool schemas for LLM"""
        return self.registry.get_schemas(format, self.enabled_tools)

    def execute(self, tool_name: str, arguments: dict) -> dict:
        """Execute a registered tool"""
        if tool_name not in self.registry.tools:
            return self._error_response(tool_name, "Unknown tool")

        if self.enabled_tools and tool_name not in self.enabled_tools:
            return self._error_response(tool_name, "Tool not enabled")

        tool_func = self.registry.tools[tool_name]['function']

        try:
            return tool_func(**arguments)
        except Exception as e:
            return self._error_response(tool_name, str(e))

    @staticmethod
    def _error_response(tool: str, error: str) -> dict:
        """Standardized error response"""
        return {
            "success": False,
            "data": None,
            "error": error,
            "metadata": {"tool": tool}
        }
```

---

## Phase 3: Testing Strategy (TDD - Concurrent)

### 3.1 Critical TOCTOU Tests (`tests/unit/test_toctou_attacks.py`)

```python
import pytest
import os
import time
from pathlib import Path
from threading import Thread

def test_symlink_replacement_attack(tmp_path):
    """
    Simulate attacker replacing file with symlink between check and use.

    With FD-based validation, this attack fails.
    """
    # Setup
    real_file = tmp_path / "real.txt"
    real_file.write_text("safe content")

    target = tmp_path / "target.txt"
    target.write_text("initial content")

    # Attack simulation
    def replace_with_symlink():
        time.sleep(0.01)  # Wait for validation to start
        target.unlink()
        target.symlink_to(real_file)  # Replace with symlink

    # Start attack thread
    Thread(target=replace_with_symlink, daemon=True).start()

    # Attempt to open target
    # With FD validation, this should either:
    # 1. Open the original file (if opened before replacement)
    # 2. Fail with SecurityError (if O_NOFOLLOW catches symlink)

    # Either way, it should NOT read real_file content
    from llm_fs_tools.core.secure_file import secure_open
    from llm_fs_tools.core.security import SecurityPolicy

    policy = SecurityPolicy(allowed_roots=[str(tmp_path)])

    # This should NOT return "safe content"
    result = None
    try:
        with secure_open(target, policy) as sfile:
            result = sfile.read_all()
    except Exception:
        pass  # Expected if O_NOFOLLOW catches symlink

    assert result != "safe content"  # Attack failed

def test_fd_based_operations_immune_to_replacement(tmp_path):
    """
    Verify that once FD is opened, file replacement doesn't affect reads.
    """
    target = tmp_path / "target.txt"
    target.write_text("original content")

    from llm_fs_tools.core.secure_file import secure_open
    from llm_fs_tools.core.security import SecurityPolicy

    policy = SecurityPolicy(allowed_roots=[str(tmp_path)])

    with secure_open(target, policy) as sfile:
        # Replace file while FD is open
        target.write_text("replaced content")

        # Read via FD - should get original content
        content = sfile.read_all()
        assert content == "original content"  # FD points to original inode
```

---

## Phase 4: Implementation Timeline (Realistic)

### Week 1: Secure Foundation
**Day 1-2:** SecureFile + FD utils (TDD)
- Write tests for secure_open
- Implement Unix/Windows variants
- Test symlink/TOCTOU scenarios

**Day 3-4:** SecurityPolicy (stateless)
- Write policy tests
- Implement pre-validation, FD containment checks
- Test blocked patterns, case sensitivity

**Day 5:** First tool (read_file)
- Write read_file tests
- Implement with SecureFile
- Integration test

### Week 2: Tool Suite
**Day 1:** get_directory_tree
**Day 2:** search_codebase
**Day 3:** list_directory
**Day 4:** Dynamic schema generation
**Day 5:** Full integration tests

### Week 3: Security Audit
**Day 1-2:** External security review
**Day 3-4:** Hardening
**Day 5:** Performance testing

### Week 4: ollama-prompt Integration
**Day 1-2:** Parser + handler updates
**Day 3-4:** Integration testing
**Day 5:** End-to-end workflows

### Week 5: Beta Release
**Day 1-2:** Documentation
**Day 3:** Beta publish (0.1.0-beta.1)
**Day 4-5:** Beta testing

### Week 6: Production Release
**Day 1-2:** Beta feedback
**Day 3:** Final testing
**Day 4:** PyPI publish (0.1.0)
**Day 5:** Announcement

---

## Success Criteria

- [ ] All TOCTOU attack tests pass
- [ ] O_NOFOLLOW enforced on Unix
- [ ] FD-based validation on all platforms
- [ ] No global state in registry
- [ ] 90%+ test coverage (including attack scenarios)
- [ ] Security audit approval
- [ ] Works with Ollama, OpenAI, Anthropic
- [ ] ollama-prompt integration tested
- [ ] Beta testing with 5+ users
- [ ] Clear threat model documentation

---
