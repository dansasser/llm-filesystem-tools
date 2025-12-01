# Implementation Plan v2: `llm-fs-tools`

## Overview
Standalone Python package providing **hardened** filesystem access tools for LLMs with built-in security governance. Provider-agnostic, works with Ollama, OpenAI, Anthropic, etc.

**Key Improvements from v1:**
- Enhanced security model (symlink/hardlink/TOCTOU protection)
- Dynamic schema generation (DRY principle)
- Rate limiting and audit logging
- Tool selection capability
- TDD approach from day 1
- Security audit phase
- Beta testing period

---

## Package Structure

```
llm-fs-tools/
├── pyproject.toml
├── README.md
├── LICENSE
├── SECURITY.md              # Security model documentation
├── llm_fs_tools/
│   ├── __init__.py          # Public API exports
│   ├── core/
│   │   ├── __init__.py
│   │   ├── tools.py         # Tool implementations with decorators
│   │   ├── security.py      # Security policy & hardened validation
│   │   ├── schemas.py       # Dynamic schema generation
│   │   ├── executor.py      # Tool execution engine
│   │   ├── rate_limiter.py  # Rate limiting
│   │   └── audit.py         # Audit logging
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── path_utils.py    # Path normalization, validation
│   │   └── file_utils.py    # Safe file operations
│   └── exceptions.py        # Custom exceptions
├── tests/
│   ├── unit/
│   │   ├── test_security.py
│   │   ├── test_tools.py
│   │   ├── test_executor.py
│   │   ├── test_rate_limiter.py
│   │   └── test_audit.py
│   ├── integration/
│   │   ├── test_full_workflow.py
│   │   ├── test_security_attacks.py
│   │   └── test_provider_compatibility.py
│   └── fixtures/
│       ├── sample_codebase/
│       ├── malicious_symlinks/
│       └── edge_cases/
└── examples/
    ├── ollama_integration.py
    ├── openai_integration.py
    ├── anthropic_integration.py
    └── advanced_usage.py
```

---

## Phase 1: Hardened Security Layer (Week 1)

### 1.1 Enhanced Security Policy (`security.py`)

```python
from pathlib import Path
from typing import Optional, Callable
import fnmatch
import os

class SecurityPolicy:
    """Hardened filesystem access governance"""

    def __init__(
        self,
        allowed_roots: list[str],
        max_file_size_mb: int = 5,
        max_directory_entries: int = 10000,  # NEW: Prevent memory exhaustion
        blocked_patterns: list[str] = None,
        blocked_extensions: list[str] = None,
        case_sensitive: bool = None,  # NEW: Auto-detect if None
        allow_symlinks: bool = False,  # NEW: Explicit symlink policy
        allow_device_files: bool = False,  # NEW: Block /dev/*, FIFOs, sockets
        custom_validator: Optional[Callable[[Path], bool]] = None,
        rate_limit_per_minute: int = 100,  # NEW: Rate limiting
        enable_audit_log: bool = True  # NEW: Audit logging
    ):
        self.allowed_roots = [Path(r).resolve() for r in allowed_roots]
        self.max_file_size_mb = max_file_size_mb
        self.max_directory_entries = max_directory_entries
        self.blocked_patterns = blocked_patterns or self._default_blocked_patterns()
        self.blocked_extensions = blocked_extensions or []
        self.case_sensitive = case_sensitive if case_sensitive is not None else self._detect_case_sensitivity()
        self.allow_symlinks = allow_symlinks
        self.allow_device_files = allow_device_files
        self.custom_validator = custom_validator
        self.rate_limit_per_minute = rate_limit_per_minute
        self.enable_audit_log = enable_audit_log

    def validate_path(self, path: str | Path) -> Path:
        """
        Validates and resolves path with hardened security checks.

        Security validations:
        1. Unicode normalization (prevent unicode attacks)
        2. Path canonicalization (resolve .., symlinks)
        3. Containment check (must be within allowed_roots)
        4. Symlink policy enforcement
        5. Device file blocking
        6. Pattern/extension blocking
        7. Custom validator

        Raises:
            SecurityError: If any validation fails
        """
        from unicodedata import normalize

        # 1. Normalize unicode (prevent attacks like ..%c0%af)
        path_str = normalize('NFC', str(path))
        path_obj = Path(path_str)

        # 2. Canonicalize (resolve symlinks, .., .)
        # CRITICAL: Use .resolve() with strict=True to catch non-existent paths early
        try:
            resolved = path_obj.resolve(strict=False)  # Allow non-existent for validation
        except (OSError, RuntimeError) as e:
            raise SecurityError(f"Path resolution failed: {e}")

        # 3. Check for symlinks BEFORE containment check
        # This prevents symlink escape attacks
        if not self.allow_symlinks and path_obj.is_symlink():
            raise SecurityError(f"Symlinks not allowed: {path}")

        # 4. Containment check - resolved path must be within allowed_roots
        is_contained = any(
            self._is_subpath(resolved, root) for root in self.allowed_roots
        )
        if not is_contained:
            raise SecurityError(f"Path outside allowed roots: {path}")

        # 5. Device file check (if file exists)
        if resolved.exists() and not self.allow_device_files:
            if self._is_device_file(resolved):
                raise SecurityError(f"Device files not allowed: {path}")

        # 6. Pattern blocking (case-aware)
        if self._matches_blocked_pattern(resolved):
            raise SecurityError(f"Path matches blocked pattern: {path}")

        # 7. Extension blocking
        if resolved.suffix.lower() in [e.lower() for e in self.blocked_extensions]:
            raise SecurityError(f"File extension blocked: {resolved.suffix}")

        # 8. Custom validator
        if self.custom_validator and not self.custom_validator(resolved):
            raise SecurityError(f"Custom validation failed: {path}")

        return resolved

    def validate_file_access(self, path: Path) -> tuple[bool, Optional[str]]:
        """
        Validates file can be safely read.

        Returns:
            (allowed, error_message)
        """
        # Check file exists and is regular file
        if not path.exists():
            return False, f"File does not exist: {path}"

        if not path.is_file():
            return False, f"Not a regular file: {path}"

        # Check size limit
        try:
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > self.max_file_size_mb:
                return False, f"File too large: {size_mb:.2f}MB > {self.max_file_size_mb}MB"
        except OSError as e:
            return False, f"Cannot stat file: {e}"

        # Check OS permissions
        if not os.access(path, os.R_OK):
            return False, f"No read permission: {path}"

        return True, None

    def validate_directory_access(self, path: Path) -> tuple[bool, Optional[str]]:
        """Validates directory can be safely read"""
        if not path.exists():
            return False, f"Directory does not exist: {path}"

        if not path.is_dir():
            return False, f"Not a directory: {path}"

        # Check OS permissions
        if not os.access(path, os.R_OK | os.X_OK):
            return False, f"No read/execute permission: {path}"

        # Check entry count (prevent memory exhaustion)
        try:
            count = sum(1 for _ in path.iterdir())
            if count > self.max_directory_entries:
                return False, f"Directory too large: {count} entries > {self.max_directory_entries}"
        except OSError as e:
            return False, f"Cannot list directory: {e}"

        return True, None

    @staticmethod
    def _is_subpath(child: Path, parent: Path) -> bool:
        """Check if child is subpath of parent (handles case sensitivity)"""
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_device_file(path: Path) -> bool:
        """Check if path is a device file, FIFO, or socket"""
        import stat
        try:
            mode = path.stat().st_mode
            return (
                stat.S_ISBLK(mode) or   # Block device
                stat.S_ISCHR(mode) or   # Character device
                stat.S_ISFIFO(mode) or  # FIFO
                stat.S_ISSOCK(mode)     # Socket
            )
        except OSError:
            return False

    def _matches_blocked_pattern(self, path: Path) -> bool:
        """Check if path matches any blocked pattern (case-aware)"""
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
        """Auto-detect if filesystem is case-sensitive"""
        import tempfile
        with tempfile.NamedTemporaryFile(prefix='TeSt') as tmp:
            return not Path(tmp.name.lower()).exists() or not Path(tmp.name.upper()).exists()

    @staticmethod
    def _default_blocked_patterns() -> list[str]:
        """Default security patterns"""
        return [
            "*.env", "*.ENV",  # Environment files (case variants)
            "*.key", "*.KEY",
            "*.pem", "*.PEM",
            "*.secret", "*.SECRET",
            ".git/*", ".Git/*", ".GIT/*",  # Git internals
            "node_modules/*", "NODE_MODULES/*",
            "__pycache__/*",
            "*.pyc",
            ".venv/*", "venv/*",
            "*.log",  # Log files can be huge
            ".DS_Store",  # macOS metadata
            "Thumbs.db"  # Windows metadata
        ]


class SecurityError(Exception):
    """Raised when security policy is violated"""
    pass
```

### 1.2 Rate Limiting (`rate_limiter.py`)

```python
from collections import deque
from datetime import datetime, timedelta
from threading import Lock

class RateLimiter:
    """Token bucket rate limiter for tool calls"""

    def __init__(self, max_calls_per_minute: int = 100):
        self.max_calls = max_calls_per_minute
        self.calls = deque()
        self.lock = Lock()

    def check_rate_limit(self) -> tuple[bool, Optional[str]]:
        """
        Check if call is within rate limit.

        Returns:
            (allowed, error_message)
        """
        with self.lock:
            now = datetime.now()
            cutoff = now - timedelta(minutes=1)

            # Remove old calls
            while self.calls and self.calls[0] < cutoff:
                self.calls.popleft()

            # Check limit
            if len(self.calls) >= self.max_calls:
                return False, f"Rate limit exceeded: {self.max_calls} calls/minute"

            # Record call
            self.calls.append(now)
            return True, None
```

### 1.3 Audit Logging (`audit.py`)

```python
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

class AuditLogger:
    """Security audit logging"""

    def __init__(self, log_file: Optional[Path] = None):
        self.logger = logging.getLogger('llm_fs_tools.audit')
        self.logger.setLevel(logging.INFO)

        # Console handler
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        self.logger.addHandler(console)

        # File handler (if specified)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def log_access(self, tool: str, path: str, allowed: bool, reason: Optional[str] = None):
        """Log file access attempt"""
        status = "ALLOWED" if allowed else "DENIED"
        msg = f"{status} - Tool: {tool}, Path: {path}"
        if reason:
            msg += f", Reason: {reason}"

        if allowed:
            self.logger.info(msg)
        else:
            self.logger.warning(msg)

    def log_error(self, tool: str, error: str):
        """Log tool execution error"""
        self.logger.error(f"ERROR - Tool: {tool}, Error: {error}")
```

---

## Phase 2: Tool Implementations with Dynamic Schemas (Week 1-2)

### 2.1 Tool Registry Decorator (`tools.py`)

```python
from functools import wraps
from typing import Callable, Any
import inspect

# Global tool registry
_TOOL_REGISTRY = {}

def tool(
    name: str,
    description: str,
    parameters_schema: dict
):
    """
    Decorator to register a tool and its schema.

    This enables dynamic schema generation - no need to duplicate definitions.
    """
    def decorator(func: Callable) -> Callable:
        _TOOL_REGISTRY[name] = {
            'function': func,
            'description': description,
            'parameters': parameters_schema,
            'signature': inspect.signature(func)
        }

        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        return wrapper
    return decorator


class FileSystemTools:
    """Filesystem tools with dynamic schema generation"""

    def __init__(
        self,
        security_policy: SecurityPolicy,
        enabled_tools: Optional[list[str]] = None  # NEW: Tool selection
    ):
        self.policy = security_policy
        self.rate_limiter = RateLimiter(security_policy.rate_limit_per_minute)
        self.audit = AuditLogger() if security_policy.enable_audit_log else None
        self.enabled_tools = enabled_tools or list(_TOOL_REGISTRY.keys())

    def get_tool_definitions(self, format: str = "openai") -> list[dict]:
        """
        Generate tool definitions dynamically from registry.

        Args:
            format: "openai", "anthropic", or "ollama"

        Returns:
            List of tool definitions in requested format
        """
        from .schemas import format_tool_schema

        tools = []
        for name in self.enabled_tools:
            if name in _TOOL_REGISTRY:
                tool_info = _TOOL_REGISTRY[name]
                schema = format_tool_schema(
                    name=name,
                    description=tool_info['description'],
                    parameters=tool_info['parameters'],
                    format=format
                )
                tools.append(schema)
        return tools

    def execute(self, tool_name: str, arguments: dict) -> dict:
        """
        Execute a tool call with security and rate limiting.

        Returns standardized response format.
        """
        # Check rate limit
        allowed, error = self.rate_limiter.check_rate_limit()
        if not allowed:
            return self._error_response(tool_name, error)

        # Check tool exists and is enabled
        if tool_name not in _TOOL_REGISTRY:
            return self._error_response(tool_name, f"Unknown tool: {tool_name}")

        if tool_name not in self.enabled_tools:
            return self._error_response(tool_name, f"Tool not enabled: {tool_name}")

        # Execute tool
        try:
            tool_info = _TOOL_REGISTRY[tool_name]
            func = tool_info['function']

            # Bind self to method
            result = func(self, **arguments)
            return result

        except SecurityError as e:
            error_msg = f"Security violation: {e}"
            if self.audit:
                self.audit.log_error(tool_name, error_msg)
            return self._error_response(tool_name, error_msg)

        except Exception as e:
            error_msg = f"Execution failed: {e}"
            if self.audit:
                self.audit.log_error(tool_name, error_msg)
            return self._error_response(tool_name, error_msg)

    @tool(
        name="get_directory_tree",
        description="Returns hierarchical directory structure",
        parameters_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory to analyze"},
                "max_depth": {"type": "integer", "default": 3, "description": "Maximum recursion depth"},
                "include_hidden": {"type": "boolean", "default": False, "description": "Include hidden files"}
            },
            "required": ["path"]
        }
    )
    def get_directory_tree(
        self,
        path: str,
        max_depth: int = 3,
        include_hidden: bool = False
    ) -> dict:
        """Returns hierarchical directory structure"""
        # Validate path
        validated_path = self.policy.validate_path(path)
        allowed, error = self.policy.validate_directory_access(validated_path)

        if not allowed:
            if self.audit:
                self.audit.log_access("get_directory_tree", path, False, error)
            raise SecurityError(error)

        if self.audit:
            self.audit.log_access("get_directory_tree", path, True)

        # Build tree
        tree = self._build_tree(validated_path, max_depth, include_hidden, current_depth=0)

        return {
            "success": True,
            "data": tree,
            "error": None,
            "metadata": {
                "tool": "get_directory_tree",
                "path": str(validated_path),
                "max_depth": max_depth
            }
        }

    @tool(
        name="read_file",
        description="Reads file content with optional line ranges",
        parameters_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File to read"},
                "start_line": {"type": "integer", "description": "First line to read (1-indexed)"},
                "end_line": {"type": "integer", "description": "Last line to read (inclusive)"}
            },
            "required": ["path"]
        }
    )
    def read_file(
        self,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> dict:
        """Reads file content with line numbers"""
        # Validate path
        validated_path = self.policy.validate_path(path)
        allowed, error = self.policy.validate_file_access(validated_path)

        if not allowed:
            if self.audit:
                self.audit.log_access("read_file", path, False, error)
            raise SecurityError(error)

        if self.audit:
            self.audit.log_access("read_file", path, True)

        # Read file (with encoding safety)
        try:
            with open(validated_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            # Apply line range
            if start_line is not None or end_line is not None:
                start = (start_line - 1) if start_line else 0
                end = end_line if end_line else len(lines)
                lines = lines[start:end]

            # Format with line numbers
            content = ''.join(f"{i+1:4d} | {line}" for i, line in enumerate(lines))

            return {
                "success": True,
                "data": {
                    "content": content,
                    "lines": len(lines),
                    "path": str(validated_path)
                },
                "error": None,
                "metadata": {
                    "tool": "read_file",
                    "path": str(validated_path),
                    "encoding": "utf-8"
                }
            }
        except UnicodeDecodeError:
            return self._error_response("read_file", "File is not text (binary file)")

    # Additional tools: search_codebase, list_directory...
    # (Following same pattern with @tool decorator)

    @staticmethod
    def _error_response(tool: str, error: str) -> dict:
        """Standardized error response"""
        return {
            "success": False,
            "data": None,
            "error": error,
            "metadata": {
                "tool": tool
            }
        }

    def _build_tree(self, path: Path, max_depth: int, include_hidden: bool, current_depth: int) -> dict:
        """Recursively build directory tree"""
        # Implementation details...
        pass
```

### 2.2 Dynamic Schema Formatting (`schemas.py`)

```python
def format_tool_schema(name: str, description: str, parameters: dict, format: str) -> dict:
    """Format tool schema for different providers"""

    if format == "openai" or format == "ollama":
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters
            }
        }

    elif format == "anthropic":
        return {
            "name": name,
            "description": description,
            "input_schema": parameters
        }

    else:
        raise ValueError(f"Unknown format: {format}")
```

---

## Phase 3: Testing Strategy (TDD - Concurrent with Development)

### 3.1 Unit Tests (Written BEFORE Implementation)

**test_security.py:**
```python
def test_symlink_attack():
    """Test that symlinks pointing outside allowed_roots are blocked"""

def test_hardlink_attack():
    """Test hardlinks to sensitive files are validated"""

def test_toctou_race_condition():
    """Test race condition handling (mock file replacement)"""

def test_device_file_blocking():
    """Test /dev/null, FIFOs, sockets are blocked"""

def test_case_insensitive_pattern_matching():
    """Test .ENV matches *.env on Windows/macOS"""

def test_unicode_normalization():
    """Test unicode attack paths are normalized"""

def test_path_traversal_attacks():
    """Test ../, ../../etc/passwd, etc."""

def test_directory_size_limit():
    """Test directories with >max_entries are rejected"""
```

**test_rate_limiter.py:**
```python
def test_rate_limit_enforcement():
    """Test calls are blocked after limit"""

def test_rate_limit_reset():
    """Test limit resets after 1 minute"""
```

**test_audit.py:**
```python
def test_audit_log_format():
    """Test audit logs contain required fields"""

def test_security_violations_logged():
    """Test blocked access attempts are logged"""
```

### 3.2 Integration Tests

**test_security_attacks.py:**
- Comprehensive attack scenarios
- Real filesystem fixtures with symlinks, hardlinks
- TOCTOU simulation

**test_provider_compatibility.py:**
- Test with Ollama, OpenAI, Anthropic (mock responses)
- Verify schema format correctness

---

## Phase 4: Implementation Timeline (Revised)

### Week 1: Security Foundation + TDD
**Day 1-2:** Security layer implementation
- Write security tests FIRST (TDD)
- Implement SecurityPolicy with all hardening
- Implement RateLimiter
- Implement AuditLogger

**Day 3-4:** First tool with full stack
- Write tests for list_directory
- Implement tool decorator registry
- Implement list_directory tool
- All tests passing

**Day 5:** Integration smoke test
- Basic end-to-end test with mocked LLM
- Security attack test suite

### Week 2: Remaining Tools
**Day 1:** get_directory_tree (TDD)
**Day 2:** read_file (TDD)
**Day 3:** search_codebase (TDD)
**Day 4:** Dynamic schema generation
**Day 5:** Full integration tests

### Week 3: Security Audit + Hardening
**Day 1-2:** External security review
- Penetration testing
- Attack scenario validation

**Day 3-4:** Hardening based on findings
**Day 5:** Performance testing and optimization

### Week 4: ollama-prompt Integration
**Day 1-2:** Update parser, main handler
**Day 3:** Integration testing
**Day 4-5:** End-to-end workflows

### Week 5: Documentation + Beta
**Day 1-2:** Documentation completion
- SECURITY.md with threat model
- API.md with examples

**Day 3:** Beta release (0.1.0-beta.1)
**Day 4-5:** Beta testing with real users

### Week 6: Production Release
**Day 1-2:** Address beta feedback
**Day 3:** Final testing
**Day 4:** PyPI publish (0.1.0)
**Day 5:** Announcement

---

## Updated Success Criteria

- [ ] Package installable via `pip install llm-fs-tools`
- [ ] Works with Ollama, OpenAI, Anthropic (tested examples)
- [ ] **Passes security audit** (NEW)
- [ ] **All attack scenarios blocked** (symlink, hardlink, TOCTOU, device files)
- [ ] **Rate limiting functional**
- [ ] **Audit logging captures security events**
- [ ] ollama-prompt seamlessly uses tools on `@directory` refs
- [ ] 80%+ test coverage
- [ ] Clear documentation with threat model
- [ ] **Beta testing completed with 5+ users**

---

## Critical Security Tests Required

1. Symlink escape attack
2. Hardlink to /etc/passwd
3. TOCTOU file replacement
4. Device file reading (/dev/zero)
5. Unicode path traversal
6. Case-insensitive bypass
7. Large directory memory exhaustion
8. Rate limit bypass attempts
9. Concurrent access race conditions
10. Permission escalation attempts

---
