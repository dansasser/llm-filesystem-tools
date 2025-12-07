# Implementation Plan v5.01: `llm-fs-tools` - Path to Production

**Version:** 5.01
**Date:** 2025-12-06
**Status:** 90% Complete - Integration Layer Remaining
**Base:** implementation-plan-v5.md + implementation-plan-v5-updates.md

---

## Overview

Standalone Python package providing **secure directory-level filesystem access** for LLMs. Primary integration target: `ollama-prompt` to replace individual file access with secure R/W directory sandbox.

**Core Value Proposition:**
```
BEFORE: @./file.py -> single file read
AFTER:  @./project/ -> secure directory sandbox (list, tree, search, read, write)
```

---

## Implementation Status

### Legend
- ~~Strikethrough~~ = COMPLETE
- **Bold** = IN PROGRESS
- Regular = PENDING

---

## Phase 1: Security Foundation - COMPLETE

### ~~1.1 Security Policy (`core/security.py`)~~ - DONE

~~**Protocol Interface:**~~
```python
# IMPLEMENTED: Lines 13-71
class SecurityPolicy(Protocol):
    def pre_validate_syntax(self, path: Path) -> Path: ...
    def post_validate_fd(self, fd: int, real_path: Path, stat_info: os.stat_result) -> None: ...
    def can_write(self, path: Path) -> bool: ...
```

~~**Implementation:**~~
```python
# IMPLEMENTED: Lines 74-287
class FileSystemPolicy:
    - allowed_roots: list[Path]
    - max_file_size_mb: int
    - max_directory_entries: int
    - blocked_patterns: list[str]
    - blocked_extensions: list[str]
    - allow_write: bool
    - writable_roots: list[Path]
    - audit_logger: Optional[AuditLogger]
```

---

### ~~1.2 Platform-Specific Secure Open (`platform/secure_open.py`)~~ - DONE

~~**Unix Implementation:**~~
```python
# IMPLEMENTED: Lines 25-64
def secure_open_unix(path: Path, flags: int) -> tuple[int, Path]:
    - O_NOFOLLOW flag to block symlinks
    - Linux: /proc/self/fd for canonical path
    - macOS: fcntl F_GETPATH for canonical path
```

~~**Windows Implementation:**~~
```python
# IMPLEMENTED: Lines 67-145
def secure_open_windows(path: Path, flags: int) -> tuple[int, Path]:
    - FILE_FLAG_OPEN_REPARSE_POINT
    - FILE_ATTRIBUTE_REPARSE_POINT detection
    - GetFinalPathNameByHandle for canonical path
```

~~**Platform Selector:**~~
```python
# IMPLEMENTED: Lines 148-162
def secure_open(path: Path, flags: int = os.O_RDONLY) -> tuple[int, Path]:
    - Routes to Unix or Windows implementation
```

---

### ~~1.3 File Handle Abstraction (`core/file_handle.py`)~~ - PARTIAL

~~**SecureFileHandle Class:**~~
```python
# IMPLEMENTED: Lines 12-76
class SecureFileHandle:
    - read_all(encoding) -> str
    - read_lines(start, end) -> list[str]
    - Context manager support
    - Automatic FD cleanup
```

~~**open_secure Context Manager:**~~
```python
# IMPLEMENTED: Lines 79-123
@contextmanager
def open_secure(path, policy) -> SecureFileHandle:
    - Syntax validation
    - Platform-specific secure open
    - FD-based security checks
```

**PENDING: read_limited() method** - See Production Path

---

## Phase 2: Read Tools - COMPLETE

### ~~2.1 Read-Only Tools (`core/tools.py`)~~ - DONE

~~**FileSystemTools Class:**~~
```python
# IMPLEMENTED: Lines 21-468
class FileSystemTools:
    - read_file(path, start_line, end_line) -> dict
    - list_directory(path, include_hidden) -> dict
    - get_directory_tree(path, max_depth, include_hidden) -> dict
    - search_codebase(pattern, path, file_pattern, case_sensitive, max_results) -> dict
```

~~**Response Format:**~~
```python
# IMPLEMENTED in all methods
{
    "success": True,
    "data": {...},
    "metadata": {"tool": "...", "path": "..."}
}
```

---

## Phase 3: Write Tools - COMPLETE

### ~~3.1 Write Tools (`core/write_tools.py`)~~ - DONE

~~**FileSystemWriteTools Class:**~~
```python
# IMPLEMENTED: Lines 19-357
class FileSystemWriteTools:
    - write_file(path, content, encoding, create_dirs) -> dict
    - delete_file(path) -> dict
    - create_directory(path, parents) -> dict  # BONUS
```

~~**Atomic Operations:**~~
```python
# IMPLEMENTED: Lines 126-141
- Uses tempfile.mkstemp() in same directory
- Atomic rename via Path.replace()
```

---

## Phase 4: Audit & Streaming - COMPLETE

### ~~4.1 Audit Logger (`utils/audit.py`)~~ - DONE

~~**AuditLogger Classes:**~~
```python
# IMPLEMENTED: Lines 17-280
class AuditLogger:        # File + console logging
class NullAuditLogger:    # Discards all logs
class MemoryAuditLogger:  # In-memory for testing
```

### ~~4.2 Streaming Support (`utils/streaming.py`)~~ - DONE

~~**StreamingFileReader:**~~
```python
# IMPLEMENTED: Lines 18-182
class StreamingFileReader:
    - stream_file(path, encoding) -> Iterator[str]
    - stream_bytes(path) -> Iterator[bytes]
    - stream_lines(path, encoding) -> Iterator[str]
    - stream_lines_numbered(path, encoding, start) -> Iterator[tuple]
    - count_lines(path, encoding) -> int
    - get_file_size(path) -> int
```

~~**ChunkedProcessor:**~~
```python
# IMPLEMENTED: Lines 185-306
class ChunkedProcessor:
    - process_file(path, processor, encoding) -> dict
    - process_lines(path, processor, encoding) -> dict
```

---

## Phase 5: Schemas & Executor - COMPLETE

### ~~5.1 Dynamic Schema Generation (`core/schemas.py`)~~ - DONE

~~**ToolSchemaGenerator:**~~
```python
# IMPLEMENTED: Lines 15-299
class ToolSchemaGenerator:
    @staticmethod
    def get_openai_format(include_write) -> list[dict]
    def get_anthropic_format(include_write) -> list[dict]
    def get_ollama_format(include_write) -> list[dict]
    def get_tool_names(include_write) -> list[str]
    def get_tool_schema(tool_name) -> Optional[dict]
```

### ~~5.2 Tool Executor (`core/executor.py`)~~ - DONE

~~**ToolExecutor:**~~
```python
# IMPLEMENTED: Lines 14-238
class ToolExecutor:
    - execute(tool_name, arguments) -> dict
    - execute_batch(calls) -> list[dict]
    - validate_arguments(tool_name, arguments) -> tuple[bool, str]
    - is_write_enabled() -> bool
    - get_available_tools() -> list[str]
```

---

## Phase 6: Testing - COMPLETE

### ~~6.1 Unit Tests~~ - DONE

```
136 tests passing:
- test_audit.py          24 tests
- test_executor.py       25 tests
- test_schemas.py        17 tests
- test_streaming.py      23 tests
- test_tools.py          25 tests
- test_write_tools.py    22 tests
```

### ~~6.2 Platform Coverage~~ - DONE

- Windows: Tested, all 136 passing
- Linux: Architecture validated
- macOS: Architecture validated

---

## PRODUCTION PATH: Remaining Work

### P1: Add read_limited() to SecureFileHandle

**File:** `llm_fs_tools/core/file_handle.py`
**Priority:** HIGH
**Effort:** 30 minutes

```python
def read_limited(
    self,
    max_bytes: int,
    encoding: str = 'utf-8',
    truncation_marker: str = "\n\n[TRUNCATED: file larger than max_bytes]\n"
) -> tuple[str, bool]:
    """
    Read file with byte limit and truncation indicator.

    Returns:
        (content, was_truncated)
    """
    os.lseek(self.fd, 0, os.SEEK_SET)
    data = os.read(self.fd, max_bytes)
    extra = os.read(self.fd, 1)
    was_truncated = len(extra) > 0

    content = data.decode(encoding, errors='replace')
    if was_truncated:
        content += truncation_marker

    return content, was_truncated
```

---

### P2: Add read_file_secure() Convenience Function

**File:** `llm_fs_tools/__init__.py`
**Priority:** HIGH
**Effort:** 1 hour

```python
def read_file_secure(
    path: str,
    repo_root: str = ".",
    max_bytes: int = 200_000,
    encoding: str = "utf-8"
) -> dict:
    """
    Simple API for single-file reads with security.

    Compatible with ollama-prompt's read_file_snippet() interface.

    Returns:
        Success: {"ok": True, "path": "<resolved_path>", "content": "<file_content>"}
        Failure: {"ok": False, "path": "<requested_path>", "error": "<error_message>"}
    """
    try:
        policy = FileSystemPolicy(
            allowed_roots=[repo_root],
            max_file_size_mb=max_bytes / (1024 * 1024) + 1,
            blocked_patterns=[],
            blocked_extensions=[]
        )

        tools = FileSystemTools(policy)
        result = tools.read_file(path)

        if result["success"]:
            content = result["data"]["content"]
            content_bytes = content.encode(encoding, errors='replace')

            if len(content_bytes) > max_bytes:
                truncated_bytes = content_bytes[:max_bytes]
                content = truncated_bytes.decode(encoding, errors='replace')
                content += "\n\n[TRUNCATED: file larger than max_bytes]\n"

            return {
                "ok": True,
                "path": result["metadata"]["path"],
                "content": content
            }
        else:
            return {
                "ok": False,
                "path": str(path),
                "error": result["error"]
            }
    except Exception as e:
        return {
            "ok": False,
            "path": str(path),
            "error": str(e)
        }

# Add to __all__
__all__.append("read_file_secure")
```

---

### P3: Add Directory Access Function

**File:** `llm_fs_tools/__init__.py`
**Priority:** HIGH
**Effort:** 1 hour

```python
def create_directory_sandbox(
    directory: str,
    allow_write: bool = False,
    max_file_size_mb: int = 5,
    blocked_patterns: list[str] = None
) -> tuple[FileSystemTools, Optional[FileSystemWriteTools]]:
    """
    Create a secure sandbox for directory access.

    This is the PRIMARY API for ollama-prompt integration.
    Grants full read access (and optionally write) to a directory tree.

    Args:
        directory: Root directory to grant access to
        allow_write: Enable write operations
        max_file_size_mb: Maximum file size to read
        blocked_patterns: Additional patterns to block

    Returns:
        (read_tools, write_tools or None)

    Example:
        # Grant access to project directory
        read_tools, write_tools = create_directory_sandbox(
            "./my-project/",
            allow_write=True
        )

        # LLM can now explore and modify the directory
        read_tools.list_directory("./my-project/")
        read_tools.search_codebase("TODO", "./my-project/")
        write_tools.write_file("./my-project/new_file.py", "# New file")
    """
    from pathlib import Path

    directory = str(Path(directory).resolve())

    default_blocked = [
        "*.env", "*.key", "*.pem", "*.secret",
        ".git/*", "node_modules/*", "__pycache__/*"
    ]

    if blocked_patterns:
        default_blocked.extend(blocked_patterns)

    policy = FileSystemPolicy(
        allowed_roots=[directory],
        max_file_size_mb=max_file_size_mb,
        blocked_patterns=default_blocked,
        allow_write=allow_write,
        writable_roots=[directory] if allow_write else []
    )

    read_tools = FileSystemTools(policy)
    write_tools = FileSystemWriteTools(policy) if allow_write else None

    return read_tools, write_tools

# Add to __all__
__all__.append("create_directory_sandbox")
```

---

### P4: Create Working Examples

**Directory:** `examples/`
**Priority:** MEDIUM
**Effort:** 2 hours

#### examples/ollama_prompt_integration.py
```python
"""
Example: Integrating llm-fs-tools with ollama-prompt

This demonstrates replacing ollama-prompt's file reading with
secure directory-level access via llm-fs-tools.
"""
from llm_fs_tools import create_directory_sandbox, read_file_secure

# Option 1: Quick file read (drop-in for read_file_snippet)
result = read_file_secure("./README.md", repo_root=".")
if result["ok"]:
    print(f"Read {len(result['content'])} chars")
else:
    print(f"Error: {result['error']}")

# Option 2: Directory sandbox (full access)
read_tools, write_tools = create_directory_sandbox(
    "./my-project/",
    allow_write=True
)

# Explore the codebase
tree = read_tools.get_directory_tree("./my-project/", max_depth=3)
print(f"Project structure: {tree['data']}")

# Search for patterns
results = read_tools.search_codebase("def main", "./my-project/", file_pattern="*.py")
print(f"Found {results['data']['total_matches']} matches")

# Read specific files
content = read_tools.read_file("./my-project/src/main.py")
print(content["data"]["content"])

# Write new files (if write_tools enabled)
if write_tools:
    write_tools.write_file("./my-project/output.txt", "Generated content")
```

---

### P5: Directory Access Integration Test

**File:** `tests/integration/test_directory_sandbox.py`
**Priority:** HIGH
**Effort:** 2 hours

```python
"""
Integration test for directory-level access.

Validates the core value proposition: granting secure access to
an entire directory tree instead of individual files.
"""
import pytest
from pathlib import Path
from llm_fs_tools import create_directory_sandbox

def test_directory_sandbox_read_access(tmp_path):
    """Sandbox provides full read access within directory."""
    # Create test structure
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("def main(): pass")
    (tmp_path / "src" / "utils.py").write_text("def helper(): pass")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text("def test(): pass")

    # Create sandbox
    read_tools, _ = create_directory_sandbox(str(tmp_path))

    # Can list directory
    result = read_tools.list_directory(str(tmp_path))
    assert result["success"]
    assert len(result["data"]["entries"]) == 2  # src, tests

    # Can get tree
    result = read_tools.get_directory_tree(str(tmp_path))
    assert result["success"]

    # Can search codebase
    result = read_tools.search_codebase("def", str(tmp_path), file_pattern="*.py")
    assert result["success"]
    assert result["data"]["total_matches"] == 3

    # Can read files
    result = read_tools.read_file(str(tmp_path / "src" / "main.py"))
    assert result["success"]
    assert "def main" in result["data"]["content"]

def test_directory_sandbox_write_access(tmp_path):
    """Sandbox provides write access when enabled."""
    read_tools, write_tools = create_directory_sandbox(
        str(tmp_path),
        allow_write=True
    )

    # Can write files
    result = write_tools.write_file(
        str(tmp_path / "new_file.py"),
        "# New file"
    )
    assert result["success"]
    assert (tmp_path / "new_file.py").exists()

    # Can create directories
    result = write_tools.create_directory(str(tmp_path / "new_dir"))
    assert result["success"]
    assert (tmp_path / "new_dir").is_dir()

def test_directory_sandbox_containment(tmp_path):
    """Sandbox blocks access outside directory."""
    # Create sandbox for subdirectory
    subdir = tmp_path / "allowed"
    subdir.mkdir()

    # Create file outside sandbox
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")

    read_tools, _ = create_directory_sandbox(str(subdir))

    # Cannot read file outside sandbox
    result = read_tools.read_file(str(outside))
    assert not result["success"]
    assert "outside allowed roots" in result["error"]

def test_directory_sandbox_symlink_blocked(tmp_path):
    """Sandbox blocks symlink attacks."""
    import os

    allowed = tmp_path / "allowed"
    allowed.mkdir()

    secret = tmp_path / "secret.txt"
    secret.write_text("secret")

    # Create symlink inside allowed pointing outside
    link = allowed / "link.txt"
    try:
        os.symlink(secret, link)
    except OSError:
        pytest.skip("Symlinks require elevated permissions")

    read_tools, _ = create_directory_sandbox(str(allowed))

    # Cannot read via symlink
    result = read_tools.read_file(str(link))
    assert not result["success"]
```

---

### P6: PyPI Publish

**Priority:** LOW (after integration complete)
**Effort:** 30 minutes

```bash
# Build
python -m build

# Test upload
twine upload --repository testpypi dist/*

# Production upload
twine upload dist/*
```

---

## Production Checklist

### Code Complete
- [x] Phase 1: Security foundation
- [x] Phase 2: Read tools
- [x] Phase 3: Write tools
- [x] Phase 4: Audit & streaming
- [x] Phase 5: Schemas & executor
- [x] Phase 6: Unit tests (136 passing)

### Integration Layer
- [ ] P1: Add `read_limited()` method
- [ ] P2: Add `read_file_secure()` function
- [ ] P3: Add `create_directory_sandbox()` function
- [ ] P4: Create working examples
- [ ] P5: Directory access integration test
- [ ] P6: PyPI publish

### Documentation
- [x] README.md
- [x] SECURITY.md
- [x] implementation-plan-v5.md
- [x] implementation-plan-v5-updates.md
- [x] analysis-log-2025-12-06.md
- [x] implementation-plan-v5.01.md (this file)

---

## Success Criteria

- [x] Package installable via `pip install llm-fs-tools` (local)
- [x] Works with Ollama, OpenAI, Anthropic (schemas implemented)
- [x] FD-based validation prevents TOCTOU attacks
- [x] Symlinks blocked on Unix (O_NOFOLLOW) and Windows (FILE_FLAG_OPEN_REPARSE_POINT)
- [x] Platform parity tests pass on Windows
- [x] Read-only and write operations both supported
- [x] Audit logging functional
- [x] Streaming support for large files
- [x] 136 tests passing (>85% coverage estimate)
- [x] SECURITY.md documents threat model
- [ ] `create_directory_sandbox()` for primary use case
- [ ] `read_file_secure()` for drop-in compatibility
- [ ] ollama-prompt integration tested
- [ ] Directory-level access validated
- [ ] PyPI published

---

## Estimated Time to Production

| Task | Time |
|------|------|
| P1: read_limited() | 30 min |
| P2: read_file_secure() | 1 hour |
| P3: create_directory_sandbox() | 1 hour |
| P4: Working examples | 2 hours |
| P5: Integration tests | 2 hours |
| P6: PyPI publish | 30 min |
| **TOTAL** | **7 hours** |

---

**READY FOR FINAL IMPLEMENTATION SPRINT**
