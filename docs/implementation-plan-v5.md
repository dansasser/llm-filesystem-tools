# Implementation Plan v5: `llm-fs-tools` (Production-Ready + Simple)

## Overview

Standalone Python package providing **production-ready** filesystem access tools for LLMs with built-in security governance. Provider-agnostic, works with Ollama, OpenAI, Anthropic, etc.

**Design Philosophy:**
- **Simple** - No FreeBSD/OpenBSD complexity, focus on Windows + Linux + macOS
- **Separation of Concerns** - Clean protocol-driven architecture
- **Production-Ready** - Audit logging, streaming, proper error handling
- **Secure** - FD-based validation to prevent TOCTOU (not path-based)
- **Flexible Permissions** - Support read-only AND write operations with separate controls

**Changes from Previous Versions:**
- ✅ Keeps v1's simple architecture (no over-engineering)
- ✅ Adds v4's critical security (FD-based validation, O_NOFOLLOW)
- ✅ Removes v4's complexity (FreeBSD/OpenBSD, magic constants)
- ✅ Adds production essentials (audit, streaming, write support)
- ✅ Protocol-driven with clear separation of concerns

---

## Package Structure

```
llm-fs-tools/
├── pyproject.toml
├── README.md
├── LICENSE
├── SECURITY.md                    # NEW: Threat model documentation
├── llm_fs_tools/
│   ├── __init__.py                # Public API exports
│   ├── core/
│   │   ├── __init__.py
│   │   ├── security.py            # Security policy + validation
│   │   ├── file_handle.py         # NEW: FD-based file abstraction
│   │   ├── tools.py               # Tool implementations (read)
│   │   ├── write_tools.py         # NEW: Write tool implementations
│   │   ├── schemas.py             # Tool definition schemas
│   │   └── executor.py            # Tool execution engine
│   ├── platform/
│   │   ├── __init__.py
│   │   ├── secure_open.py         # NEW: Platform-specific secure open
│   │   └── paths.py               # NEW: Platform-specific FD→path
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── audit.py               # NEW: Audit logging
│   │   └── streaming.py           # NEW: Streaming support
│   └── exceptions.py              # Structured errors
├── tests/
│   ├── unit/
│   │   ├── test_security_policy.py
│   │   ├── test_file_handle.py
│   │   ├── test_tools.py
│   │   ├── test_write_tools.py
│   │   └── test_platform_parity.py  # NEW: Cross-platform tests
│   ├── integration/
│   │   ├── test_full_workflow.py
│   │   └── test_attack_scenarios.py # NEW: TOCTOU attack tests
│   └── fixtures/
│       ├── sample_codebase/
│       └── attack_scenarios/        # NEW: Deterministic attack tests
└── examples/
    ├── ollama_integration.py
    ├── openai_integration.py
    ├── write_example.py              # NEW: Write operation example
    └── audit_example.py              # NEW: Audit logging example
```

---

## Phase 1: Security Foundation (Week 1)

### 1.1 Security Policy (`core/security.py`)

**Protocol Interface:**
```python
class SecurityPolicy(Protocol):
    """Protocol for security policies - enables custom implementations"""

    def pre_validate_syntax(self, path: Path) -> Path:
        """Minimal syntax-only validation (no filesystem access)"""
        ...

    def post_validate_fd(
        self,
        fd: int,
        real_path: Path,
        stat_info: os.stat_result
    ) -> None:
        """Validate after opening - raises SecurityError if invalid"""
        ...

    def can_write(self, path: Path) -> bool:
        """Check if write is allowed to this path"""
        ...
```

**Implementation:**
```python
class FileSystemPolicy:
    """Default security policy implementation"""

    def __init__(
        self,
        allowed_roots: list[str],
        max_file_size_mb: int = 5,
        max_directory_entries: int = 10000,
        blocked_patterns: list[str] = None,
        blocked_extensions: list[str] = None,
        # NEW: Write support
        allow_write: bool = False,
        writable_roots: list[str] = None,
        # NEW: Audit support
        audit_logger: Optional['AuditLogger'] = None
    ):
        # Resolve allowed roots at init time (safe - no TOCTOU)
        self.allowed_roots = [Path(r).resolve(strict=True) for r in allowed_roots]
        self.max_file_size_mb = max_file_size_mb
        self.max_directory_entries = max_directory_entries
        self.blocked_patterns = blocked_patterns or self._default_blocked()
        self.blocked_extensions = [e.lower() for e in (blocked_extensions or [])]

        # Write permissions
        self.allow_write = allow_write
        self.writable_roots = [Path(r).resolve(strict=True) for r in (writable_roots or [])]

        # Audit logging
        self.audit = audit_logger

    def pre_validate_syntax(self, path: Path) -> Path:
        """
        MINIMAL pre-validation - syntax only, NO filesystem access.

        Prevents TOCTOU by doing NO security checks here.
        Only checks extension (syntax-based).
        """
        # Normalize unicode (syntax)
        from unicodedata import normalize
        path_str = normalize('NFC', str(path))
        path_obj = Path(path_str)

        # Check extension (syntax)
        if path_obj.suffix.lower() in self.blocked_extensions:
            raise SecurityError(f"Blocked extension: {path_obj.suffix}")

        return path_obj

    def post_validate_fd(
        self,
        fd: int,
        real_path: Path,
        stat_info: os.stat_result
    ) -> None:
        """
        ALL security checks happen here, after file is open.
        Uses FD, not path, to prevent TOCTOU.
        """
        import stat

        # 1. Verify file type (uses FD stat)
        if not stat.S_ISREG(stat_info.st_mode):
            raise SecurityError(
                f"Not a regular file (mode: {stat.filemode(stat_info.st_mode)})"
            )

        # 2. Check for special files (uses FD stat)
        if (stat.S_ISBLK(stat_info.st_mode) or
            stat.S_ISCHR(stat_info.st_mode) or
            stat.S_ISFIFO(stat_info.st_mode) or
            stat.S_ISSOCK(stat_info.st_mode)):
            raise SecurityError("Device/FIFO/socket files not allowed")

        # 3. Verify containment (uses real_path from FD)
        if not self._is_within_roots(real_path, self.allowed_roots):
            raise SecurityError(f"Path outside allowed roots: {real_path}")

        # 4. Check size limit (uses FD stat)
        size_mb = stat_info.st_size / (1024 * 1024)
        if size_mb > self.max_file_size_mb:
            raise SecurityError(
                f"File too large: {size_mb:.2f}MB > {self.max_file_size_mb}MB"
            )

        # 5. Check blocked patterns (uses real_path)
        if self._matches_blocked(real_path):
            raise SecurityError(f"Path matches blocked pattern: {real_path}")

        # 6. Log audit trail
        if self.audit:
            self.audit.log_access("read", str(real_path), True)

    def can_write(self, path: Path) -> bool:
        """Check if write is allowed"""
        if not self.allow_write:
            return False

        # Resolve path (safe here - not in critical path)
        try:
            resolved = path.resolve(strict=False)
        except Exception:
            return False

        # Check if within writable roots
        if not self._is_within_roots(resolved, self.writable_roots):
            return False

        # Check parent directory is within writable roots
        parent = resolved.parent
        if not self._is_within_roots(parent, self.writable_roots):
            return False

        return True

    def _is_within_roots(self, path: Path, roots: list[Path]) -> bool:
        """Check if path is within any of the roots"""
        for root in roots:
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def _matches_blocked(self, path: Path) -> bool:
        """Check if path matches any blocked pattern"""
        import fnmatch
        path_str = str(path).lower()

        for pattern in self.blocked_patterns:
            if fnmatch.fnmatch(path_str, pattern.lower()):
                return True
        return False

    @staticmethod
    def _default_blocked() -> list[str]:
        """Default security patterns"""
        return [
            "*.env",
            "*.key",
            "*.pem",
            "*.secret",
            ".git/*",
            "node_modules/*",
            "__pycache__/*",
            ".venv/*",
            "venv/*",
        ]
```

---

### 1.2 Platform-Specific Secure Open (`platform/secure_open.py`)

**Protocol Interface:**
```python
class SecureOpener(Protocol):
    """Protocol for platform-specific secure file opening"""

    def secure_open(self, path: Path, flags: int) -> tuple[int, Path]:
        """
        Open file securely for this platform.

        Returns:
            (file_descriptor, canonical_path)
        """
        ...
```

**Implementation (Unix/Linux/macOS):**
```python
import os
import platform
from pathlib import Path

def secure_open_unix(path: Path, flags: int) -> tuple[int, Path]:
    """
    Unix secure open with O_NOFOLLOW.

    Works on: Linux, macOS
    """
    # Open with O_NOFOLLOW - fails if path is symlink
    try:
        fd = os.open(str(path), flags | os.O_NOFOLLOW)
    except OSError as e:
        if e.errno == 40:  # ELOOP
            raise SecurityError(f"Symlink detected: {path}")
        raise

    # Get canonical path from FD
    try:
        system = platform.system()

        if system == 'Linux':
            # Use /proc/self/fd (exists on all modern Linux)
            real_path = os.readlink(f'/proc/self/fd/{fd}')
            return fd, Path(real_path)

        elif system == 'Darwin':
            # macOS - use fcntl F_GETPATH
            import fcntl
            # macOS-specific constant
            F_GETPATH = 50
            path_bytes = fcntl.fcntl(fd, F_GETPATH, bytes(1024))
            real_path = path_bytes.rstrip(b'\x00').decode('utf-8')
            return fd, Path(real_path)

        else:
            # Other Unix - use fstat and original path
            # (Not perfect but good enough for BSD)
            return fd, path.resolve(strict=True)

    except Exception as e:
        os.close(fd)
        raise SecurityError(f"FD verification failed: {e}")
```

**Implementation (Windows):**
```python
def secure_open_windows(path: Path, flags: int) -> tuple[int, Path]:
    """
    Windows secure open with reparse point check.

    Works on: Windows 10+
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    # Windows API constants
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400

    # Open with FILE_FLAG_OPEN_REPARSE_POINT (doesn't follow symlinks)
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        None
    )

    if handle == -1:
        raise OSError(f"CreateFileW failed: {path}")

    # Check if it's a reparse point (symlink/junction)
    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('dwFileAttributes', wintypes.DWORD),
            ('ftCreationTime', wintypes.FILETIME),
            ('ftLastAccessTime', wintypes.FILETIME),
            ('ftLastWriteTime', wintypes.FILETIME),
            ('dwVolumeSerialNumber', wintypes.DWORD),
            ('nFileSizeHigh', wintypes.DWORD),
            ('nFileSizeLow', wintypes.DWORD),
            ('nNumberOfLinks', wintypes.DWORD),
            ('nFileIndexHigh', wintypes.DWORD),
            ('nFileIndexLow', wintypes.DWORD),
        ]

    file_info = BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(file_info)):
        kernel32.CloseHandle(handle)
        raise OSError(f"GetFileInformationByHandle failed")

    # Check if reparse point
    if file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        kernel32.CloseHandle(handle)
        raise SecurityError(f"Symlink/junction detected: {path}")

    # Convert to Python FD
    fd = msvcrt.open_osfhandle(handle, flags)

    # Get canonical path using GetFinalPathNameByHandle
    path_buffer = ctypes.create_unicode_buffer(1024)
    length = kernel32.GetFinalPathNameByHandleW(
        handle,
        path_buffer,
        1024,
        0  # FILE_NAME_NORMALIZED
    )

    if length == 0:
        os.close(fd)
        raise OSError("GetFinalPathNameByHandle failed")

    # Remove \\?\ prefix if present
    real_path_str = path_buffer.value
    if real_path_str.startswith('\\\\?\\'):
        real_path_str = real_path_str[4:]

    return fd, Path(real_path_str)
```

**Platform Selector:**
```python
def secure_open(path: Path, flags: int = os.O_RDONLY) -> tuple[int, Path]:
    """
    Platform-independent secure open.

    Returns:
        (fd, canonical_path)
    """
    system = platform.system()

    if system in ('Linux', 'Darwin'):
        return secure_open_unix(path, flags)
    elif system == 'Windows':
        return secure_open_windows(path, flags)
    else:
        raise OSError(f"Unsupported platform: {system}")
```

---

### 1.3 File Handle Abstraction (`core/file_handle.py`)

**Protocol Interface:**
```python
class FileHandle(Protocol):
    """Protocol for file handles"""

    def read_all(self, encoding: str = 'utf-8') -> str:
        """Read entire file"""
        ...

    def read_lines(
        self,
        start: Optional[int] = None,
        end: Optional[int] = None
    ) -> list[str]:
        """Read lines with optional range"""
        ...

    def close(self) -> None:
        """Close file descriptor"""
        ...
```

**Implementation:**
```python
import os
from pathlib import Path
from contextlib import contextmanager
from typing import Optional

class SecureFileHandle:
    """TOCTOU-resistant file handle using file descriptors"""

    def __init__(
        self,
        fd: int,
        original_path: Path,
        real_path: Path,
        stat_info: os.stat_result
    ):
        self.fd = fd
        self.original_path = original_path
        self.real_path = real_path
        self.stat = stat_info

    def read_all(self, encoding: str = 'utf-8') -> str:
        """Read entire file using FD"""
        os.lseek(self.fd, 0, os.SEEK_SET)

        # Read in chunks (don't trust cached size)
        chunks = []
        while True:
            chunk = os.read(self.fd, 8192)
            if not chunk:
                break
            chunks.append(chunk)

        data = b''.join(chunks)
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
        self.close()

    def close(self):
        """Close FD"""
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self):
        """Safety cleanup"""
        if hasattr(self, 'fd') and self.fd >= 0:
            try:
                os.close(self.fd)
            except:
                pass


@contextmanager
def open_secure(
    path: str | Path,
    policy: SecurityPolicy
) -> SecureFileHandle:
    """
    Atomically open and validate file - TOCTOU resistant.

    Flow:
        1. Minimal pre-validation (syntax only)
        2. Platform-specific secure open
        3. ALL security checks on FD
        4. Return handle
    """
    from .platform.secure_open import secure_open

    path = Path(path)

    # Step 1: Syntax validation only
    validated_path = policy.pre_validate_syntax(path)

    # Step 2: Platform-specific secure open
    fd, real_path = secure_open(validated_path)

    try:
        # Step 3: Get FD stat
        stat_info = os.fstat(fd)

        # Step 4: Security validation on FD
        policy.post_validate_fd(fd, real_path, stat_info)

        # Create handle
        handle = SecureFileHandle(fd, path, real_path, stat_info)

        yield handle

    except Exception as e:
        # Clean up FD on error
        os.close(fd)

        # Log failure
        if hasattr(policy, 'audit') and policy.audit:
            policy.audit.log_access("open", str(path), False, str(e))

        raise
```

---

## Phase 2: Read Tools (Week 2)

### 2.1 Read-Only Tools (`core/tools.py`)

```python
from typing import Optional
from pathlib import Path

class FileSystemTools:
    """Read-only filesystem tools for LLMs"""

    def __init__(self, security_policy: SecurityPolicy):
        self.policy = security_policy

    def read_file(
        self,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> dict:
        """
        Read file content with optional line range.

        Returns:
            {
                "success": True,
                "data": {
                    "content": "file content",
                    "lines": ["line1", "line2"],
                    "total_lines": 100,
                    "encoding": "utf-8"
                },
                "metadata": {
                    "tool": "read_file",
                    "path": "/resolved/path",
                    "size_bytes": 1024
                }
            }
        """
        try:
            with open_secure(path, self.policy) as handle:
                lines = handle.read_lines(start_line, end_line)

                return {
                    "success": True,
                    "data": {
                        "content": ''.join(lines),
                        "lines": lines,
                        "total_lines": len(lines),
                        "encoding": "utf-8"
                    },
                    "metadata": {
                        "tool": "read_file",
                        "path": str(handle.real_path),
                        "size_bytes": handle.stat.st_size
                    }
                }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "read_file", "path": str(path)}
            }

    def list_directory(
        self,
        path: str,
        include_hidden: bool = False
    ) -> dict:
        """List immediate directory contents"""
        try:
            dir_path = Path(path).resolve(strict=True)

            # Check directory is within allowed roots
            if not self.policy._is_within_roots(dir_path, self.policy.allowed_roots):
                raise SecurityError(f"Directory outside allowed roots: {dir_path}")

            entries = []
            for entry in dir_path.iterdir():
                if not include_hidden and entry.name.startswith('.'):
                    continue

                stat_info = entry.stat()
                entries.append({
                    "name": entry.name,
                    "type": "file" if entry.is_file() else "directory",
                    "size": stat_info.st_size if entry.is_file() else None
                })

            # Check entry count limit
            if len(entries) > self.policy.max_directory_entries:
                raise SecurityError(
                    f"Too many entries: {len(entries)} > {self.policy.max_directory_entries}"
                )

            return {
                "success": True,
                "data": {
                    "entries": entries,
                    "total": len(entries)
                },
                "metadata": {
                    "tool": "list_directory",
                    "path": str(dir_path)
                }
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "list_directory", "path": str(path)}
            }

    def get_directory_tree(
        self,
        path: str,
        max_depth: int = 3,
        include_hidden: bool = False
    ) -> dict:
        """Returns hierarchical directory structure"""
        try:
            def build_tree(dir_path: Path, current_depth: int) -> dict:
                if current_depth > max_depth:
                    return None

                tree = {
                    "name": dir_path.name,
                    "type": "directory",
                    "children": []
                }

                for entry in dir_path.iterdir():
                    if not include_hidden and entry.name.startswith('.'):
                        continue

                    if entry.is_file():
                        tree["children"].append({
                            "name": entry.name,
                            "type": "file",
                            "size": entry.stat().st_size
                        })
                    elif entry.is_dir():
                        subtree = build_tree(entry, current_depth + 1)
                        if subtree:
                            tree["children"].append(subtree)

                return tree

            dir_path = Path(path).resolve(strict=True)

            # Security check
            if not self.policy._is_within_roots(dir_path, self.policy.allowed_roots):
                raise SecurityError(f"Directory outside allowed roots")

            tree = build_tree(dir_path, 0)

            return {
                "success": True,
                "data": tree,
                "metadata": {
                    "tool": "get_directory_tree",
                    "path": str(dir_path),
                    "max_depth": max_depth
                }
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "get_directory_tree", "path": str(path)}
            }

    def search_codebase(
        self,
        pattern: str,
        path: str,
        file_pattern: str = "*",
        case_sensitive: bool = False,
        max_results: int = 100
    ) -> dict:
        """Grep-style search across files"""
        import re
        import fnmatch

        try:
            dir_path = Path(path).resolve(strict=True)

            # Security check
            if not self.policy._is_within_roots(dir_path, self.policy.allowed_roots):
                raise SecurityError(f"Directory outside allowed roots")

            # Compile regex
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)

            matches = []
            for file_path in dir_path.rglob(file_pattern):
                if not file_path.is_file():
                    continue

                # Try to read file securely
                try:
                    with open_secure(file_path, self.policy) as handle:
                        lines = handle.read_lines()

                        for i, line in enumerate(lines, 1):
                            if regex.search(line):
                                matches.append({
                                    "file": str(file_path.relative_to(dir_path)),
                                    "line": i,
                                    "content": line.rstrip(),
                                    "match": regex.search(line).group()
                                })

                                if len(matches) >= max_results:
                                    break

                except SecurityError:
                    # Skip files that fail security check
                    continue

                if len(matches) >= max_results:
                    break

            return {
                "success": True,
                "data": {
                    "matches": matches,
                    "total_matches": len(matches),
                    "truncated": len(matches) >= max_results
                },
                "metadata": {
                    "tool": "search_codebase",
                    "pattern": pattern,
                    "path": str(dir_path)
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "search_codebase", "path": str(path)}
            }
```

---

## Phase 3: Write Tools (Week 3)

### 3.1 Write Tools (`core/write_tools.py`)

```python
class FileSystemWriteTools:
    """Write filesystem tools - requires explicit permission"""

    def __init__(self, security_policy: SecurityPolicy):
        self.policy = security_policy

        if not self.policy.allow_write:
            raise ValueError("Write tools require allow_write=True in policy")

    def write_file(
        self,
        path: str,
        content: str,
        encoding: str = 'utf-8',
        create_dirs: bool = False
    ) -> dict:
        """
        Atomically write file with security validation.

        Returns:
            {
                "success": True,
                "data": {
                    "bytes_written": 1024,
                    "path": "/resolved/path"
                },
                "metadata": {
                    "tool": "write_file",
                    "operation": "create" | "overwrite"
                }
            }
        """
        try:
            file_path = Path(path)

            # Check write permission
            if not self.policy.can_write(file_path):
                raise SecurityError(f"Write not allowed: {path}")

            # Create parent directories if requested
            if create_dirs:
                file_path.parent.mkdir(parents=True, exist_ok=True)

            # Atomic write using temp file + rename
            import tempfile

            # Create temp file in same directory (ensures same filesystem)
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding=encoding,
                dir=file_path.parent,
                delete=False
            ) as tmp:
                tmp.write(content)
                tmp_path = Path(tmp.name)

            # Atomic rename
            existed = file_path.exists()
            tmp_path.replace(file_path)

            # Audit log
            if self.policy.audit:
                self.policy.audit.log_access(
                    "write",
                    str(file_path),
                    True,
                    f"{'overwrite' if existed else 'create'}"
                )

            return {
                "success": True,
                "data": {
                    "bytes_written": len(content.encode(encoding)),
                    "path": str(file_path.resolve())
                },
                "metadata": {
                    "tool": "write_file",
                    "operation": "overwrite" if existed else "create"
                }
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "write_file", "path": str(path)}
            }

    def delete_file(self, path: str) -> dict:
        """Delete file with security validation"""
        try:
            file_path = Path(path)

            # Check write permission
            if not self.policy.can_write(file_path):
                raise SecurityError(f"Write not allowed: {path}")

            # Verify file exists and is regular file
            if not file_path.exists():
                raise SecurityError(f"File does not exist: {path}")

            if not file_path.is_file():
                raise SecurityError(f"Not a regular file: {path}")

            # Delete
            file_path.unlink()

            # Audit log
            if self.policy.audit:
                self.policy.audit.log_access("delete", str(file_path), True)

            return {
                "success": True,
                "data": {"path": str(file_path)},
                "metadata": {"tool": "delete_file"}
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "delete_file", "path": str(path)}
            }
```

---

## Phase 4: Audit & Streaming (Week 4)

### 4.1 Audit Logger (`utils/audit.py`)

```python
import logging
from datetime import datetime
from typing import Optional
from pathlib import Path

class AuditLogger:
    """Audit logging for file access"""

    def __init__(
        self,
        log_file: Optional[str] = None,
        console: bool = False
    ):
        self.logger = logging.getLogger('llm_fs_tools.audit')
        self.logger.setLevel(logging.INFO)

        # File handler
        if log_file:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s'
            ))
            self.logger.addHandler(handler)

        # Console handler
        if console:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)

    def log_access(
        self,
        operation: str,
        path: str,
        success: bool,
        details: str = ""
    ) -> None:
        """Log file access attempt"""
        status = "SUCCESS" if success else "DENIED"
        message = f"{operation.upper()} | {status} | {path}"

        if details:
            message += f" | {details}"

        if success:
            self.logger.info(message)
        else:
            self.logger.warning(message)

    def log_warning(self, message: str) -> None:
        """Log security warning"""
        self.logger.warning(f"WARNING | {message}")
```

### 4.2 Streaming Support (`utils/streaming.py`)

```python
from typing import Iterator, Optional
from pathlib import Path

class StreamingFileReader:
    """Stream large files in chunks"""

    def __init__(
        self,
        policy: SecurityPolicy,
        chunk_size: int = 8192
    ):
        self.policy = policy
        self.chunk_size = chunk_size

    def stream_file(
        self,
        path: str | Path,
        encoding: str = 'utf-8'
    ) -> Iterator[str]:
        """
        Stream file in chunks.

        Yields:
            Chunks of file content
        """
        with open_secure(path, self.policy) as handle:
            while True:
                chunk = os.read(handle.fd, self.chunk_size)
                if not chunk:
                    break

                yield chunk.decode(encoding, errors='replace')

    def stream_lines(
        self,
        path: str | Path,
        encoding: str = 'utf-8'
    ) -> Iterator[str]:
        """
        Stream file line by line.

        Yields:
            Individual lines
        """
        buffer = ""
        for chunk in self.stream_file(path, encoding):
            buffer += chunk

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                yield line + '\n'

        # Yield remaining buffer
        if buffer:
            yield buffer
```

---

## Phase 5: Schemas & Executor (Week 5)

### 5.1 Dynamic Schema Generation (`core/schemas.py`)

```python
class ToolSchemaGenerator:
    """Generates tool definitions for different LLM providers"""

    @staticmethod
    def get_openai_format(include_write: bool = False) -> list[dict]:
        """OpenAI function calling format"""
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read file content with optional line range",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to file"
                            },
                            "start_line": {
                                "type": "integer",
                                "description": "First line to read (1-indexed)"
                            },
                            "end_line": {
                                "type": "integer",
                                "description": "Last line to read (inclusive)"
                            }
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "list_directory",
                    "description": "List directory contents",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "include_hidden": {"type": "boolean", "default": False}
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_directory_tree",
                    "description": "Get hierarchical directory structure",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "max_depth": {"type": "integer", "default": 3},
                            "include_hidden": {"type": "boolean", "default": False}
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_codebase",
                    "description": "Search for pattern in codebase",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string", "description": "Regex pattern"},
                            "path": {"type": "string"},
                            "file_pattern": {"type": "string", "default": "*"},
                            "case_sensitive": {"type": "boolean", "default": False},
                            "max_results": {"type": "integer", "default": 100}
                        },
                        "required": ["pattern", "path"]
                    }
                }
            }
        ]

        # Add write tools if enabled
        if include_write:
            tools.extend([
                {
                    "type": "function",
                    "function": {
                        "name": "write_file",
                        "description": "Write content to file",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "content": {"type": "string"},
                                "create_dirs": {"type": "boolean", "default": False}
                            },
                            "required": ["path", "content"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "delete_file",
                        "description": "Delete a file",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"}
                            },
                            "required": ["path"]
                        }
                    }
                }
            ])

        return tools

    @staticmethod
    def get_anthropic_format(include_write: bool = False) -> list[dict]:
        """Anthropic tool format (similar to OpenAI)"""
        # Anthropic uses similar format
        openai_tools = ToolSchemaGenerator.get_openai_format(include_write)

        # Convert to Anthropic format
        return [
            {
                "name": tool["function"]["name"],
                "description": tool["function"]["description"],
                "input_schema": tool["function"]["parameters"]
            }
            for tool in openai_tools
        ]

    @staticmethod
    def get_ollama_format(include_write: bool = False) -> list[dict]:
        """Ollama tool format (OpenAI-compatible)"""
        return ToolSchemaGenerator.get_openai_format(include_write)
```

### 5.2 Tool Executor (`core/executor.py`)

```python
class ToolExecutor:
    """Routes and executes tool calls"""

    def __init__(
        self,
        read_tools: FileSystemTools,
        write_tools: Optional[FileSystemWriteTools] = None
    ):
        self.read_tools = read_tools
        self.write_tools = write_tools

    def execute(self, tool_name: str, arguments: dict) -> dict:
        """
        Execute tool call.

        Returns:
            Standardized response dict
        """
        # Route to appropriate tool
        if tool_name in ('read_file', 'list_directory', 'get_directory_tree', 'search_codebase'):
            method = getattr(self.read_tools, tool_name)
            return method(**arguments)

        elif tool_name in ('write_file', 'delete_file'):
            if not self.write_tools:
                return {
                    "success": False,
                    "error": "Write operations not enabled",
                    "metadata": {"tool": tool_name}
                }

            method = getattr(self.write_tools, tool_name)
            return method(**arguments)

        else:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}",
                "metadata": {"tool": tool_name}
            }
```

---

## Phase 6: Testing (Throughout)

### 6.1 TOCTOU Attack Tests (`tests/integration/test_attack_scenarios.py`)

```python
import pytest
import os
from pathlib import Path

def test_symlink_blocked_unix(tmp_path):
    """Symlinks are blocked on Unix"""
    if os.name == 'nt':
        pytest.skip("Unix-only test")

    from llm_fs_tools import FileSystemPolicy, FileSystemTools

    # Create target
    target = tmp_path / "target.txt"
    target.write_text("secret")

    # Create symlink
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    # Policy allowing tmp_path
    policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
    tools = FileSystemTools(policy)

    # Attempt to read symlink - should fail
    result = tools.read_file(str(link))

    assert result["success"] == False
    assert "symlink" in result["error"].lower()


def test_symlink_blocked_windows(tmp_path):
    """Symlinks are blocked on Windows"""
    if os.name != 'nt':
        pytest.skip("Windows-only test")

    from llm_fs_tools import FileSystemPolicy, FileSystemTools

    # Create target
    target = tmp_path / "target.txt"
    target.write_text("secret")

    # Create symlink (requires admin on Windows)
    link = tmp_path / "link.txt"
    try:
        os.symlink(target, link, target_is_directory=False)
    except OSError:
        pytest.skip("Symlink creation requires admin on Windows")

    # Policy allowing tmp_path
    policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
    tools = FileSystemTools(policy)

    # Attempt to read - should fail
    result = tools.read_file(str(link))

    assert result["success"] == False
    assert "symlink" in result["error"].lower() or "junction" in result["error"].lower()


def test_path_traversal_blocked(tmp_path):
    """Path traversal attacks are blocked"""
    from llm_fs_tools import FileSystemPolicy, FileSystemTools

    # Create allowed directory
    allowed = tmp_path / "allowed"
    allowed.mkdir()

    # Create file outside allowed
    secret = tmp_path / "secret.txt"
    secret.write_text("secret content")

    # Policy only allows 'allowed' directory
    policy = FileSystemPolicy(allowed_roots=[str(allowed)])
    tools = FileSystemTools(policy)

    # Attempt path traversal
    result = tools.read_file(str(allowed / ".." / "secret.txt"))

    assert result["success"] == False
    assert "outside allowed roots" in result["error"]
```

### 6.2 Platform Parity Tests (`tests/unit/test_platform_parity.py`)

```python
import pytest
import platform

def test_secure_open_works_on_current_platform(tmp_path):
    """Secure open works on current platform"""
    from llm_fs_tools.platform.secure_open import secure_open

    # Create test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("test content")

    # Open securely
    fd, real_path = secure_open(test_file)

    try:
        # Verify FD is valid
        assert fd >= 0

        # Verify path is resolved
        assert real_path.exists()
        assert real_path.is_file()

        # Verify we can read from FD
        data = os.read(fd, 1024)
        assert data == b"test content"

    finally:
        os.close(fd)


@pytest.mark.parametrize("system", ["Linux", "Darwin", "Windows"])
def test_platform_specific_implementation_exists(system):
    """Each platform has an implementation"""
    from llm_fs_tools.platform import secure_open

    # Skip if not current platform
    if platform.system() != system:
        pytest.skip(f"Not running on {system}")

    # Should have platform-specific function
    if system in ("Linux", "Darwin"):
        assert hasattr(secure_open, 'secure_open_unix')
    elif system == "Windows":
        assert hasattr(secure_open, 'secure_open_windows')
```

---

## Implementation Timeline (6 Weeks)

### Week 1: Security Foundation
- Day 1-2: Platform-specific secure_open (Unix/Windows/macOS)
- Day 3-4: SecurityPolicy with FD-based validation
- Day 5: SecureFileHandle + open_secure context manager

### Week 2: Read Tools
- Day 1-2: read_file, list_directory
- Day 3-4: get_directory_tree, search_codebase
- Day 5: Unit tests for all read tools

### Week 3: Write Tools & Security
- Day 1-2: write_file, delete_file with atomic operations
- Day 3-4: TOCTOU attack tests (deterministic)
- Day 5: Platform parity tests

### Week 4: Production Features
- Day 1-2: Audit logging + streaming support
- Day 3-4: ollama-prompt integration
- Day 5: Integration testing

### Week 5: Documentation & Examples
- Day 1-2: SECURITY.md (threat model), API docs
- Day 3-4: Working examples (Ollama/OpenAI/Anthropic)
- Day 5: Beta release prep

### Week 6: Release
- Day 1-2: Beta testing feedback
- Day 3-4: Final hardening
- Day 5: PyPI publish (v0.1.0)

---

## Public API (`__init__.py`)

```python
"""
llm-filesystem-tools: Production-ready filesystem access for LLMs

Simple, secure, protocol-driven architecture with read and write support.
"""

from .core.security import FileSystemPolicy, SecurityError
from .core.tools import FileSystemTools
from .core.write_tools import FileSystemWriteTools
from .core.schemas import ToolSchemaGenerator
from .core.executor import ToolExecutor
from .utils.audit import AuditLogger
from .utils.streaming import StreamingFileReader

__version__ = "0.1.0"
__all__ = [
    # Core
    "FileSystemPolicy",
    "SecurityError",

    # Tools
    "FileSystemTools",
    "FileSystemWriteTools",

    # Integration
    "ToolSchemaGenerator",
    "ToolExecutor",

    # Utilities
    "AuditLogger",
    "StreamingFileReader",
]
```

---

## Success Criteria

- [ ] Package installable via `pip install llm-fs-tools`
- [ ] Works with Ollama, OpenAI, Anthropic (examples for each)
- [ ] FD-based validation prevents TOCTOU attacks
- [ ] Symlinks blocked on Unix (O_NOFOLLOW) and Windows (FILE_FLAG_OPEN_REPARSE_POINT)
- [ ] Platform parity tests pass on Linux, macOS, Windows
- [ ] Deterministic TOCTOU attack tests pass
- [ ] Read-only and write operations both supported
- [ ] Audit logging functional
- [ ] Streaming support for large files
- [ ] 85%+ test coverage
- [ ] SECURITY.md documents threat model
- [ ] ollama-prompt integration tested
- [ ] Clear separation of concerns (protocols, not classes)

---

## Key Design Decisions

1. **FD-based validation** - All security checks happen AFTER opening file
2. **Platform-specific implementations** - Unix vs Windows have different security primitives
3. **Separation of read/write** - Different permission models, different tools
4. **Protocol-driven** - Interfaces define contracts, implementations follow
5. **Atomic operations** - Write uses temp file + rename (POSIX guarantees)
6. **Audit by default** - Security decisions are logged
7. **Streaming support** - Large files don't blow up memory
8. **No FreeBSD/OpenBSD** - Focus on 95% use case (Linux/macOS/Windows)

---

**READY FOR IMPLEMENTATION** - Simple, secure, production-ready architecture that can be built in 6 weeks.
