"""
Compatibility layer for ollama-prompt integration.

Provides drop-in replacements for ollama-prompt's secure_file.py functions:
- read_file_secure() - Read file with TOCTOU protection
- secure_open() - Open file securely, returns fd
- create_directory_tools() - Create configured FileSystemTools for directory access

These functions match ollama-prompt's exact signatures for seamless migration.
"""

import os
import stat
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union

from .core.security import FileSystemPolicy
from .core.tools import FileSystemTools
from .core.write_tools import FileSystemWriteTools
from .core.file_handle import open_secure as _open_secure
from .exceptions import SecurityError

# Configure audit logger (matches ollama-prompt's logger name pattern)
audit_logger = logging.getLogger("llm_fs_tools.file_audit")

# Default maximum bytes to read (matches ollama-prompt)
DEFAULT_MAX_FILE_BYTES = 200_000


def secure_open(
    path: str,
    repo_root: str = ".",
    audit: bool = True
) -> Dict[str, Any]:
    """
    Securely open a file with TOCTOU protection.

    Drop-in replacement for ollama-prompt's secure_open().

    Security features:
    1. Opens with O_NOFOLLOW (blocks symlinks at open time on Unix)
    2. Validates file type via fstat (rejects devices, FIFOs, sockets)
    3. Validates path containment AFTER opening (eliminates TOCTOU)

    Args:
        path: Path to file (relative or absolute)
        repo_root: Allowed root directory
        audit: Whether to log access attempts

    Returns:
        Dict with:
        - ok: bool - Whether open succeeded
        - fd: int - File descriptor (if ok=True)
        - path: str - Original path
        - resolved_path: str - Resolved path (if ok=True)
        - size: int - File size in bytes (if ok=True)
        - error: str - Error message (if ok=False)
        - blocked_reason: str - Security reason for block (if applicable)
    """
    try:
        # Resolve repo_root to absolute path
        root_path = Path(repo_root).resolve()

        # Create minimal policy for single-root use
        policy = FileSystemPolicy(
            allowed_roots=[str(root_path)],
            max_file_size_mb=1000,  # No practical limit for open
            blocked_patterns=[],
            blocked_extensions=[]
        )

        # Compute target path
        if os.path.isabs(path):
            target = Path(path)
        else:
            target = root_path / path

        # Use our secure open
        with _open_secure(target, policy) as handle:
            # Get file descriptor and stats
            fd = handle.fd
            resolved_path = str(handle.real_path)
            file_size = handle.stat.st_size

            # Verify it's a regular file
            if not stat.S_ISREG(handle.stat.st_mode):
                if stat.S_ISDIR(handle.stat.st_mode):
                    file_type = "directory"
                elif stat.S_ISLNK(handle.stat.st_mode):
                    file_type = "symlink"
                elif stat.S_ISFIFO(handle.stat.st_mode):
                    file_type = "FIFO/pipe"
                elif stat.S_ISSOCK(handle.stat.st_mode):
                    file_type = "socket"
                elif stat.S_ISBLK(handle.stat.st_mode):
                    file_type = "block device"
                elif stat.S_ISCHR(handle.stat.st_mode):
                    file_type = "character device"
                else:
                    file_type = "non-regular file"

                reason = f"invalid file type: {file_type}"
                if audit:
                    audit_logger.warning(
                        f"BLOCKED: {path} -> {file_type} not allowed"
                    )
                return {
                    "ok": False,
                    "path": path,
                    "error": f"Not a regular file ({file_type}): {path}",
                    "blocked_reason": reason
                }

            # Duplicate fd so it survives context manager exit
            new_fd = os.dup(fd)

            if audit:
                audit_logger.info(f"ALLOWED: {path} -> {resolved_path}")

            return {
                "ok": True,
                "fd": new_fd,
                "path": path,
                "resolved_path": resolved_path,
                "size": file_size
            }

    except SecurityError as e:
        error_msg = str(e)
        reason = "security violation"

        if "symlink" in error_msg.lower():
            reason = "symlink blocked"
        elif "outside" in error_msg.lower() or "root" in error_msg.lower():
            reason = "path outside allowed root"

        if audit:
            audit_logger.warning(f"BLOCKED: {path} -> {error_msg}")

        return {
            "ok": False,
            "path": path,
            "error": error_msg,
            "blocked_reason": reason
        }

    except FileNotFoundError:
        return {
            "ok": False,
            "path": path,
            "error": f"File not found: {path}"
        }

    except PermissionError:
        return {
            "ok": False,
            "path": path,
            "error": f"Permission denied: {path}"
        }

    except Exception as e:
        return {
            "ok": False,
            "path": path,
            "error": str(e)
        }


def read_file_secure(
    path: str,
    repo_root: str = ".",
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    audit: bool = True
) -> Dict[str, Any]:
    """
    Securely read a file with full TOCTOU protection.

    Drop-in replacement for ollama-prompt's read_file_secure().

    Security features:
    1. Opens with O_NOFOLLOW (blocks symlinks on Unix)
    2. Validates file type (rejects devices, FIFOs, sockets)
    3. Validates containment AFTER opening (eliminates TOCTOU race)
    4. Audit logging of all access attempts

    Args:
        path: Path to file
        repo_root: Allowed root directory
        max_bytes: Maximum bytes to read (default: 200,000)
        audit: Whether to log access attempts

    Returns:
        Dict with:
        - ok: bool
        - path: str
        - content: str (if ok=True)
        - error: str (if ok=False)
    """
    # Step 1: Securely open the file
    open_result = secure_open(path, repo_root, audit=audit)

    if not open_result["ok"]:
        return {
            "ok": False,
            "path": path,
            "error": open_result["error"]
        }

    fd = open_result["fd"]
    file_size = open_result.get("size", 0)
    fd_closed = False

    try:
        # Step 2: Read content from file descriptor in BINARY mode
        # This ensures max_bytes limits actual bytes, not characters
        # Note: os.fdopen takes ownership of fd and closes it on exit
        with os.fdopen(fd, "rb") as f:
            fd_closed = True  # fdopen now owns the fd
            bytes_read = f.read(max_bytes)

        # Detect truncation by comparing file_size to bytes actually read
        truncated = file_size > len(bytes_read)

        # Decode with safe handling for invalid UTF-8 sequences
        content = bytes_read.decode("utf-8", errors="replace")

        # Step 3: Add truncation notice if file was truncated
        if truncated:
            content += "\n\n[TRUNCATED: file larger than max_bytes]\n"

        return {
            "ok": True,
            "path": path,
            "content": content
        }

    except Exception as e:
        # Only close fd if fdopen hasn't taken ownership yet
        if not fd_closed:
            try:
                os.close(fd)
            except OSError:
                pass

        return {
            "ok": False,
            "path": path,
            "error": str(e)
        }


def create_directory_tools(
    directory: Union[str, Path],
    allow_write: bool = False,
    max_file_size_mb: float = 10.0,
    max_directory_entries: int = 10000,
    blocked_patterns: Optional[list] = None,
    blocked_extensions: Optional[list] = None
) -> Union[FileSystemTools, FileSystemWriteTools]:
    """
    Create a configured FileSystemTools instance for directory access.

    Provides directory-level operations:
    - list_directory() - List immediate contents
    - get_directory_tree() - Hierarchical structure
    - search_codebase() - Grep-style search
    - read_file() - Read individual files

    If allow_write=True, also provides:
    - write_file() - Write/create files
    - create_directory() - Create directories
    - delete_file() - Delete files

    Args:
        directory: Root directory for access
        allow_write: Enable write operations (default: False)
        max_file_size_mb: Maximum file size in MB (default: 10)
        max_directory_entries: Maximum entries to list (default: 10000)
        blocked_patterns: Glob patterns to block (default: None)
        blocked_extensions: File extensions to block (default: None)

    Returns:
        FileSystemTools instance (or FileSystemWriteTools if allow_write=True)

    Example:
        # Read-only directory access
        tools = create_directory_tools("/path/to/repo")
        tree = tools.get_directory_tree(".", max_depth=3)
        results = tools.search_codebase("TODO", ".", file_pattern="*.py")

        # Read-write access
        tools = create_directory_tools("/path/to/repo", allow_write=True)
        tools.write_file("new_file.txt", "content")
    """
    # Resolve directory to absolute path
    root_path = Path(directory).resolve()

    if not root_path.exists():
        raise ValueError(f"Directory does not exist: {directory}")

    if not root_path.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    # Default blocked patterns for security
    if blocked_patterns is None:
        blocked_patterns = []

    if blocked_extensions is None:
        blocked_extensions = []

    # Create policy
    if allow_write:
        # Write-enabled policy
        policy = FileSystemPolicy(
            allowed_roots=[str(root_path)],
            max_file_size_mb=int(max_file_size_mb),
            max_directory_entries=max_directory_entries,
            blocked_patterns=blocked_patterns,
            blocked_extensions=blocked_extensions,
            allow_write=True,
            writable_roots=[str(root_path)]
        )
        return FileSystemWriteTools(policy)
    else:
        # Read-only policy
        policy = FileSystemPolicy(
            allowed_roots=[str(root_path)],
            max_file_size_mb=int(max_file_size_mb),
            max_directory_entries=max_directory_entries,
            blocked_patterns=blocked_patterns,
            blocked_extensions=blocked_extensions
        )
        return FileSystemTools(policy)


# Backward compatibility alias
safe_read_file = read_file_secure
