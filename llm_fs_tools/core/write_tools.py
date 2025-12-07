"""
Write-enabled filesystem tools for LLMs.

Provides secure write operations with:
- write_file: Atomic file writes using temp file + rename
- delete_file: Secure file deletion with validation

Requires explicit permission via FileSystemPolicy(allow_write=True).
"""
import os
import tempfile
from pathlib import Path

from .security import FileSystemPolicy
from ..exceptions import SecurityError


class FileSystemWriteTools:
    """
    Write filesystem tools - requires explicit permission.

    All write operations require:
    - allow_write=True in policy
    - Path within writable_roots
    """

    def __init__(self, security_policy: FileSystemPolicy):
        """
        Initialize with security policy.

        Args:
            security_policy: Policy with allow_write=True and writable_roots defined

        Raises:
            ValueError: If write is not enabled in policy
        """
        self.policy = security_policy

        if not self.policy.allow_write:
            raise ValueError(
                "Write tools require allow_write=True in policy. "
                "Create policy with: FileSystemPolicy(..., allow_write=True, writable_roots=[...])"
            )

        if not self.policy.writable_roots:
            raise ValueError(
                "Write tools require writable_roots to be defined. "
                "Create policy with: FileSystemPolicy(..., writable_roots=['/path/to/writable'])"
            )

    def write_file(
        self,
        path: str,
        content: str,
        encoding: str = 'utf-8',
        create_dirs: bool = False
    ) -> dict:
        """
        Atomically write file with security validation.

        Uses temp file + rename for atomic operation (POSIX guarantees).

        Args:
            path: Path to write file
            content: Content to write
            encoding: File encoding (default: utf-8)
            create_dirs: Create parent directories if they don't exist

        Returns:
            Standardized response dict:
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

            # Resolve to absolute path
            if not file_path.is_absolute():
                file_path = Path.cwd() / file_path
            file_path = file_path.resolve()

            # Check write permission
            if not self.policy.can_write(file_path):
                raise SecurityError(
                    f"Write not allowed: {path}. "
                    f"Path must be within writable_roots: {[str(r) for r in self.policy.writable_roots]}"
                )

            # Check blocked patterns
            if self.policy._matches_blocked(file_path):
                raise SecurityError(f"Path matches blocked pattern: {path}")

            # Check blocked extensions
            if file_path.suffix.lower() in self.policy.blocked_extensions:
                raise SecurityError(f"Blocked extension: {file_path.suffix}")

            # Create parent directories if requested
            if create_dirs:
                # Verify parent would be within writable roots
                if not self.policy.can_write(file_path.parent / "dummy"):
                    # FIX 1: Removed f-string (no variables used)
                    raise SecurityError("Cannot create directories outside writable roots")
                file_path.parent.mkdir(parents=True, exist_ok=True)
            elif not file_path.parent.exists():
                raise SecurityError(
                    f"Parent directory does not exist: {file_path.parent}. "
                    f"Use create_dirs=True to create it."
                )

            # Track if file existed before
            existed = file_path.exists()

            # Atomic write using temp file + rename
            # Create temp file in same directory (ensures same filesystem for atomic rename)
            fd = None
            tmp_path = None
            try:
                fd, tmp_path_str = tempfile.mkstemp(
                    dir=str(file_path.parent),
                    prefix='.tmp_write_',
                    suffix=file_path.suffix
                )
                tmp_path = Path(tmp_path_str)

                # Write content
                content_bytes = content.encode(encoding)
                os.write(fd, content_bytes)
                os.close(fd)
                fd = None

                # Atomic rename (POSIX guarantees atomicity)
                tmp_path.replace(file_path)

            except Exception: # FIX 2: Removed 'as e' here because 'e' is NOT used in this block
                # Clean up temp file on error
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                if tmp_path and tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass
                raise

            # Log audit trail
            operation = "overwrite" if existed else "create"
            if self.policy.audit:
                self.policy.audit.log_access("write", str(file_path), True, operation)

            return {
                "success": True,
                "data": {
                    "bytes_written": len(content.encode(encoding)),
                    "path": str(file_path)
                },
                "metadata": {
                    "tool": "write_file",
                    "operation": operation
                }
            }

        except SecurityError as e: # KEEP 'as e' here because we use str(e) below
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "write_file", "path": str(path)}
            }
        except PermissionError: # KEEP removed 'as e' here (unused)
            return {
                "success": False,
                "error": f"Permission denied: {path}",
                "metadata": {"tool": "write_file", "path": str(path)}
            }
        except Exception as e: # KEEP 'as e' here because we use str(e) below
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "write_file", "path": str(path)}
            }

    def delete_file(self, path: str) -> dict:
        """
        Delete file with security validation.

        Args:
            path: Path to file to delete

        Returns:
            Standardized response dict:
            {
                "success": True,
                "data": {
                    "path": "/resolved/path"
                },
                "metadata": {
                    "tool": "delete_file"
                }
            }
        """
        try:
            file_path = Path(path)

            # Resolve to absolute path
            if not file_path.is_absolute():
                file_path = Path.cwd() / file_path
            file_path = file_path.resolve()

            # Check write permission (delete requires write permission)
            if not self.policy.can_write(file_path):
                raise SecurityError(
                    f"Delete not allowed: {path}. "
                    f"Path must be within writable_roots."
                )

            # Verify file exists
            if not file_path.exists():
                raise SecurityError(f"File does not exist: {path}")

            # Verify it's a regular file (not directory, symlink, etc.)
            if not file_path.is_file():
                raise SecurityError(f"Not a regular file: {path}")

            # Check if it's a symlink (extra safety)
            if file_path.is_symlink():
                raise SecurityError(f"Cannot delete symlink: {path}")

            # Delete the file
            file_path.unlink()

            # Log audit trail
            if self.policy.audit:
                self.policy.audit.log_access("delete", str(file_path), True)

            return {
                "success": True,
                "data": {
                    "path": str(file_path)
                },
                "metadata": {
                    "tool": "delete_file"
                }
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "delete_file", "path": str(path)}
            }
        except PermissionError:
            return {
                "success": False,
                "error": f"Permission denied: {path}",
                "metadata": {"tool": "delete_file", "path": str(path)}
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "delete_file", "path": str(path)}
            }

    def create_directory(self, path: str, parents: bool = False) -> dict:
        """
        Create a directory with security validation.

        Args:
            path: Path to directory to create
            parents: Create parent directories if they don't exist

        Returns:
            Standardized response dict:
            {
                "success": True,
                "data": {
                    "path": "/resolved/path"
                },
                "metadata": {
                    "tool": "create_directory"
                }
            }
        """
        try:
            dir_path = Path(path)

            # Resolve to absolute path
            if not dir_path.is_absolute():
                dir_path = Path.cwd() / dir_path
            dir_path = dir_path.resolve()

            # Check write permission
            if not self.policy.can_write(dir_path / "dummy"):
                raise SecurityError(
                    f"Create directory not allowed: {path}. "
                    f"Path must be within writable_roots."
                )

            # Check if already exists
            if dir_path.exists():
                if dir_path.is_dir():
                    return {
                        "success": True,
                        "data": {"path": str(dir_path)},
                        "metadata": {"tool": "create_directory", "operation": "already_exists"}
                    }
                else:
                    raise SecurityError(f"Path exists but is not a directory: {path}")

            # Create directory
            dir_path.mkdir(parents=parents, exist_ok=True)

            # Log audit trail
            if self.policy.audit:
                self.policy.audit.log_access("mkdir", str(dir_path), True)

            return {
                "success": True,
                "data": {
                    "path": str(dir_path)
                },
                "metadata": {
                    "tool": "create_directory",
                    "operation": "created"
                }
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "create_directory", "path": str(path)}
            }
        except PermissionError:
            return {
                "success": False,
                "error": f"Permission denied: {path}",
                "metadata": {"tool": "create_directory", "path": str(path)}
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "create_directory", "path": str(path)}
            }