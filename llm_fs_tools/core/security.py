"""
Security policy and validation logic.
"""
import os
import stat
from pathlib import Path
from typing import Protocol, Optional, Any
from unicodedata import normalize

from ..exceptions import SecurityError


class SecurityPolicy(Protocol):
    """
    Protocol for security policies - enables custom implementations.
    
    This protocol defines the interface for validating file access.
    Implementations must follow the "Check-Use-Check" pattern to prevent TOCTOU.
    """

    def pre_validate_syntax(self, path: Path) -> Path:
        """
        Minimal syntax-only validation (no filesystem access).
        
        This should ONLY check syntax-level properties that don't require
        filesystem access. Security checks happen in post_validate_fd.
        
        Args:
            path: Path to validate
            
        Returns:
            Normalized path
            
        Raises:
            SecurityError: If syntax validation fails
        """
        ...

    def post_validate_fd(
        self,
        fd: int,
        real_path: Path,
        stat_info: os.stat_result
    ) -> None:
        """
        Validate after opening - raises SecurityError if invalid.
        
        ALL security checks happen here, after the file is open.
        Uses FD and stat info, not paths, to prevent TOCTOU.
        
        Args:
            fd: Open file descriptor
            real_path: Canonical path obtained from FD
            stat_info: Stat result from fstat(fd)
            
        Raises:
            SecurityError: If validation fails
        """
        ...

    def can_write(self, path: Path) -> bool:
        """
        Check if write is allowed to this path.
        
        Args:
            path: Path to check
            
        Returns:
            True if write is allowed
        """
        ...


class FileSystemPolicy:
    """
    Default security policy implementation.
    
    Enforces:
    - Path containment within allowed roots
    - File size limits
    - Blocked patterns and extensions
    - Special file type restrictions
    """

    def __init__(
        self,
        allowed_roots: list[str],
        max_file_size_mb: int = 5,
        max_directory_entries: int = 10000,
        blocked_patterns: Optional[list[str]] = None,
        blocked_extensions: Optional[list[str]] = None,
        # Write support
        allow_write: bool = False,
        writable_roots: Optional[list[str]] = None,
        # Audit support
        audit_logger: Optional[Any] = None
    ):
        """
        Initialize security policy.
        
        Args:
            allowed_roots: List of directory paths that can be accessed
            max_file_size_mb: Maximum file size in MB
            max_directory_entries: Maximum entries when listing directories
            blocked_patterns: Glob patterns to block (e.g., "*.env")
            blocked_extensions: File extensions to block (e.g., ".secret")
            allow_write: Whether to allow write operations
            writable_roots: List of directory paths that can be written to
            audit_logger: Optional audit logger instance
        """
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
        
        Args:
            path: Path to validate
            
        Returns:
            Normalized path
            
        Raises:
            SecurityError: If extension is blocked
        """
        # Normalize unicode (syntax)
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
        
        Args:
            fd: Open file descriptor
            real_path: Canonical path from FD
            stat_info: Stat result from fstat(fd)
            
        Raises:
            SecurityError: If validation fails
        """
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
        """
        Check if write is allowed.
        
        Args:
            path: Path to check
            
        Returns:
            True if write is allowed
        """
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
        """
        Check if path is within any of the roots.
        
        Args:
            path: Path to check
            roots: List of root paths
            
        Returns:
            True if path is within any root
        """
        for root in roots:
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def _matches_blocked(self, path: Path) -> bool:
        """
        Check if path matches any blocked pattern.
        
        Args:
            path: Path to check
            
        Returns:
            True if path matches a blocked pattern
        """
        import fnmatch
        path_str = str(path).lower()

        for pattern in self.blocked_patterns:
            if fnmatch.fnmatch(path_str, pattern.lower()):
                return True
        return False

    @staticmethod
    def _default_blocked() -> list[str]:
        """
        Default security patterns.
        
        Returns:
            List of glob patterns to block
        """
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
