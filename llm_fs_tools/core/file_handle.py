"""
Secure file handle abstraction.
"""
import os
from pathlib import Path
from contextlib import contextmanager
from typing import Optional, Generator

from .security import SecurityPolicy


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
            except Exception:
                pass


@contextmanager
def open_secure(
    path: str | Path,
    policy: SecurityPolicy
) -> Generator[SecureFileHandle, None, None]:
    """
    Atomically open and validate file - TOCTOU resistant.

    Flow:
        1. Minimal pre-validation (syntax only)
        2. Platform-specific secure open
        3. ALL security checks on FD
        4. Return handle
    """
    from ..platform.secure_open import secure_open

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
