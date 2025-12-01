"""
Platform-specific secure file opening.
"""
import os
import platform
from pathlib import Path
from typing import Protocol, Tuple

from ..exceptions import SecurityError


class SecureOpener(Protocol):
    """Protocol for platform-specific secure file opening"""

    def secure_open(self, path: Path, flags: int) -> Tuple[int, Path]:
        """
        Open file securely for this platform.

        Returns:
            (file_descriptor, canonical_path)
        """
        ...


def secure_open_unix(path: Path, flags: int) -> Tuple[int, Path]:
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


def secure_open_windows(path: Path, flags: int) -> Tuple[int, Path]:
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


def secure_open(path: Path, flags: int = os.O_RDONLY) -> Tuple[int, Path]:
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
