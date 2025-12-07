"""
Audit logging for file access.

Provides structured logging of all file access attempts with:
- Success/failure tracking
- Operation type (read, write, delete, etc.)
- Configurable output (file, console, both)
- Structured log format for analysis
"""
import logging
import uuid
from datetime import datetime
from typing import Optional
from pathlib import Path


class AuditLogger:
    """
    Audit logging for file access.

    Logs all file access attempts with operation type, path, and result.
    Useful for security monitoring and compliance.
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        console: bool = False,
        log_level: int = logging.INFO
    ):
        """
        Initialize audit logger.

        Args:
            log_file: Path to log file (creates if doesn't exist)
            console: Also log to console/stderr
            log_level: Logging level (default: INFO)
        """
        # Use unique logger name per instance to avoid shared state
        logger_name = f'llm_fs_tools.audit.{uuid.uuid4().hex[:8]}'
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(log_level)
        self.logger.propagate = False  # Don't propagate to root logger

        self._file_handler = None

        # File handler
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            self._file_handler = logging.FileHandler(log_file, encoding='utf-8')
            self._file_handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            self.logger.addHandler(self._file_handler)

        # Console handler
        if console:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '[AUDIT] %(message)s'
            ))
            self.logger.addHandler(handler)

        self.log_file = log_file
        self.console = console

    def _flush(self) -> None:
        """Flush file handler to ensure writes are persisted."""
        if self._file_handler:
            self._file_handler.flush()

    def log_access(
        self,
        operation: str,
        path: str,
        success: bool,
        details: str = ""
    ) -> None:
        """
        Log a file access attempt.

        Args:
            operation: Type of operation (read, write, delete, mkdir, etc.)
            path: Path that was accessed
            success: Whether operation succeeded
            details: Additional details (error message, etc.)
        """
        status = "SUCCESS" if success else "DENIED"
        message = f"{operation.upper()} | {status} | {path}"

        if details:
            message += f" | {details}"

        if success:
            self.logger.info(message)
        else:
            self.logger.warning(message)
        self._flush()

    def log_warning(self, message: str) -> None:
        """
        Log a security warning.

        Args:
            message: Warning message
        """
        self.logger.warning(f"WARNING | {message}")
        self._flush()

    def log_error(self, message: str) -> None:
        """
        Log a security error.

        Args:
            message: Error message
        """
        self.logger.error(f"ERROR | {message}")
        self._flush()

    def log_security_event(
        self,
        event_type: str,
        path: str,
        description: str
    ) -> None:
        """
        Log a security-related event.

        Args:
            event_type: Type of security event (symlink_blocked, traversal_attempt, etc.)
            path: Path involved
            description: Description of the event
        """
        self.logger.warning(f"SECURITY | {event_type} | {path} | {description}")
        self._flush()

    def get_log_path(self) -> Optional[str]:
        """
        Get the path to the log file.

        Returns:
            Log file path or None if not logging to file
        """
        return self.log_file


class NullAuditLogger(AuditLogger):
    """
    Null audit logger that discards all logs.

    Useful when audit logging is not needed but the interface is expected.
    """

    def __init__(self):
        """Initialize null logger (no configuration needed)."""
        # Don't call parent __init__ - we don't want to create any handlers
        self.log_file = None
        self.console = False

    def log_access(self, operation: str, path: str, success: bool, details: str = "") -> None:
        """Discard log entry."""
        pass

    def log_warning(self, message: str) -> None:
        """Discard warning."""
        pass

    def log_error(self, message: str) -> None:
        """Discard error."""
        pass

    def log_security_event(self, event_type: str, path: str, description: str) -> None:
        """Discard security event."""
        pass


class MemoryAuditLogger(AuditLogger):
    """
    Audit logger that stores entries in memory.

    Useful for testing and programmatic access to audit log.
    """

    def __init__(self, max_entries: int = 1000):
        """
        Initialize memory logger.

        Args:
            max_entries: Maximum entries to keep (oldest removed when exceeded)
        """
        self.log_file = None
        self.console = False
        self.max_entries = max_entries
        self.entries: list[dict] = []

    def log_access(
        self,
        operation: str,
        path: str,
        success: bool,
        details: str = ""
    ) -> None:
        """Store log entry in memory."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation.upper(),
            "path": path,
            "success": success,
            "details": details
        }
        self.entries.append(entry)

        # Trim if over limit
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]

    def log_warning(self, message: str) -> None:
        """Store warning in memory."""
        self.entries.append({
            "timestamp": datetime.now().isoformat(),
            "type": "warning",
            "message": message
        })
        # Trim if over limit
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]

    def log_error(self, message: str) -> None:
        """Store error in memory."""
        self.entries.append({
            "timestamp": datetime.now().isoformat(),
            "type": "error",
            "message": message
        })
        # Trim if over limit
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]

    def log_security_event(
        self,
        event_type: str,
        path: str,
        description: str
    ) -> None:
        """Store security event in memory."""
        self.entries.append({
            "timestamp": datetime.now().isoformat(),
            "type": "security",
            "event_type": event_type,
            "path": path,
            "description": description
        })
        # Trim if over limit
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]

    def get_entries(self) -> list[dict]:
        """
        Get all stored log entries.

        Returns:
            List of log entry dictionaries
        """
        return self.entries.copy()

    def get_failures(self) -> list[dict]:
        """
        Get all failed access attempts.

        Returns:
            List of failed access entries
        """
        return [e for e in self.entries if e.get("success") is False]

    def get_security_events(self) -> list[dict]:
        """
        Get all security events.

        Returns:
            List of security event entries
        """
        return [e for e in self.entries if e.get("type") == "security"]

    def clear(self) -> None:
        """Clear all stored entries."""
        self.entries.clear()
