"""
Unit tests for audit logging utilities.

Tests cover:
- AuditLogger: File and console logging
- NullAuditLogger: No-op logging
- MemoryAuditLogger: In-memory logging for testing
"""
import os
import sys
import pytest
from pathlib import Path
import tempfile

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from llm_fs_tools import AuditLogger, NullAuditLogger, MemoryAuditLogger


class TestAuditLogger:
    """Test AuditLogger with file output."""

    def test_log_to_file(self, tmp_path):
        """Can log to a file."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file=str(log_file))

        logger.log_access("read", "/path/to/file.txt", True)

        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "READ" in content
        assert "SUCCESS" in content
        assert "/path/to/file.txt" in content

    def test_log_failure(self, tmp_path):
        """Logs failures with WARNING level."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file=str(log_file))

        logger.log_access("write", "/blocked/path", False, "Access denied")

        content = log_file.read_text(encoding="utf-8")
        assert "WRITE" in content
        assert "DENIED" in content
        assert "Access denied" in content

    def test_log_with_details(self, tmp_path):
        """Includes details in log entry."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file=str(log_file))

        logger.log_access("read", "/file.txt", True, "1024 bytes")

        content = log_file.read_text(encoding="utf-8")
        assert "1024 bytes" in content

    def test_log_warning(self, tmp_path):
        """Can log warnings."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file=str(log_file))

        logger.log_warning("Suspicious activity detected")

        content = log_file.read_text(encoding="utf-8")
        assert "WARNING" in content
        assert "Suspicious activity" in content

    def test_log_error(self, tmp_path):
        """Can log errors."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file=str(log_file))

        logger.log_error("Critical failure occurred")

        content = log_file.read_text(encoding="utf-8")
        assert "ERROR" in content
        assert "Critical failure" in content

    def test_log_security_event(self, tmp_path):
        """Can log security events."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file=str(log_file))

        logger.log_security_event(
            "symlink_blocked",
            "/path/to/symlink",
            "Symlink access attempt blocked"
        )

        content = log_file.read_text(encoding="utf-8")
        assert "SECURITY" in content
        assert "symlink_blocked" in content
        assert "/path/to/symlink" in content

    def test_creates_parent_directories(self, tmp_path):
        """Creates parent directories for log file."""
        log_file = tmp_path / "nested" / "dir" / "audit.log"
        logger = AuditLogger(log_file=str(log_file))

        logger.log_access("read", "/file.txt", True)

        assert log_file.exists()

    def test_get_log_path(self, tmp_path):
        """Returns log file path."""
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file=str(log_file))

        assert logger.get_log_path() == str(log_file)

    def test_no_file_returns_none(self):
        """Returns None when not logging to file."""
        logger = AuditLogger(console=True)

        assert logger.get_log_path() is None


class TestNullAuditLogger:
    """Test NullAuditLogger (no-op implementation)."""

    def test_log_access_does_nothing(self):
        """log_access is a no-op."""
        logger = NullAuditLogger()
        # Should not raise
        logger.log_access("read", "/path", True)
        logger.log_access("write", "/path", False, "error")

    def test_log_warning_does_nothing(self):
        """log_warning is a no-op."""
        logger = NullAuditLogger()
        logger.log_warning("warning message")

    def test_log_error_does_nothing(self):
        """log_error is a no-op."""
        logger = NullAuditLogger()
        logger.log_error("error message")

    def test_log_security_event_does_nothing(self):
        """log_security_event is a no-op."""
        logger = NullAuditLogger()
        logger.log_security_event("event", "/path", "description")

    def test_get_log_path_returns_none(self):
        """Always returns None."""
        logger = NullAuditLogger()
        assert logger.get_log_path() is None


class TestMemoryAuditLogger:
    """Test MemoryAuditLogger for in-memory logging."""

    def test_stores_access_entries(self):
        """Stores access log entries in memory."""
        logger = MemoryAuditLogger()

        logger.log_access("read", "/file.txt", True)
        logger.log_access("write", "/other.txt", False, "blocked")

        entries = logger.get_entries()
        assert len(entries) == 2
        assert entries[0]["operation"] == "READ"
        assert entries[0]["path"] == "/file.txt"
        assert entries[0]["success"] is True
        assert entries[1]["success"] is False

    def test_stores_warnings(self):
        """Stores warning entries."""
        logger = MemoryAuditLogger()

        logger.log_warning("Test warning")

        entries = logger.get_entries()
        assert len(entries) == 1
        assert entries[0]["type"] == "warning"
        assert entries[0]["message"] == "Test warning"

    def test_stores_errors(self):
        """Stores error entries."""
        logger = MemoryAuditLogger()

        logger.log_error("Test error")

        entries = logger.get_entries()
        assert len(entries) == 1
        assert entries[0]["type"] == "error"
        assert entries[0]["message"] == "Test error"

    def test_stores_security_events(self):
        """Stores security event entries."""
        logger = MemoryAuditLogger()

        logger.log_security_event("traversal_attempt", "/etc/passwd", "Path traversal blocked")

        entries = logger.get_entries()
        assert len(entries) == 1
        assert entries[0]["type"] == "security"
        assert entries[0]["event_type"] == "traversal_attempt"
        assert entries[0]["path"] == "/etc/passwd"

    def test_get_failures(self):
        """Can filter to only failures."""
        logger = MemoryAuditLogger()

        logger.log_access("read", "/file1.txt", True)
        logger.log_access("read", "/file2.txt", False)
        logger.log_access("write", "/file3.txt", False)
        logger.log_access("read", "/file4.txt", True)

        failures = logger.get_failures()
        assert len(failures) == 2
        assert all(f["success"] is False for f in failures)

    def test_get_security_events(self):
        """Can filter to only security events."""
        logger = MemoryAuditLogger()

        logger.log_access("read", "/file.txt", True)
        logger.log_security_event("type1", "/path1", "desc1")
        logger.log_warning("warning")
        logger.log_security_event("type2", "/path2", "desc2")

        events = logger.get_security_events()
        assert len(events) == 2
        assert all(e["type"] == "security" for e in events)

    def test_clear(self):
        """Can clear all entries."""
        logger = MemoryAuditLogger()

        logger.log_access("read", "/file.txt", True)
        logger.log_warning("warning")
        assert len(logger.get_entries()) == 2

        logger.clear()
        assert len(logger.get_entries()) == 0

    def test_max_entries_limit(self):
        """Respects max_entries limit."""
        logger = MemoryAuditLogger(max_entries=5)

        for i in range(10):
            logger.log_access("read", f"/file{i}.txt", True)

        entries = logger.get_entries()
        assert len(entries) == 5
        # Should keep the most recent entries
        assert entries[0]["path"] == "/file5.txt"
        assert entries[4]["path"] == "/file9.txt"

    def test_entries_have_timestamps(self):
        """All entries have timestamps."""
        logger = MemoryAuditLogger()

        logger.log_access("read", "/file.txt", True)
        logger.log_warning("warning")
        logger.log_security_event("event", "/path", "desc")

        for entry in logger.get_entries():
            assert "timestamp" in entry

    def test_get_entries_returns_copy(self):
        """get_entries returns a copy, not the original list."""
        logger = MemoryAuditLogger()
        logger.log_access("read", "/file.txt", True)

        entries1 = logger.get_entries()
        entries2 = logger.get_entries()

        assert entries1 is not entries2
        assert entries1 == entries2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
