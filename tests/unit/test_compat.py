"""
Tests for ollama-prompt compatibility layer.

These tests verify that the compatibility functions match
ollama-prompt's secure_file.py interface exactly.
"""

import os
import tempfile
import pytest
from pathlib import Path

from llm_fs_tools import (
    read_file_secure,
    secure_open_compat,
    create_directory_tools,
    safe_read_file,
    DEFAULT_MAX_FILE_BYTES,
)


class TestReadFileSecure:
    """Tests for read_file_secure() compatibility."""

    def test_read_file_success(self, tmp_path):
        """Test successful file read."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        result = read_file_secure(str(test_file), repo_root=str(tmp_path))

        assert result["ok"] is True
        assert result["path"] == str(test_file)
        assert result["content"] == "Hello, World!"

    def test_read_file_relative_path(self, tmp_path):
        """Test reading with relative path."""
        test_file = tmp_path / "subdir" / "test.txt"
        test_file.parent.mkdir()
        test_file.write_text("Relative path content")

        result = read_file_secure("subdir/test.txt", repo_root=str(tmp_path))

        assert result["ok"] is True
        assert result["content"] == "Relative path content"

    def test_read_file_not_found(self, tmp_path):
        """Test reading non-existent file."""
        result = read_file_secure("nonexistent.txt", repo_root=str(tmp_path))

        assert result["ok"] is False
        assert "path" in result
        assert "error" in result
        # Error message varies by platform
        error_lower = result["error"].lower()
        assert any(x in error_lower for x in ["not found", "no such file", "createfilew failed", "does not exist"])

    def test_read_file_max_bytes(self, tmp_path):
        """Test max_bytes truncation."""
        test_file = tmp_path / "large.txt"
        content = "x" * 1000
        test_file.write_text(content)

        result = read_file_secure(str(test_file), repo_root=str(tmp_path), max_bytes=100)

        assert result["ok"] is True
        assert len(result["content"]) < len(content)
        assert "[TRUNCATED" in result["content"]

    def test_read_file_outside_root(self, tmp_path):
        """Test reading file outside allowed root."""
        # Create file in temp root
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Create subdirectory as the allowed root
        subdir = tmp_path / "allowed"
        subdir.mkdir()

        # Try to read file from parent (outside allowed root)
        result = read_file_secure(
            str(test_file),
            repo_root=str(subdir)
        )

        assert result["ok"] is False
        assert "error" in result

    def test_default_max_bytes(self):
        """Test DEFAULT_MAX_FILE_BYTES matches ollama-prompt."""
        assert DEFAULT_MAX_FILE_BYTES == 200_000

    def test_safe_read_file_alias(self, tmp_path):
        """Test safe_read_file is alias for read_file_secure."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("alias test")

        result = safe_read_file(str(test_file), repo_root=str(tmp_path))

        assert result["ok"] is True
        assert result["content"] == "alias test"


class TestSecureOpen:
    """Tests for secure_open_compat() compatibility."""

    def test_secure_open_success(self, tmp_path):
        """Test successful secure open."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Secure open test")

        result = secure_open_compat(str(test_file), repo_root=str(tmp_path))

        assert result["ok"] is True
        assert "fd" in result
        assert isinstance(result["fd"], int)
        assert "resolved_path" in result
        assert "size" in result
        assert result["size"] == len("Secure open test")

        # Clean up - close the fd
        os.close(result["fd"])

    def test_secure_open_relative_path(self, tmp_path):
        """Test secure open with relative path."""
        test_file = tmp_path / "subdir" / "test.txt"
        test_file.parent.mkdir()
        test_file.write_text("content")

        result = secure_open_compat("subdir/test.txt", repo_root=str(tmp_path))

        assert result["ok"] is True
        assert result["fd"] is not None

        os.close(result["fd"])

    def test_secure_open_not_found(self, tmp_path):
        """Test secure open for non-existent file."""
        result = secure_open_compat("nonexistent.txt", repo_root=str(tmp_path))

        assert result["ok"] is False
        assert "error" in result

    def test_secure_open_read_content(self, tmp_path):
        """Test reading content from secure-opened fd."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Read from FD")

        result = secure_open_compat(str(test_file), repo_root=str(tmp_path))

        assert result["ok"] is True

        # Read from fd
        with os.fdopen(result["fd"], "r", encoding="utf-8") as f:
            content = f.read()

        assert content == "Read from FD"


class TestCreateDirectoryTools:
    """Tests for create_directory_tools() factory."""

    def test_create_readonly_tools(self, tmp_path):
        """Test creating read-only directory tools."""
        # Create some test files
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.py").write_text("print('hello')")
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "file3.txt").write_text("nested")

        tools = create_directory_tools(str(tmp_path))

        # Test list_directory
        result = tools.list_directory(str(tmp_path))
        assert result["success"] is True
        assert len(result["data"]["entries"]) >= 2

        # Test get_directory_tree
        result = tools.get_directory_tree(str(tmp_path), max_depth=2)
        assert result["success"] is True
        assert result["data"]["type"] == "directory"

        # Test read_file
        result = tools.read_file(str(tmp_path / "file1.txt"))
        assert result["success"] is True
        assert result["data"]["content"] == "content1"

        # Test search_codebase
        result = tools.search_codebase("hello", str(tmp_path), file_pattern="*.py")
        assert result["success"] is True

    def test_create_write_tools(self, tmp_path):
        """Test creating write-enabled directory tools."""
        tools = create_directory_tools(str(tmp_path), allow_write=True)

        # Test write_file
        result = tools.write_file(str(tmp_path / "new_file.txt"), "new content")
        assert result["success"] is True

        # Verify file was created
        assert (tmp_path / "new_file.txt").read_text() == "new content"

    def test_invalid_directory(self, tmp_path):
        """Test error handling for invalid directory."""
        with pytest.raises(ValueError, match="does not exist"):
            create_directory_tools(str(tmp_path / "nonexistent"))

    def test_not_a_directory(self, tmp_path):
        """Test error handling for file instead of directory."""
        test_file = tmp_path / "file.txt"
        test_file.write_text("content")

        with pytest.raises(ValueError, match="Not a directory"):
            create_directory_tools(str(test_file))

    def test_custom_options(self, tmp_path):
        """Test custom options for directory tools."""
        tools = create_directory_tools(
            str(tmp_path),
            max_file_size_mb=5.0,
            max_directory_entries=500,
            blocked_patterns=["*.log"],
            blocked_extensions=[".tmp"]
        )

        # Should work
        result = tools.list_directory(str(tmp_path))
        assert result["success"] is True


class TestSymlinkBlocking:
    """Tests for symlink blocking (Unix only)."""

    @pytest.mark.skipif(os.name == 'nt', reason="Symlinks require admin on Windows")
    def test_read_file_blocks_symlink(self, tmp_path):
        """Test that symlinks are blocked."""
        # Create real file
        real_file = tmp_path / "real.txt"
        real_file.write_text("real content")

        # Create symlink
        link_file = tmp_path / "link.txt"
        link_file.symlink_to(real_file)

        # Should block symlink
        result = read_file_secure(str(link_file), repo_root=str(tmp_path))

        assert result["ok"] is False
        # Error should mention symlink or blocked

    @pytest.mark.skipif(os.name == 'nt', reason="Symlinks require admin on Windows")
    def test_secure_open_blocks_symlink(self, tmp_path):
        """Test that secure_open blocks symlinks."""
        real_file = tmp_path / "real.txt"
        real_file.write_text("real content")

        link_file = tmp_path / "link.txt"
        link_file.symlink_to(real_file)

        result = secure_open_compat(str(link_file), repo_root=str(tmp_path))

        assert result["ok"] is False


class TestReturnFormat:
    """Tests verifying exact return format matches ollama-prompt."""

    def test_read_success_format(self, tmp_path):
        """Test successful read has correct keys."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = read_file_secure(str(test_file), repo_root=str(tmp_path))

        # Must have exactly these keys
        assert "ok" in result
        assert "path" in result
        assert "content" in result
        assert result["ok"] is True

    def test_read_failure_format(self, tmp_path):
        """Test failed read has correct keys."""
        result = read_file_secure("nonexistent.txt", repo_root=str(tmp_path))

        # Must have exactly these keys
        assert "ok" in result
        assert "path" in result
        assert "error" in result
        assert result["ok"] is False

    def test_secure_open_success_format(self, tmp_path):
        """Test successful secure_open has correct keys."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = secure_open_compat(str(test_file), repo_root=str(tmp_path))

        assert "ok" in result
        assert "fd" in result
        assert "path" in result
        assert "resolved_path" in result
        assert "size" in result
        assert result["ok"] is True

        os.close(result["fd"])

    def test_secure_open_failure_format(self, tmp_path):
        """Test failed secure_open has correct keys."""
        result = secure_open_compat("nonexistent.txt", repo_root=str(tmp_path))

        assert "ok" in result
        assert "path" in result
        assert "error" in result
        assert result["ok"] is False
