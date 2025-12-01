"""
Unit tests for read-only FileSystemTools.

Tests cover:
- read_file: Read file content with line ranges
- list_directory: List directory contents
- get_directory_tree: Hierarchical directory structure
- search_codebase: Pattern search across files
"""
import os
import sys
import pytest
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from llm_fs_tools import FileSystemPolicy, FileSystemTools, SecurityError


class TestReadFile:
    """Test read_file method."""

    def test_read_regular_file(self, tmp_path):
        """Can read a regular file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.read_file(str(test_file))

        assert result["success"] is True
        assert result["data"]["content"] == "Hello, World!"
        assert result["metadata"]["tool"] == "read_file"
        assert result["metadata"]["size_bytes"] == 13

    def test_read_file_with_line_range(self, tmp_path):
        """Can read specific line range."""
        test_file = tmp_path / "lines.txt"
        test_file.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.read_file(str(test_file), start_line=2, end_line=4)

        assert result["success"] is True
        assert len(result["data"]["lines"]) == 3
        assert "line2" in result["data"]["content"]
        assert "line3" in result["data"]["content"]
        assert "line4" in result["data"]["content"]
        assert "line1" not in result["data"]["content"]
        assert "line5" not in result["data"]["content"]

    def test_read_nonexistent_file(self, tmp_path):
        """Reading nonexistent file returns error."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.read_file(str(tmp_path / "nonexistent.txt"))

        assert result["success"] is False
        # Error message varies by platform: "not found", "no such file", or "CreateFileW failed"
        error_lower = result["error"].lower()
        assert any(x in error_lower for x in ["not found", "no such file", "createfilew failed", "nonexistent"])

    def test_read_file_outside_root(self, tmp_path):
        """Reading file outside allowed root is blocked."""
        # Create allowed and outside directories
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        secret_file = outside / "secret.txt"
        secret_file.write_text("secret content", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(allowed)])
        tools = FileSystemTools(policy)

        result = tools.read_file(str(secret_file))

        assert result["success"] is False
        assert "outside" in result["error"].lower() or "not found" in result["error"].lower()

    def test_read_file_blocked_extension(self, tmp_path):
        """Files with blocked extensions are rejected."""
        test_file = tmp_path / "secrets.env"
        test_file.write_text("API_KEY=secret", encoding="utf-8")

        policy = FileSystemPolicy(
            allowed_roots=[str(tmp_path)],
            blocked_extensions=[".env"]
        )
        tools = FileSystemTools(policy)

        result = tools.read_file(str(test_file))

        assert result["success"] is False
        assert "blocked" in result["error"].lower()


class TestListDirectory:
    """Test list_directory method."""

    def test_list_directory_basic(self, tmp_path):
        """Can list directory contents."""
        # Create files and subdirectory
        (tmp_path / "file1.txt").write_text("content1", encoding="utf-8")
        (tmp_path / "file2.py").write_text("print('hello')", encoding="utf-8")
        (tmp_path / "subdir").mkdir()

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.list_directory(str(tmp_path))

        assert result["success"] is True
        assert result["data"]["total"] == 3

        entries = {e["name"]: e for e in result["data"]["entries"]}
        assert "file1.txt" in entries
        assert entries["file1.txt"]["type"] == "file"
        assert "subdir" in entries
        assert entries["subdir"]["type"] == "directory"

    def test_list_directory_hidden_files(self, tmp_path):
        """Hidden files are excluded by default."""
        (tmp_path / "visible.txt").write_text("visible", encoding="utf-8")
        (tmp_path / ".hidden").write_text("hidden", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        # Without include_hidden
        result = tools.list_directory(str(tmp_path))
        names = [e["name"] for e in result["data"]["entries"]]
        assert "visible.txt" in names
        assert ".hidden" not in names

        # With include_hidden
        result = tools.list_directory(str(tmp_path), include_hidden=True)
        names = [e["name"] for e in result["data"]["entries"]]
        assert ".hidden" in names

    def test_list_directory_sorted(self, tmp_path):
        """Entries are sorted: directories first, then by name."""
        (tmp_path / "zebra.txt").write_text("z", encoding="utf-8")
        (tmp_path / "alpha.txt").write_text("a", encoding="utf-8")
        (tmp_path / "beta_dir").mkdir()
        (tmp_path / "alpha_dir").mkdir()

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.list_directory(str(tmp_path))
        names = [e["name"] for e in result["data"]["entries"]]

        # Directories first, then files, both sorted alphabetically
        assert names.index("alpha_dir") < names.index("alpha.txt")
        assert names.index("beta_dir") < names.index("alpha.txt")
        assert names.index("alpha_dir") < names.index("beta_dir")
        assert names.index("alpha.txt") < names.index("zebra.txt")

    def test_list_directory_outside_root(self, tmp_path):
        """Listing directory outside allowed root is blocked."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()

        policy = FileSystemPolicy(allowed_roots=[str(allowed)])
        tools = FileSystemTools(policy)

        result = tools.list_directory(str(outside))

        assert result["success"] is False
        assert "outside" in result["error"].lower()

    def test_list_nonexistent_directory(self, tmp_path):
        """Listing nonexistent directory returns error."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.list_directory(str(tmp_path / "nonexistent"))

        assert result["success"] is False
        assert "not found" in result["error"].lower()


class TestGetDirectoryTree:
    """Test get_directory_tree method."""

    def test_get_tree_basic(self, tmp_path):
        """Can get basic directory tree."""
        # Create structure:
        # tmp_path/
        #   file1.txt
        #   subdir/
        #     file2.txt
        (tmp_path / "file1.txt").write_text("content", encoding="utf-8")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file2.txt").write_text("content2", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.get_directory_tree(str(tmp_path))

        assert result["success"] is True
        tree = result["data"]
        assert tree["type"] == "directory"
        assert len(tree["children"]) == 2

        # Find subdir in children
        subdir_entry = next(c for c in tree["children"] if c["name"] == "subdir")
        assert subdir_entry["type"] == "directory"
        assert len(subdir_entry["children"]) == 1
        assert subdir_entry["children"][0]["name"] == "file2.txt"

    def test_get_tree_max_depth(self, tmp_path):
        """Tree respects max_depth parameter."""
        # Create deep structure
        current = tmp_path
        for i in range(5):
            current = current / f"level{i}"
            current.mkdir()
            (current / f"file{i}.txt").write_text("content", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.get_directory_tree(str(tmp_path), max_depth=2)

        assert result["success"] is True
        assert result["metadata"]["max_depth"] == 2

        # Navigate down and check truncation
        tree = result["data"]
        level0 = next(c for c in tree["children"] if c["name"] == "level0")
        level1 = next(c for c in level0["children"] if c["name"] == "level1")
        # Level2 should be truncated
        if any(c["name"] == "level2" for c in level1["children"]):
            level2 = next(c for c in level1["children"] if c["name"] == "level2")
            assert level2.get("truncated") is True

    def test_get_tree_hidden_files(self, tmp_path):
        """Hidden files are excluded by default."""
        (tmp_path / ".hidden").mkdir()
        (tmp_path / "visible").mkdir()

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.get_directory_tree(str(tmp_path))
        names = [c["name"] for c in result["data"]["children"]]
        assert ".hidden" not in names
        assert "visible" in names

        result = tools.get_directory_tree(str(tmp_path), include_hidden=True)
        names = [c["name"] for c in result["data"]["children"]]
        assert ".hidden" in names

    def test_get_tree_outside_root(self, tmp_path):
        """Getting tree outside allowed root is blocked."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()

        policy = FileSystemPolicy(allowed_roots=[str(allowed)])
        tools = FileSystemTools(policy)

        result = tools.get_directory_tree(str(outside))

        assert result["success"] is False


class TestSearchCodebase:
    """Test search_codebase method."""

    def test_search_basic(self, tmp_path):
        """Can search for pattern in files."""
        (tmp_path / "file1.py").write_text("def hello():\n    print('hello')\n", encoding="utf-8")
        (tmp_path / "file2.py").write_text("def goodbye():\n    print('bye')\n", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("def hello", str(tmp_path))

        assert result["success"] is True
        assert result["data"]["total_matches"] == 1
        assert result["data"]["matches"][0]["file"] == "file1.py"
        assert result["data"]["matches"][0]["line"] == 1
        assert "def hello" in result["data"]["matches"][0]["match"]

    def test_search_case_insensitive(self, tmp_path):
        """Search is case-insensitive by default."""
        (tmp_path / "test.py").write_text("Hello World\nhello world\nHELLO WORLD\n", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("hello", str(tmp_path))

        assert result["success"] is True
        assert result["data"]["total_matches"] == 3

    def test_search_case_sensitive(self, tmp_path):
        """Case-sensitive search works."""
        (tmp_path / "test.py").write_text("Hello World\nhello world\nHELLO WORLD\n", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("Hello", str(tmp_path), case_sensitive=True)

        assert result["success"] is True
        assert result["data"]["total_matches"] == 1

    def test_search_file_pattern(self, tmp_path):
        """Can filter by file pattern."""
        (tmp_path / "code.py").write_text("def main():\n    pass\n", encoding="utf-8")
        (tmp_path / "code.js").write_text("function main() {}\n", encoding="utf-8")
        (tmp_path / "readme.md").write_text("main documentation\n", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("main", str(tmp_path), file_pattern="*.py")

        assert result["success"] is True
        assert result["data"]["total_matches"] == 1
        assert result["data"]["matches"][0]["file"] == "code.py"

    def test_search_max_results(self, tmp_path):
        """Respects max_results limit."""
        # Create file with many matches
        content = "\n".join([f"match line {i}" for i in range(50)])
        (tmp_path / "many.txt").write_text(content, encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("match", str(tmp_path), max_results=10)

        assert result["success"] is True
        assert result["data"]["total_matches"] == 10
        assert result["data"]["truncated"] is True

    def test_search_invalid_regex(self, tmp_path):
        """Invalid regex returns error."""
        (tmp_path / "test.txt").write_text("content", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("[invalid(regex", str(tmp_path))

        assert result["success"] is False
        assert "invalid regex" in result["error"].lower()

    def test_search_recursive(self, tmp_path):
        """Search is recursive through subdirectories."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (tmp_path / "top.py").write_text("MARKER_TOP", encoding="utf-8")
        (subdir / "nested.py").write_text("MARKER_NESTED", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("MARKER", str(tmp_path))

        assert result["success"] is True
        assert result["data"]["total_matches"] == 2
        files = [m["file"] for m in result["data"]["matches"]]
        assert "top.py" in files
        assert str(Path("subdir") / "nested.py") in files or "subdir/nested.py" in files or "subdir\\nested.py" in files

    def test_search_skips_blocked_files(self, tmp_path):
        """Search skips files matching blocked patterns."""
        (tmp_path / "code.py").write_text("SECRET_KEY = 'abc'", encoding="utf-8")
        (tmp_path / "secrets.env").write_text("SECRET_KEY = 'xyz'", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("SECRET_KEY", str(tmp_path))

        assert result["success"] is True
        # Should only find in code.py, not in .env (blocked by default)
        files = [m["file"] for m in result["data"]["matches"]]
        assert "code.py" in files
        assert "secrets.env" not in files

    def test_search_outside_root(self, tmp_path):
        """Search outside allowed root is blocked."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "test.txt").write_text("content", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(allowed)])
        tools = FileSystemTools(policy)

        result = tools.search_codebase("content", str(outside))

        assert result["success"] is False


class TestIntegration:
    """Integration tests for FileSystemTools."""

    def test_workflow_list_then_read(self, tmp_path):
        """Can list directory then read discovered files."""
        (tmp_path / "file1.txt").write_text("content 1", encoding="utf-8")
        (tmp_path / "file2.txt").write_text("content 2", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        # List directory
        list_result = tools.list_directory(str(tmp_path))
        assert list_result["success"] is True

        # Read each file
        for entry in list_result["data"]["entries"]:
            if entry["type"] == "file":
                file_path = tmp_path / entry["name"]
                read_result = tools.read_file(str(file_path))
                assert read_result["success"] is True
                assert "content" in read_result["data"]["content"]

    def test_workflow_search_then_read(self, tmp_path):
        """Can search then read matched files."""
        (tmp_path / "match.py").write_text("def target_function():\n    pass\n", encoding="utf-8")
        (tmp_path / "other.py").write_text("def other():\n    pass\n", encoding="utf-8")

        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        tools = FileSystemTools(policy)

        # Search for pattern
        search_result = tools.search_codebase("target_function", str(tmp_path))
        assert search_result["success"] is True
        assert len(search_result["data"]["matches"]) == 1

        # Read the matched file
        matched_file = tmp_path / search_result["data"]["matches"][0]["file"]
        read_result = tools.read_file(str(matched_file))
        assert read_result["success"] is True
        assert "target_function" in read_result["data"]["content"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
