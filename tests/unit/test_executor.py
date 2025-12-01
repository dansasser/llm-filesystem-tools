"""
Unit tests for ToolExecutor.

Tests cover:
- Read tool execution
- Write tool execution
- Error handling
- Argument validation
- Batch execution
"""
import sys
import pytest
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from llm_fs_tools import (
    FileSystemPolicy,
    FileSystemTools,
    FileSystemWriteTools,
    ToolExecutor
)


class TestExecutorInit:
    """Test ToolExecutor initialization."""

    def test_read_only_init(self, tmp_path):
        """Can initialize with only read tools."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        read_tools = FileSystemTools(policy)

        executor = ToolExecutor(read_tools=read_tools)

        assert executor.read_tools == read_tools
        assert executor.write_tools is None

    def test_read_write_init(self, tmp_path):
        """Can initialize with both read and write tools."""
        policy = FileSystemPolicy(
            allowed_roots=[str(tmp_path)],
            allow_write=True,
            writable_roots=[str(tmp_path)]
        )
        read_tools = FileSystemTools(policy)
        write_tools = FileSystemWriteTools(policy)

        executor = ToolExecutor(read_tools=read_tools, write_tools=write_tools)

        assert executor.read_tools == read_tools
        assert executor.write_tools == write_tools


class TestReadToolExecution:
    """Test read tool execution."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create executor with read-only tools."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        return ToolExecutor(read_tools=FileSystemTools(policy))

    def test_execute_read_file(self, tmp_path, executor):
        """Can execute read_file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!", encoding="utf-8")

        result = executor.execute("read_file", {"path": str(test_file)})

        assert result["success"] is True
        assert result["data"]["content"] == "Hello, World!"

    def test_execute_list_directory(self, tmp_path, executor):
        """Can execute list_directory."""
        (tmp_path / "file1.txt").touch()
        (tmp_path / "file2.txt").touch()

        result = executor.execute("list_directory", {"path": str(tmp_path)})

        assert result["success"] is True
        names = [e["name"] for e in result["data"]["entries"]]
        assert "file1.txt" in names
        assert "file2.txt" in names

    def test_execute_get_directory_tree(self, tmp_path, executor):
        """Can execute get_directory_tree."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file.txt").touch()

        result = executor.execute("get_directory_tree", {"path": str(tmp_path)})

        assert result["success"] is True
        # Tree structure is returned directly in data
        assert "name" in result["data"]
        assert "type" in result["data"]
        assert result["data"]["type"] == "directory"

    def test_execute_search_codebase(self, tmp_path, executor):
        """Can execute search_codebase."""
        test_file = tmp_path / "code.py"
        test_file.write_text("def hello():\n    pass\n", encoding="utf-8")

        result = executor.execute("search_codebase", {
            "pattern": "def hello",
            "path": str(tmp_path)
        })

        assert result["success"] is True


class TestWriteToolExecution:
    """Test write tool execution."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create executor with read/write tools."""
        policy = FileSystemPolicy(
            allowed_roots=[str(tmp_path)],
            allow_write=True,
            writable_roots=[str(tmp_path)]
        )
        read_tools = FileSystemTools(policy)
        write_tools = FileSystemWriteTools(policy)
        return ToolExecutor(read_tools=read_tools, write_tools=write_tools)

    def test_execute_write_file(self, tmp_path, executor):
        """Can execute write_file."""
        test_file = tmp_path / "new.txt"

        result = executor.execute("write_file", {
            "path": str(test_file),
            "content": "New content"
        })

        assert result["success"] is True
        assert test_file.read_text(encoding="utf-8") == "New content"

    def test_execute_delete_file(self, tmp_path, executor):
        """Can execute delete_file."""
        test_file = tmp_path / "to_delete.txt"
        test_file.write_text("delete me", encoding="utf-8")

        result = executor.execute("delete_file", {"path": str(test_file)})

        assert result["success"] is True
        assert not test_file.exists()

    def test_execute_create_directory(self, tmp_path, executor):
        """Can execute create_directory."""
        new_dir = tmp_path / "new_dir"

        result = executor.execute("create_directory", {"path": str(new_dir)})

        assert result["success"] is True
        assert new_dir.is_dir()


class TestWriteToolsDisabled:
    """Test behavior when write tools not configured."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create read-only executor."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        return ToolExecutor(read_tools=FileSystemTools(policy))

    def test_write_file_disabled(self, tmp_path, executor):
        """write_file fails when write tools not configured."""
        result = executor.execute("write_file", {
            "path": str(tmp_path / "file.txt"),
            "content": "content"
        })

        assert result["success"] is False
        assert "not enabled" in result["error"]

    def test_delete_file_disabled(self, tmp_path, executor):
        """delete_file fails when write tools not configured."""
        result = executor.execute("delete_file", {
            "path": str(tmp_path / "file.txt")
        })

        assert result["success"] is False
        assert "not enabled" in result["error"]


class TestErrorHandling:
    """Test error handling in executor."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create read-only executor."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        return ToolExecutor(read_tools=FileSystemTools(policy))

    def test_unknown_tool(self, executor):
        """Returns error for unknown tool."""
        result = executor.execute("unknown_tool", {})

        assert result["success"] is False
        assert "Unknown tool" in result["error"]
        assert result["metadata"]["tool"] == "unknown_tool"

    def test_missing_required_argument(self, executor):
        """Handles missing required arguments."""
        result = executor.execute("read_file", {})  # Missing 'path'

        assert result["success"] is False
        assert "Invalid arguments" in result["error"] or "path" in result["error"].lower()


class TestHelperMethods:
    """Test helper methods."""

    def test_is_write_enabled_false(self, tmp_path):
        """is_write_enabled returns False without write_tools."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        executor = ToolExecutor(read_tools=FileSystemTools(policy))

        assert executor.is_write_enabled() is False

    def test_is_write_enabled_true(self, tmp_path):
        """is_write_enabled returns True with write_tools."""
        policy = FileSystemPolicy(
            allowed_roots=[str(tmp_path)],
            allow_write=True,
            writable_roots=[str(tmp_path)]
        )
        executor = ToolExecutor(
            read_tools=FileSystemTools(policy),
            write_tools=FileSystemWriteTools(policy)
        )

        assert executor.is_write_enabled() is True

    def test_get_available_tools_read_only(self, tmp_path):
        """get_available_tools returns read tools only."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        executor = ToolExecutor(read_tools=FileSystemTools(policy))

        tools = executor.get_available_tools()

        assert len(tools) == 4
        assert "read_file" in tools
        assert "write_file" not in tools

    def test_get_available_tools_with_write(self, tmp_path):
        """get_available_tools includes write tools."""
        policy = FileSystemPolicy(
            allowed_roots=[str(tmp_path)],
            allow_write=True,
            writable_roots=[str(tmp_path)]
        )
        executor = ToolExecutor(
            read_tools=FileSystemTools(policy),
            write_tools=FileSystemWriteTools(policy)
        )

        tools = executor.get_available_tools()

        assert len(tools) == 7
        assert "write_file" in tools


class TestBatchExecution:
    """Test batch execution."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create read-only executor."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        return ToolExecutor(read_tools=FileSystemTools(policy))

    def test_execute_batch(self, tmp_path, executor):
        """Can execute multiple calls in batch."""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_text("content1", encoding="utf-8")
        file2.write_text("content2", encoding="utf-8")

        calls = [
            ("read_file", {"path": str(file1)}),
            ("read_file", {"path": str(file2)})
        ]

        results = executor.execute_batch(calls)

        assert len(results) == 2
        assert results[0]["success"] is True
        assert results[0]["data"]["content"] == "content1"
        assert results[1]["success"] is True
        assert results[1]["data"]["content"] == "content2"

    def test_batch_with_errors(self, tmp_path, executor):
        """Batch continues after individual errors."""
        file1 = tmp_path / "exists.txt"
        file1.write_text("exists", encoding="utf-8")

        calls = [
            ("read_file", {"path": str(tmp_path / "missing.txt")}),
            ("read_file", {"path": str(file1)})
        ]

        results = executor.execute_batch(calls)

        assert len(results) == 2
        assert results[0]["success"] is False  # Missing file
        assert results[1]["success"] is True   # Existing file


class TestArgumentValidation:
    """Test argument validation."""

    @pytest.fixture
    def executor(self, tmp_path):
        """Create read-only executor."""
        policy = FileSystemPolicy(allowed_roots=[str(tmp_path)])
        return ToolExecutor(read_tools=FileSystemTools(policy))

    def test_validate_valid_arguments(self, executor):
        """Validates correct arguments."""
        is_valid, error = executor.validate_arguments("read_file", {"path": "/file.txt"})

        assert is_valid is True
        assert error is None

    def test_validate_missing_required(self, executor):
        """Detects missing required argument."""
        is_valid, error = executor.validate_arguments("read_file", {})

        assert is_valid is False
        assert "path" in error

    def test_validate_unknown_tool(self, executor):
        """Detects unknown tool."""
        is_valid, error = executor.validate_arguments("unknown", {})

        assert is_valid is False
        assert "Unknown tool" in error

    def test_validate_write_disabled(self, executor):
        """Detects write tool when disabled."""
        is_valid, error = executor.validate_arguments("write_file", {
            "path": "/file.txt",
            "content": "data"
        })

        assert is_valid is False
        assert "not enabled" in error

    def test_validate_wrong_type(self, executor):
        """Detects wrong argument type."""
        is_valid, error = executor.validate_arguments("read_file", {
            "path": "/file.txt",
            "start_line": "not an integer"
        })

        assert is_valid is False
        assert "type" in error.lower()


class TestExecutorIntegration:
    """Integration tests for executor."""

    def test_full_workflow(self, tmp_path):
        """Tests complete read/write/read workflow."""
        policy = FileSystemPolicy(
            allowed_roots=[str(tmp_path)],
            allow_write=True,
            writable_roots=[str(tmp_path)]
        )
        executor = ToolExecutor(
            read_tools=FileSystemTools(policy),
            write_tools=FileSystemWriteTools(policy)
        )

        # Create directory
        result = executor.execute("create_directory", {
            "path": str(tmp_path / "subdir")
        })
        assert result["success"] is True

        # Write file
        result = executor.execute("write_file", {
            "path": str(tmp_path / "subdir" / "file.txt"),
            "content": "test content",
            "create_dirs": True
        })
        assert result["success"] is True

        # Read file
        result = executor.execute("read_file", {
            "path": str(tmp_path / "subdir" / "file.txt")
        })
        assert result["success"] is True
        assert result["data"]["content"] == "test content"

        # List directory
        result = executor.execute("list_directory", {
            "path": str(tmp_path / "subdir")
        })
        assert result["success"] is True
        assert len(result["data"]["entries"]) == 1

        # Delete file
        result = executor.execute("delete_file", {
            "path": str(tmp_path / "subdir" / "file.txt")
        })
        assert result["success"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
