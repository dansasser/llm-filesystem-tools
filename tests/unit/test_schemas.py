"""
Unit tests for ToolSchemaGenerator.

Tests cover:
- OpenAI format schema generation
- Anthropic format schema generation
- Ollama format schema generation
- Tool inclusion/exclusion based on write flag
"""
import sys
import pytest
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from llm_fs_tools import ToolSchemaGenerator


class TestOpenAIFormat:
    """Test OpenAI function calling format."""

    def test_read_only_tools(self):
        """Returns only read tools when include_write=False."""
        tools = ToolSchemaGenerator.get_openai_format(include_write=False)

        assert len(tools) == 4
        names = [t["function"]["name"] for t in tools]
        assert "read_file" in names
        assert "list_directory" in names
        assert "get_directory_tree" in names
        assert "search_codebase" in names

        # Should not include write tools
        assert "write_file" not in names
        assert "delete_file" not in names
        assert "create_directory" not in names

    def test_includes_write_tools(self):
        """Includes write tools when include_write=True."""
        tools = ToolSchemaGenerator.get_openai_format(include_write=True)

        assert len(tools) == 7
        names = [t["function"]["name"] for t in tools]
        assert "write_file" in names
        assert "delete_file" in names
        assert "create_directory" in names

    def test_openai_format_structure(self):
        """Verifies correct OpenAI format structure."""
        tools = ToolSchemaGenerator.get_openai_format()

        for tool in tools:
            assert tool["type"] == "function"
            assert "function" in tool
            assert "name" in tool["function"]
            assert "description" in tool["function"]
            assert "parameters" in tool["function"]

            params = tool["function"]["parameters"]
            assert params["type"] == "object"
            assert "properties" in params
            assert "required" in params

    def test_read_file_schema(self):
        """Verifies read_file schema is correct."""
        tools = ToolSchemaGenerator.get_openai_format()
        read_file = next(t for t in tools if t["function"]["name"] == "read_file")

        params = read_file["function"]["parameters"]
        assert "path" in params["properties"]
        assert "start_line" in params["properties"]
        assert "end_line" in params["properties"]
        assert params["required"] == ["path"]

    def test_search_codebase_schema(self):
        """Verifies search_codebase schema is correct."""
        tools = ToolSchemaGenerator.get_openai_format()
        search = next(t for t in tools if t["function"]["name"] == "search_codebase")

        params = search["function"]["parameters"]
        assert "pattern" in params["properties"]
        assert "path" in params["properties"]
        assert "file_pattern" in params["properties"]
        assert "case_sensitive" in params["properties"]
        assert "max_results" in params["properties"]
        assert set(params["required"]) == {"pattern", "path"}

    def test_write_file_schema(self):
        """Verifies write_file schema is correct."""
        tools = ToolSchemaGenerator.get_openai_format(include_write=True)
        write_file = next(t for t in tools if t["function"]["name"] == "write_file")

        params = write_file["function"]["parameters"]
        assert "path" in params["properties"]
        assert "content" in params["properties"]
        assert "encoding" in params["properties"]
        assert "create_dirs" in params["properties"]
        assert set(params["required"]) == {"path", "content"}


class TestAnthropicFormat:
    """Test Anthropic tool format."""

    def test_anthropic_format_structure(self):
        """Verifies correct Anthropic format structure."""
        tools = ToolSchemaGenerator.get_anthropic_format()

        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            # Should NOT have "type" or "function" wrapper
            assert "type" not in tool
            assert "function" not in tool

    def test_anthropic_read_only(self):
        """Returns only read tools by default."""
        tools = ToolSchemaGenerator.get_anthropic_format(include_write=False)

        assert len(tools) == 4
        names = [t["name"] for t in tools]
        assert "read_file" in names
        assert "write_file" not in names

    def test_anthropic_with_write(self):
        """Includes write tools when requested."""
        tools = ToolSchemaGenerator.get_anthropic_format(include_write=True)

        assert len(tools) == 7
        names = [t["name"] for t in tools]
        assert "write_file" in names

    def test_input_schema_matches_openai_params(self):
        """input_schema should match OpenAI parameters."""
        openai_tools = ToolSchemaGenerator.get_openai_format()
        anthropic_tools = ToolSchemaGenerator.get_anthropic_format()

        for openai_tool, anthropic_tool in zip(openai_tools, anthropic_tools):
            assert openai_tool["function"]["parameters"] == anthropic_tool["input_schema"]


class TestOllamaFormat:
    """Test Ollama format."""

    def test_ollama_same_as_openai(self):
        """Ollama format should match OpenAI format."""
        openai_tools = ToolSchemaGenerator.get_openai_format()
        ollama_tools = ToolSchemaGenerator.get_ollama_format()

        assert openai_tools == ollama_tools

    def test_ollama_with_write(self):
        """Write tools work in Ollama format."""
        openai_tools = ToolSchemaGenerator.get_openai_format(include_write=True)
        ollama_tools = ToolSchemaGenerator.get_ollama_format(include_write=True)

        assert openai_tools == ollama_tools


class TestToolNames:
    """Test get_tool_names helper."""

    def test_read_tool_names(self):
        """Returns read tool names by default."""
        names = ToolSchemaGenerator.get_tool_names()

        assert names == ["read_file", "list_directory", "get_directory_tree", "search_codebase"]

    def test_write_tool_names(self):
        """Includes write tool names when requested."""
        names = ToolSchemaGenerator.get_tool_names(include_write=True)

        assert len(names) == 7
        assert "write_file" in names
        assert "delete_file" in names
        assert "create_directory" in names


class TestGetToolSchema:
    """Test get_tool_schema helper."""

    def test_get_existing_tool(self):
        """Returns schema for existing tool."""
        schema = ToolSchemaGenerator.get_tool_schema("read_file")

        assert schema is not None
        assert schema["function"]["name"] == "read_file"

    def test_get_write_tool(self):
        """Returns schema for write tool."""
        schema = ToolSchemaGenerator.get_tool_schema("write_file")

        assert schema is not None
        assert schema["function"]["name"] == "write_file"

    def test_get_nonexistent_tool(self):
        """Returns None for nonexistent tool."""
        schema = ToolSchemaGenerator.get_tool_schema("nonexistent_tool")

        assert schema is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
