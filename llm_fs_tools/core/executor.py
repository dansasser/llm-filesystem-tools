"""
Tool execution engine.

Provides routing and execution of tool calls from LLM responses.
Handles parameter validation and error handling for seamless
integration with function calling workflows.
"""
from typing import Optional

from .tools import FileSystemTools
from .write_tools import FileSystemWriteTools


class ToolExecutor:
    """
    Routes and executes tool calls.

    Provides a unified interface for executing filesystem tools,
    routing calls to the appropriate handler based on tool name.

    Example:
        executor = ToolExecutor(
            read_tools=FileSystemTools(policy),
            write_tools=FileSystemWriteTools(policy)
        )

        # Execute a tool call from LLM response
        result = executor.execute("read_file", {"path": "/file.txt"})
    """

    # Read-only tools
    READ_TOOLS = frozenset([
        "read_file",
        "list_directory",
        "get_directory_tree",
        "search_codebase"
    ])

    # Write tools
    WRITE_TOOLS = frozenset([
        "write_file",
        "delete_file",
        "create_directory"
    ])

    def __init__(
        self,
        read_tools: FileSystemTools,
        write_tools: Optional[FileSystemWriteTools] = None
    ):
        """
        Initialize tool executor.

        Args:
            read_tools: FileSystemTools instance for read operations
            write_tools: Optional FileSystemWriteTools for write operations
        """
        self.read_tools = read_tools
        self.write_tools = write_tools

    def execute(self, tool_name: str, arguments: dict) -> dict:
        """
        Execute a tool call.

        Routes the call to the appropriate tool handler and returns
        the result in standardized format.

        Args:
            tool_name: Name of the tool to execute
            arguments: Dictionary of arguments to pass to the tool

        Returns:
            Standardized response dict:
            {
                "success": bool,
                "data": {...} or None,
                "error": str or None,
                "metadata": {"tool": tool_name, ...}
            }
        """
        try:
            # Route to read tools
            if tool_name in self.READ_TOOLS:
                return self._execute_read_tool(tool_name, arguments)

            # Route to write tools
            elif tool_name in self.WRITE_TOOLS:
                return self._execute_write_tool(tool_name, arguments)

            # Unknown tool
            else:
                return {
                    "success": False,
                    "error": f"Unknown tool: {tool_name}",
                    "metadata": {"tool": tool_name}
                }

        except TypeError as e:
            # Handle missing/invalid arguments
            return {
                "success": False,
                "error": f"Invalid arguments: {str(e)}",
                "metadata": {"tool": tool_name, "arguments": arguments}
            }

        except Exception as e:
            # Handle unexpected errors
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "metadata": {"tool": tool_name}
            }

    def _execute_read_tool(self, tool_name: str, arguments: dict) -> dict:
        """Execute a read tool."""
        method = getattr(self.read_tools, tool_name)
        return method(**arguments)

    def _execute_write_tool(self, tool_name: str, arguments: dict) -> dict:
        """Execute a write tool."""
        if not self.write_tools:
            return {
                "success": False,
                "error": "Write operations not enabled",
                "metadata": {"tool": tool_name}
            }

        method = getattr(self.write_tools, tool_name)
        return method(**arguments)

    def is_write_enabled(self) -> bool:
        """
        Check if write operations are enabled.

        Returns:
            True if write_tools is configured
        """
        return self.write_tools is not None

    def get_available_tools(self) -> list[str]:
        """
        Get list of available tool names.

        Returns:
            List of tool names that can be executed
        """
        tools = list(self.READ_TOOLS)
        if self.write_tools:
            tools.extend(self.WRITE_TOOLS)
        return sorted(tools)

    def execute_batch(
        self,
        calls: list[tuple[str, dict]]
    ) -> list[dict]:
        """
        Execute multiple tool calls in sequence.

        Useful for processing multiple tool calls from a single
        LLM response.

        Args:
            calls: List of (tool_name, arguments) tuples

        Returns:
            List of result dicts in same order as input
        """
        return [
            self.execute(tool_name, arguments)
            for tool_name, arguments in calls
        ]

    def validate_arguments(self, tool_name: str, arguments: dict) -> tuple[bool, Optional[str]]:
        """
        Validate arguments for a tool call without executing.

        Useful for pre-flight validation of LLM-generated tool calls.

        Args:
            tool_name: Name of the tool
            arguments: Arguments to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check tool exists
        all_tools = self.READ_TOOLS | self.WRITE_TOOLS
        if tool_name not in all_tools:
            return False, f"Unknown tool: {tool_name}"

        # Check write tool without write_tools
        if tool_name in self.WRITE_TOOLS and not self.write_tools:
            return False, "Write operations not enabled"

        # Get required parameters from schema
        from .schemas import ToolSchemaGenerator
        schema = ToolSchemaGenerator.get_tool_schema(tool_name)
        if not schema:
            return False, f"No schema found for tool: {tool_name}"

        params = schema["function"]["parameters"]
        required = params.get("required", [])

        # Check required arguments present
        for param in required:
            if param not in arguments:
                return False, f"Missing required argument: {param}"

        # Check argument types (basic validation)
        properties = params.get("properties", {})
        for arg_name, arg_value in arguments.items():
            if arg_name not in properties:
                # Unknown argument - allow for flexibility
                continue

            expected_type = properties[arg_name].get("type")
            if expected_type:
                if not self._check_type(arg_value, expected_type):
                    return False, f"Invalid type for {arg_name}: expected {expected_type}"

        return True, None

    def _check_type(self, value, expected_type: str) -> bool:
        """Check if value matches expected JSON schema type."""
        type_map: dict[str, type | tuple[type, ...]] = {
            "string": str,
            "integer": int,
            "boolean": bool,
            "number": (int, float),
            "array": list,
            "object": dict
        }

        expected = type_map.get(expected_type)
        if expected is None:
            return True  # Unknown type, allow

        return isinstance(value, expected)
