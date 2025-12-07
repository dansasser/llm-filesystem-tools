"""
Tool schema generation for LLMs.

Provides tool definitions in multiple formats:
- OpenAI function calling format
- Anthropic tool format
- Ollama format (OpenAI-compatible)

These schemas can be passed directly to LLM APIs to enable
function calling/tool use with the filesystem tools.
"""
from typing import Optional


class ToolSchemaGenerator:
    """
    Generates tool definitions for different LLM providers.

    Provides static methods to generate tool schemas in the format
    expected by various LLM APIs. Schemas include all read tools
    and optionally write tools.
    """

    @staticmethod
    def get_openai_format(include_write: bool = False) -> list[dict]:
        """
        Get tool definitions in OpenAI function calling format.

        Args:
            include_write: Whether to include write operation tools

        Returns:
            List of tool definitions in OpenAI format
        """
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read file content with optional line range. Returns the file content as a string.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Absolute or relative path to the file to read"
                            },
                            "start_line": {
                                "type": "integer",
                                "description": "First line to read (1-indexed, inclusive). If omitted, reads from beginning."
                            },
                            "end_line": {
                                "type": "integer",
                                "description": "Last line to read (1-indexed, inclusive). If omitted, reads to end."
                            }
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "list_directory",
                    "description": "List the contents of a directory. Returns files and subdirectories with their types.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the directory to list"
                            },
                            "include_hidden": {
                                "type": "boolean",
                                "description": "Whether to include hidden files (starting with .)",
                                "default": False
                            }
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_directory_tree",
                    "description": "Get hierarchical directory structure as a tree. Useful for understanding project layout.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Root path to start the tree from"
                            },
                            "max_depth": {
                                "type": "integer",
                                "description": "Maximum depth to traverse (default: 3)",
                                "default": 3
                            },
                            "include_hidden": {
                                "type": "boolean",
                                "description": "Whether to include hidden files and directories",
                                "default": False
                            }
                        },
                        "required": ["path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_codebase",
                    "description": "Search for a regex pattern across files in a directory. Returns matching lines with context.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {
                                "type": "string",
                                "description": "Regular expression pattern to search for"
                            },
                            "path": {
                                "type": "string",
                                "description": "Directory to search in"
                            },
                            "file_pattern": {
                                "type": "string",
                                "description": "Glob pattern to filter files (e.g., '*.py', '*.js')",
                                "default": "*"
                            },
                            "case_sensitive": {
                                "type": "boolean",
                                "description": "Whether search is case-sensitive",
                                "default": False
                            },
                            "max_results": {
                                "type": "integer",
                                "description": "Maximum number of results to return",
                                "default": 100
                            }
                        },
                        "required": ["pattern", "path"]
                    }
                }
            }
        ]

        # Add write tools if enabled
        if include_write:
            tools.extend([
                {
                    "type": "function",
                    "function": {
                        "name": "write_file",
                        "description": "Write content to a file. Creates the file if it doesn't exist, or overwrites if it does.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path to the file to write"
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Content to write to the file"
                                },
                                "encoding": {
                                    "type": "string",
                                    "description": "Text encoding to use",
                                    "default": "utf-8"
                                },
                                "create_dirs": {
                                    "type": "boolean",
                                    "description": "Create parent directories if they don't exist",
                                    "default": False
                                }
                            },
                            "required": ["path", "content"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "delete_file",
                        "description": "Delete a file. Only deletes regular files, not directories.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path to the file to delete"
                                }
                            },
                            "required": ["path"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "create_directory",
                        "description": "Create a new directory.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path of the directory to create"
                                },
                                "parents": {
                                    "type": "boolean",
                                    "description": "Create parent directories as needed",
                                    "default": False
                                }
                            },
                            "required": ["path"]
                        }
                    }
                }
            ])

        return tools

    @staticmethod
    def get_anthropic_format(include_write: bool = False) -> list[dict]:
        """
        Get tool definitions in Anthropic tool format.

        Anthropic uses a slightly different format than OpenAI, with
        'input_schema' instead of nested 'parameters'.

        Args:
            include_write: Whether to include write operation tools

        Returns:
            List of tool definitions in Anthropic format
        """
        openai_tools = ToolSchemaGenerator.get_openai_format(include_write)

        return [
            {
                "name": tool["function"]["name"],
                "description": tool["function"]["description"],
                "input_schema": tool["function"]["parameters"]
            }
            for tool in openai_tools
        ]

    @staticmethod
    def get_ollama_format(include_write: bool = False) -> list[dict]:
        """
        Get tool definitions in Ollama format.

        Ollama uses OpenAI-compatible format for function calling.

        Args:
            include_write: Whether to include write operation tools

        Returns:
            List of tool definitions in Ollama format
        """
        return ToolSchemaGenerator.get_openai_format(include_write)

    @staticmethod
    def get_tool_names(include_write: bool = False) -> list[str]:
        """
        Get list of available tool names.

        Args:
            include_write: Whether to include write operation tool names

        Returns:
            List of tool names
        """
        names = ["read_file", "list_directory", "get_directory_tree", "search_codebase"]
        if include_write:
            names.extend(["write_file", "delete_file", "create_directory"])
        return names

    @staticmethod
    def get_tool_schema(tool_name: str) -> Optional[dict]:
        """
        Get schema for a specific tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Tool schema in OpenAI format, or None if not found
        """
        # Get all tools including write
        all_tools = ToolSchemaGenerator.get_openai_format(include_write=True)

        for tool in all_tools:
            if tool["function"]["name"] == tool_name:
                return tool

        return None
