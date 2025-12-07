"""
llm-filesystem-tools: Production-ready filesystem access for LLMs.

Simple, secure, protocol-driven architecture with read and write support.

Example usage:
    from llm_fs_tools import FileSystemPolicy, FileSystemTools

    # Create policy with allowed directories
    policy = FileSystemPolicy(
        allowed_roots=["/path/to/project"],
        max_file_size_mb=5
    )

    # Create tools instance
    tools = FileSystemTools(policy)

    # Read a file
    result = tools.read_file("/path/to/project/file.py")
    if result["success"]:
        print(result["data"]["content"])

    # List directory
    result = tools.list_directory("/path/to/project")

    # Get directory tree
    result = tools.get_directory_tree("/path/to/project", max_depth=3)

    # Search codebase
    result = tools.search_codebase("def main", "/path/to/project", file_pattern="*.py")
"""

from .core.security import FileSystemPolicy, SecurityPolicy
from .core.file_handle import SecureFileHandle, open_secure
from .core.tools import FileSystemTools
from .core.write_tools import FileSystemWriteTools
from .core.schemas import ToolSchemaGenerator
from .core.executor import ToolExecutor
from .utils.audit import AuditLogger, NullAuditLogger, MemoryAuditLogger
from .utils.streaming import StreamingFileReader, ChunkedProcessor
from .exceptions import SecurityError, ValidationError

# Compatibility layer for ollama-prompt integration
from .compat import (
    read_file_secure,
    secure_open as secure_open_compat,
    create_directory_tools,
    safe_read_file,
    DEFAULT_MAX_FILE_BYTES,
)

__version__ = "0.1.0"

__all__ = [
    # Core
    "FileSystemPolicy",
    "SecurityPolicy",
    "SecurityError",
    "ValidationError",

    # File handling
    "SecureFileHandle",
    "open_secure",

    # Tools
    "FileSystemTools",
    "FileSystemWriteTools",

    # Schema & Executor
    "ToolSchemaGenerator",
    "ToolExecutor",

    # Utilities
    "AuditLogger",
    "NullAuditLogger",
    "MemoryAuditLogger",
    "StreamingFileReader",
    "ChunkedProcessor",

    # Compatibility layer (ollama-prompt drop-in replacements)
    "read_file_secure",
    "secure_open_compat",
    "create_directory_tools",
    "safe_read_file",
    "DEFAULT_MAX_FILE_BYTES",
]
