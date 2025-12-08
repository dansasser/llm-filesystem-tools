# LLM Filesystem Tools

**Secure filesystem access for Large Language Models with governance-first design.**

[![PyPI version](https://badge.fury.io/py/llm-fs-tools.svg)](https://badge.fury.io/py/llm-fs-tools)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Stop reinventing filesystem tools for every LLM project. `llm-fs-tools` provides production-ready, secure file operations that work with any LLM supporting function calling - Ollama, OpenAI, Anthropic, and more.

## The Problem

You want your AI assistant to analyze code, search files, or explore directories. You have three bad options:

1. **Inject everything into the prompt** - Wastes tokens, hits context limits, can't scale
2. **Use heavy frameworks** - LangChain/LlamaIndex lock you into their ecosystem
3. **Roll your own** - Reinvent security, path validation, and tool schemas every time

## The Solution

```bash
pip install llm-fs-tools
```

```python
from llm_fs_tools import FileSystemTools, SecurityPolicy

# Define security boundaries
policy = SecurityPolicy(
    allowed_roots=["./my-project"],
    max_file_size_mb=5,
    blocked_patterns=["*.env", ".git/*"]
)

# Initialize tools
fs_tools = FileSystemTools(policy)

# Use with any LLM (Ollama example)
import ollama

response = ollama.chat(
    model='qwen2.5-coder',
    messages=[{'role': 'user', 'content': 'Analyze the codebase structure'}],
    tools=fs_tools.get_tool_definitions()  # Auto-generates schemas
)

# Execute tool calls
for tool_call in response.message.tool_calls:
    result = fs_tools.execute(
        tool_call.function.name,
        tool_call.function.arguments
    )
```

**That's it.** Your model can now safely explore filesystems.

---

## Features

### 🔒 Security First
- **Path traversal protection** - Validates all paths stay within allowed roots
- **Configurable boundaries** - Whitelist directories, block patterns
- **Automatic filtering** - Excludes `.env`, `.git`, `node_modules` by default
- **Size limits** - Prevents reading massive files that blow up context

### 🛠️ Rich Tool Set
- **`get_directory_tree`** - Hierarchical structure with configurable depth
- **`read_file`** - Read with line numbers and range support
- **`search_codebase`** - Grep-style regex search across files
- **`list_directory`** - Fast flat listings

### 🎯 Zero Lock-In
- **Framework-agnostic** - Works with raw API calls, not just frameworks
- **Provider-agnostic** - Same tools work with Ollama, OpenAI, Anthropic
- **Minimal dependencies** - No heavy frameworks required
- **Standard schemas** - Uses OpenAI function calling format

### 🚀 Production Ready
- **Comprehensive error handling** - Graceful failures with detailed messages
- **Type hints throughout** - Full mypy compliance
- **Extensive logging** - Debug tool execution and security checks
- **Tested** - 80%+ coverage

---

## Quick Examples

### Ollama (Local Models)

```python
import ollama
from llm_fs_tools import FileSystemTools, SecurityPolicy

policy = SecurityPolicy(allowed_roots=["./src"])
fs_tools = FileSystemTools(policy)

response = ollama.chat(
    model='codellama',
    messages=[{
        'role': 'user',
        'content': 'Find all database queries in this codebase'
    }],
    tools=fs_tools.get_tool_definitions()
)

# Handle tool calls in a loop
messages = [{'role': 'user', 'content': 'Find all database queries'}]
while response.message.tool_calls:
    messages.append(response.message)
    
    for tool_call in response.message.tool_calls:
        result = fs_tools.execute(
            tool_call.function.name,
            tool_call.function.arguments
        )
        messages.append({
            'role': 'tool',
            'content': json.dumps(result),
            'tool_call_id': tool_call.id
        })
    
    response = ollama.chat(model='codellama', messages=messages)

print(response.message.content)
```

### OpenAI

```python
from openai import OpenAI
from llm_fs_tools import FileSystemTools, SecurityPolicy

client = OpenAI()
policy = SecurityPolicy(allowed_roots=["./"])
fs_tools = FileSystemTools(policy)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Summarize the README"}],
    tools=fs_tools.get_tool_definitions(format="openai")
)

# Execute tool calls
for tool_call in response.choices[0].message.tool_calls:
    result = fs_tools.execute(
        tool_call.function.name,
        json.loads(tool_call.function.arguments)
    )
```

### Anthropic Claude

```python
import anthropic
from llm_fs_tools import FileSystemTools, SecurityPolicy

client = anthropic.Anthropic()
policy = SecurityPolicy(allowed_roots=["./docs"])
fs_tools = FileSystemTools(policy)

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    messages=[{"role": "user", "content": "What's in the docs?"}],
    tools=fs_tools.get_tool_definitions(format="anthropic")
)

# Handle tool use
for block in response.content:
    if block.type == "tool_use":
        result = fs_tools.execute(block.name, block.input)
```

---

## Security Model

### Path Validation

Every file operation validates paths through the security policy:

```python
policy = SecurityPolicy(
    allowed_roots=[
        "/home/user/projects",
        "/home/user/documents"
    ],
    blocked_patterns=[
        "*.env",           # Environment files
        "*.key",           # Key files
        ".git/*",          # Git internals
        "node_modules/*",  # Dependencies
        "__pycache__/*"    # Python cache
    ],
    blocked_extensions=[
        ".pem",
        ".secret"
    ],
    max_file_size_mb=10
)
```

**Validation Process:**
1. Resolve symlinks and relative paths
2. Check if resolved path is within `allowed_roots`
3. Match against `blocked_patterns` and `blocked_extensions`
4. Verify file size is under `max_file_size_mb`

**Security guarantees:**
- ❌ No path traversal attacks (`../../../etc/passwd`)
- ❌ No symlink escapes
- ❌ No sensitive file access
- ✅ Explicit allowlist model

### Error Handling

Security violations return structured errors, never raising exceptions to the LLM:

```python
{
    "success": False,
    "error": "Access denied: Path outside allowed roots",
    "data": None,
    "metadata": {
        "tool": "read_file",
        "attempted_path": "/etc/passwd",
        "violation_type": "outside_allowed_roots"
    }
}
```

---

## Tool Reference

### `get_directory_tree`

Returns hierarchical directory structure.

**Parameters:**
- `path` (str, required) - Directory to analyze
- `max_depth` (int, default=3) - Maximum recursion depth
- `include_hidden` (bool, default=False) - Include hidden files

**Example Output:**
```json
{
    "success": true,
    "data": {
        "name": "src",
        "type": "directory",
        "children": [
            {
                "name": "main.py",
                "type": "file",
                "size": 1024
            },
            {
                "name": "utils",
                "type": "directory",
                "children": [...]
            }
        ]
    }
}
```

### `read_file`

Reads file content with optional line ranges.

**Parameters:**
- `path` (str, required) - File to read
- `start_line` (int, optional) - First line to read (1-indexed)
- `end_line` (int, optional) - Last line to read (inclusive)

**Example:**
```python
# Read entire file
fs_tools.execute("read_file", {"path": "./main.py"})

# Read lines 10-20
fs_tools.execute("read_file", {
    "path": "./main.py",
    "start_line": 10,
    "end_line": 20
})
```

### `search_codebase`

Grep-style search with regex support.

**Parameters:**
- `pattern` (str, required) - Search pattern (regex)
- `path` (str, required) - Directory to search
- `file_pattern` (str, default="*") - File glob filter
- `case_sensitive` (bool, default=False) - Case sensitivity
- `max_results` (int, default=100) - Result limit

**Example:**
```python
# Find all TODO comments in Python files
fs_tools.execute("search_codebase", {
    "pattern": r"TODO:.*",
    "path": "./src",
    "file_pattern": "*.py"
})
```

**Output:**
```json
{
    "success": true,
    "data": {
        "matches": [
            {
                "file": "./src/main.py",
                "line": 42,
                "content": "# TODO: Refactor this function",
                "match": "TODO: Refactor this function"
            }
        ],
        "total_matches": 1,
        "truncated": false
    }
}
```

### `list_directory`

Fast flat directory listing.

**Parameters:**
- `path` (str, required) - Directory to list
- `include_hidden` (bool, default=False) - Include hidden files

---

## Configuration

### Basic Setup

```python
from llm_fs_tools import FileSystemTools, SecurityPolicy

policy = SecurityPolicy(
    allowed_roots=["./project"],
)

fs_tools = FileSystemTools(policy)
```

### Advanced Configuration

```python
from pathlib import Path

policy = SecurityPolicy(
    # Multiple allowed directories
    allowed_roots=[
        "./src",
        "./docs",
        str(Path.home() / "projects")
    ],
    
    # File size limits
    max_file_size_mb=5,
    
    # Block sensitive patterns
    blocked_patterns=[
        "*.env",
        "*.key",
        "*.pem",
        ".git/*",
        "node_modules/*",
        "__pycache__/*",
        "*.pyc",
        ".venv/*"
    ],
    
    # Block by extension
    blocked_extensions=[
        ".secret",
        ".private"
    ],
    
    # Custom validation
    custom_validator=lambda path: not path.name.startswith("temp_")
)

fs_tools = FileSystemTools(policy)
```

### Configuration File

```yaml
# llm-fs-config.yaml
security:
  allowed_roots:
    - ./src
    - ./docs
  max_file_size_mb: 10
  blocked_patterns:
    - "*.env"
    - ".git/*"
```

```python
import yaml
from llm_fs_tools import SecurityPolicy, FileSystemTools

with open("llm-fs-config.yaml") as f:
    config = yaml.safe_load(f)

policy = SecurityPolicy(**config["security"])
fs_tools = FileSystemTools(policy)
```

---

## Architecture

### Design Principles

1. **Governance Over Scale** - Security boundaries define capability, not model size
2. **Explicit Over Implicit** - Allowlists, not denylists
3. **Simple Over Complex** - Minimal API surface, zero magic
4. **Portable Over Coupled** - Works everywhere, depends on nothing

### Component Overview

```
┌─────────────────────────────────────────┐
│           Your Application               │
│  (Ollama/OpenAI/Anthropic/etc)          │
└─────────────┬───────────────────────────┘
              │
              ├─ get_tool_definitions()
              │  (Returns JSON schemas)
              │
              └─ execute(name, args)
                 (Runs tool, returns result)
                        │
        ┌───────────────┴────────────────┐
        │      FileSystemTools            │
        │  ┌──────────────────────────┐  │
        │  │   Security Policy        │  │
        │  │  - Path validation       │  │
        │  │  - Size limits          │  │
        │  │  - Pattern blocking     │  │
        │  └──────────────────────────┘  │
        │  ┌──────────────────────────┐  │
        │  │   Tool Implementations   │  │
        │  │  - get_directory_tree    │  │
        │  │  - read_file            │  │
        │  │  - search_codebase      │  │
        │  │  - list_directory       │  │
        │  └──────────────────────────┘  │
        └─────────────────────────────────┘
```

---

## Use Cases

### AI Coding Assistants

```python
# Let Claude explore and refactor your codebase
policy = SecurityPolicy(allowed_roots=["./src"])
fs_tools = FileSystemTools(policy)

response = claude.chat(
    messages=[{
        'role': 'user',
        'content': 'Refactor the authentication module for better testability'
    }],
    tools=fs_tools.get_tool_definitions()
)
```

### Automated Code Reviews

```python
# LLM reviews your PR changes
policy = SecurityPolicy(
    allowed_roots=["./"],
    blocked_patterns=["*.env", "node_modules/*"]
)

fs_tools = FileSystemTools(policy)

response = gpt4.chat(
    messages=[{
        'role': 'user',
        'content': 'Review the changes in src/ for security issues and best practices'
    }],
    tools=fs_tools.get_tool_definitions()
)
```

### Documentation Generation

```python
# Generate docs from codebase structure
policy = SecurityPolicy(allowed_roots=["./src", "./docs"])
fs_tools = FileSystemTools(policy)

response = ollama.chat(
    model='codellama',
    messages=[{
        'role': 'user',
        'content': 'Generate API documentation from the source files'
    }],
    tools=fs_tools.get_tool_definitions()
)
```

### Dependency Analysis

```python
# Find all imports and dependencies
fs_tools.execute("search_codebase", {
    "pattern": r"^import |^from .* import",
    "path": "./src",
    "file_pattern": "*.py"
})
```

---

## Comparison

| Feature | llm-filesystem-tools | LangChain | MCP Servers | Roll Your Own |
|---------|---------------------|-----------|-------------|---------------|
| **Installation** | `pip install` | `pip install langchain` | Server setup + client | ❌ N/A |
| **Dependencies** | Minimal | 50+ packages | MCP protocol | ❌ You maintain |
| **Security Model** | Built-in policy engine | Manual | Per-server | ❌ You build |
| **Provider Support** | All (OpenAI/Anthropic/Ollama) | LangChain models only | MCP clients only | ✅ Up to you |
| **Framework Lock-in** | ❌ None | ✅ LangChain ecosystem | ✅ MCP protocol | ❌ None |
| **Path Validation** | ✅ Automatic | ❌ Manual | Varies | ❌ You build |
| **Learning Curve** | 5 minutes | Days | Hours | ❌ Weeks |

---

## Roadmap

### v0.1.0 (Current)
- ✅ Core filesystem tools
- ✅ Security policy engine
- ✅ Multi-provider schemas
- ✅ Path validation

### v0.2.0 (Next)
- [ ] Caching layer for repeated reads
- [ ] File watching/change detection
- [ ] Batch operations
- [ ] Performance optimizations

### v0.3.0
- [ ] Git integration tools
- [ ] Diff/patch operations
- [ ] Binary file support
- [ ] Archive handling (zip, tar)

### v1.0.0
- [ ] Stable API
- [ ] Full test coverage
- [ ] Production hardening
- [ ] Performance benchmarks

---

## Contributing

We welcome contributions! This project follows the governance-first philosophy: intelligence emerges from coordination, not complexity.

### Development Setup

```bash
# Clone the repo
git clone https://github.com/dansasser/llm-filesystem-tools.git
cd llm-filesystem-tools

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
mypy llm_fs_tools
```

### Guidelines

- **Security first** - All PRs must maintain security guarantees
- **Test coverage** - New features need tests
- **Type hints** - Full typing required
- **Documentation** - Update docs for API changes

### Areas for Contribution

- 🔧 New tool implementations
- 🛡️ Enhanced security features
- 📚 Documentation improvements
- 🧪 Test coverage expansion
- 🐛 Bug fixes

---

## FAQ

**Q: Does this work with LangChain/LlamaIndex?**  
A: Yes! You can wrap these tools in LangChain/LlamaIndex tool interfaces, but you don't need those frameworks to use this package.

**Q: Can I use this in production?**  
A: Yes, but audit the security policy for your use case. The default blocked patterns are a starting point, not a complete security solution.

**Q: What about write operations?**  
A: Currently read-only by design. Write operations may come in v0.3.0 with additional safeguards.

**Q: Does this work on Windows?**  
A: Yes! Path handling is cross-platform using `pathlib`.

**Q: Can I use this with streaming responses?**  
A: Yes! Tool calls work with both streaming and non-streaming LLM responses.

**Q: What's the performance impact?**  
A: Minimal. Tool execution is typically <100ms. Directory trees are cached per call.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Credits

Created by [Dan Sasser](https://dansasser.me) as part of the [SIM-ONE Framework](https://github.com/dansasser/SIM-ONE) - governance-first AI architecture.

**Related Projects:**
- [ollama-prompt](https://github.com/dansasser/ollama-prompt) - Command-line tool using llm-filesystem-tools
- [SIM-ONE](https://github.com/dansasser/SIM-ONE) - Comprehensive AI governance system

---

## Support

- **Issues:** [GitHub Issues](https://github.com/dansasser/llm-filesystem-tools/issues)
- **Discussions:** [GitHub Discussions](https://github.com/dansasser/llm-filesystem-tools/discussions)
- **Email:** [Contact](mailto:dan@gorombo.com)

---

**Star this repo if it's useful! ⭐**
