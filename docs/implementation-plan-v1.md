# Implementation Plan: `llm-fs-tools`

## Overview
Standalone Python package providing filesystem access tools for LLMs with built-in security governance. Provider-agnostic, works with Ollama, OpenAI, Anthropic, etc.

---

## Package Structure

```
llm-fs-tools/
├── pyproject.toml
├── README.md
├── LICENSE
├── llm_fs_tools/
│   ├── __init__.py           # Public API exports
│   ├── tools.py              # Tool implementations
│   ├── security.py           # Security policy & validation
│   ├── schemas.py            # Tool definition schemas
│   └── executor.py           # Tool execution engine
├── tests/
│   ├── test_tools.py
│   ├── test_security.py
│   └── fixtures/
└── examples/
    ├── ollama_integration.py
    ├── openai_integration.py
    └── standalone_usage.py
```

---

## Phase 1: Core Package (`llm-fs-tools`)

### 1.1 Security Layer (`security.py`)

```python
class SecurityPolicy:
    """Governs filesystem access boundaries"""
    def __init__(
        self,
        allowed_roots: list[str],
        max_file_size_mb: int = 5,
        blocked_patterns: list[str] = None,
        blocked_extensions: list[str] = None
    )
    
    def validate_path(self, path: str) -> Path:
        """Validates and resolves path within allowed roots"""
        # Check if path within allowed_roots
        # Check against blocked patterns/extensions
        # Raise SecurityError if invalid
    
    def can_read_file(self, path: Path) -> bool:
        """Check if file is readable under policy"""
```

**Default blocked patterns:**
- `*.env`, `*.key`, `*.pem`, `*.secret`
- `.git/*`, `node_modules/*`, `__pycache__/*`

---

### 1.2 Tool Implementations (`tools.py`)

```python
class FileSystemTools:
    def __init__(self, security_policy: SecurityPolicy):
        self.policy = security_policy
    
    def get_directory_tree(
        self,
        path: str,
        max_depth: int = 3,
        include_hidden: bool = False
    ) -> dict:
        """Returns hierarchical directory structure"""
    
    def read_file(
        self,
        path: str,
        start_line: int = None,
        end_line: int = None
    ) -> dict:
        """Reads file content with line numbers"""
    
    def search_codebase(
        self,
        pattern: str,
        path: str,
        file_pattern: str = "*",
        case_sensitive: bool = False,
        max_results: int = 100
    ) -> dict:
        """Grep-style search across files"""
    
    def list_directory(
        self,
        path: str,
        include_hidden: bool = False
    ) -> dict:
        """Lists immediate directory contents"""
```

**Return Format:**
```python
{
    "success": True,
    "data": {...},
    "error": None,
    "metadata": {
        "tool": "read_file",
        "timestamp": "2025-11-08T...",
        "path": "/resolved/path"
    }
}
```

---

### 1.3 Schema Definitions (`schemas.py`)

```python
class ToolSchemaGenerator:
    """Generates tool definitions in various formats"""
    
    @staticmethod
    def get_openai_format() -> list[dict]:
        """OpenAI function calling format"""
    
    @staticmethod
    def get_anthropic_format() -> list[dict]:
        """Anthropic tool format"""
    
    @staticmethod
    def get_ollama_format() -> list[dict]:
        """Ollama tool format (OpenAI-compatible)"""
```

---

### 1.4 Executor (`executor.py`)

```python
class ToolExecutor:
    def __init__(self, tools: FileSystemTools):
        self.tools = tools
    
    def execute(self, tool_name: str, arguments: dict) -> dict:
        """Routes tool call to appropriate method"""
        # Maps tool_name to method
        # Handles errors gracefully
        # Returns standardized response
```

---

### 1.5 Public API (`__init__.py`)

```python
from .tools import FileSystemTools
from .security import SecurityPolicy, SecurityError
from .schemas import ToolSchemaGenerator
from .executor import ToolExecutor

__version__ = "0.1.0"
__all__ = [
    "FileSystemTools",
    "SecurityPolicy", 
    "SecurityError",
    "ToolSchemaGenerator",
    "ToolExecutor"
]
```

---

## Phase 2: Integration with `ollama-prompt`

### 2.1 Add Dependency

```toml
# ollama-prompt/pyproject.toml
[project]
dependencies = [
    "llm-fs-tools>=0.1.0",
    # ... existing deps
]
```

### 2.2 Update Prompt Parser

```python
# ollama-prompt/parser.py

def parse_at_references(prompt: str) -> tuple[list, list]:
    """
    Returns:
        (files_to_inject, directories_for_tools)
    """
    refs = extract_at_symbols(prompt)
    files = []
    dirs = []
    
    for ref in refs:
        path = Path(ref)
        if path.is_file():
            files.append(ref)
        elif path.is_dir():
            dirs.append(ref)
        else:
            raise ValueError(f"Invalid reference: {ref}")
    
    return files, dirs
```

### 2.3 Update Main Handler

```python
# ollama-prompt/main.py

from llm_fs_tools import (
    FileSystemTools,
    SecurityPolicy,
    ToolSchemaGenerator,
    ToolExecutor
)

def handle_prompt(prompt: str, model: str, config: dict):
    files, dirs = parse_at_references(prompt)
    
    # Inject files (existing behavior)
    for file_path in files:
        content = read_file(file_path)
        prompt = inject_content(prompt, file_path, content)
    
    # Enable tools if directories detected
    if dirs:
        # Setup security policy
        policy = SecurityPolicy(
            allowed_roots=dirs + config.get('allowed_roots', []),
            max_file_size_mb=config.get('max_file_size', 5)
        )
        
        # Initialize tools
        fs_tools = FileSystemTools(policy)
        executor = ToolExecutor(fs_tools)
        
        # Get tool definitions
        tool_defs = ToolSchemaGenerator.get_ollama_format()
        
        # Send with tools enabled
        response = ollama.chat(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
            tools=tool_defs
        )
        
        # Tool call loop
        messages = [{'role': 'user', 'content': prompt}]
        while response.message.tool_calls:
            messages.append(response.message)
            
            for tool_call in response.message.tool_calls:
                result = executor.execute(
                    tool_call.function.name,
                    tool_call.function.arguments
                )
                messages.append({
                    'role': 'tool',
                    'content': json.dumps(result),
                    'tool_call_id': tool_call.id
                })
            
            response = ollama.chat(model=model, messages=messages)
        
        return response.message.content
    
    else:
        # Normal prompt (no tools)
        return ollama.chat(model=model, messages=[{'role': 'user', 'content': prompt}])
```

---

## Phase 3: Testing & Documentation

### 3.1 Unit Tests
- `test_security.py` - Path validation, blocked patterns
- `test_tools.py` - Each tool function
- `test_executor.py` - Tool routing and error handling

### 3.2 Integration Tests
- Full workflow with mock LLM responses
- Security boundary violations
- Large file handling

### 3.3 Documentation
- **README.md** - Quick start, examples
- **SECURITY.md** - Security model explanation
- **API.md** - Full API reference
- **examples/** - Working code samples

---

## Phase 4: Distribution

### 4.1 PyPI Package
```bash
pip install llm-fs-tools
```

### 4.2 Repository
```
github.com/dansasser/llm-fs-tools
```

### 4.3 Version Strategy
- `0.1.0` - Initial release (core tools)
- `0.2.0` - Add caching layer
- `0.3.0` - Add git integration tools
- `1.0.0` - Stable API

---

## Implementation Order

1. **Week 1:** Core package skeleton + security layer
2. **Week 2:** Tool implementations + schemas
3. **Week 3:** Executor + testing
4. **Week 4:** ollama-prompt integration
5. **Week 5:** Documentation + examples
6. **Week 6:** PyPI publish + announcement

---

## Configuration Example

```yaml
# ollama-prompt config
filesystem_tools:
  enabled: true
  allowed_roots:
    - ./
    - ~/projects
  max_file_size_mb: 5
  blocked_patterns:
    - "*.env"
    - ".git/*"
  max_results: 100
```

---

## Success Criteria

- [ ] Package installable via `pip install llm-fs-tools`
- [ ] Works with Ollama, OpenAI, Anthropic (examples for each)
- [ ] Security policy prevents path traversal attacks
- [ ] ollama-prompt seamlessly uses tools on `@directory` refs
- [ ] 80%+ test coverage
- [ ] Clear documentation with runnable examples

---
