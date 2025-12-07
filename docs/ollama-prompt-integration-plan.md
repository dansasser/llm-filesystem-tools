# ollama-prompt + llm-fs-tools Integration Plan

**Date:** 2025-12-06
**Status:** Design Phase
**Packages:**
- `ollama-prompt` - CLI for sending prompts to Ollama with file references
- `llm-fs-tools` - Secure filesystem access library for LLMs

---

## Executive Summary

ollama-prompt currently has `secure_file.py` which duplicates much of llm-fs-tools' security features for individual file reading. The integration should:

1. **Replace** ollama-prompt's `secure_file.py` with llm-fs-tools dependency
2. **Add** directory-level access syntax (`@./directory/`)
3. **Expose** new capabilities: list, tree, search, write

---

## Current State Analysis

### ollama-prompt/secure_file.py (Current)

```python
# Key functions
secure_open(path, repo_root, audit) -> {ok, fd, resolved_path, size} | {ok: False, error}
read_file_secure(path, repo_root, max_bytes, audit) -> {ok, path, content} | {ok: False, error}
```

**Features:**
- O_NOFOLLOW on Unix
- Partial Windows reparse point detection
- fstat validation
- Path containment check
- Audit logging

### ollama-prompt/cli.py (Current)

```python
# File reference expansion
pattern = r'@((?:\.\.?[/\\]|[/\\])[^\s@?!,;]+)'

# Matches:
# @./file.py      -> relative to cwd
# @../file.py     -> parent directory
# @/absolute/path -> absolute path

# Result wrapping:
--- FILE: path START ---
{content}
--- FILE: path END ---
```

---

## Integration Design

### Option Selected: Replace + Extend

Replace `secure_file.py` with `llm-fs-tools` and extend syntax for directory access.

### Changes to llm-fs-tools

#### 1. Add Drop-in Compatibility Functions

**File:** `llm_fs_tools/__init__.py`

```python
def read_file_secure(
    path: str,
    repo_root: str = ".",
    max_bytes: int = 200_000,
    audit: bool = True
) -> dict:
    """
    Drop-in replacement for ollama-prompt's read_file_secure().

    Returns:
        {"ok": True, "path": str, "content": str}
        {"ok": False, "path": str, "error": str}
    """
    # Implementation using FileSystemPolicy + FileSystemTools

def secure_open(
    path: str,
    repo_root: str = ".",
    audit: bool = True
) -> dict:
    """
    Drop-in replacement for ollama-prompt's secure_open().

    Returns:
        {"ok": True, "fd": int, "path": str, "resolved_path": str, "size": int}
        {"ok": False, "path": str, "error": str}
    """
    # Implementation using platform/secure_open.py
```

#### 2. Add Directory Access Function

```python
def create_directory_tools(
    directory: str,
    allow_write: bool = False,
    audit: bool = True
) -> dict:
    """
    Create tools for directory-level access.

    This is the PRIMARY integration point for ollama-prompt.

    Args:
        directory: Root directory to grant access to
        allow_write: Enable write operations
        audit: Enable audit logging

    Returns:
        {
            "ok": True,
            "directory": str,  # Resolved path
            "tools": {
                "list": callable,      # list_directory
                "tree": callable,      # get_directory_tree
                "search": callable,    # search_codebase
                "read": callable,      # read_file
                "write": callable,     # write_file (if allow_write)
                "mkdir": callable,     # create_directory (if allow_write)
            }
        }
    """
```

---

### Changes to ollama-prompt

#### 1. Replace secure_file.py Import

**File:** `ollama_prompt/cli.py`

```python
# BEFORE
from .secure_file import read_file_secure, DEFAULT_MAX_FILE_BYTES

# AFTER
from llm_fs_tools import read_file_secure
DEFAULT_MAX_FILE_BYTES = 200_000
```

#### 2. Delete secure_file.py

Remove `ollama_prompt/secure_file.py` entirely - functionality provided by llm-fs-tools.

#### 3. Extend File Reference Syntax

**New Syntax:**

| Pattern | Meaning | Handler |
|---------|---------|---------|
| `@./file.py` | Read single file | `read_file_secure()` |
| `@./directory/` | Grant directory access | `create_directory_tools()` |
| `@./dir/:list` | List directory | `tools["list"]()` |
| `@./dir/:tree` | Get directory tree | `tools["tree"]()` |
| `@./dir/:search:pattern` | Search for pattern | `tools["search"](pattern)` |

**Updated Regex:**

```python
# File reference (existing)
file_pattern = r'@((?:\.\.?[/\\]|[/\\])[^\s@?!,;:]+)'

# Directory reference (new - ends with / or \)
dir_pattern = r'@((?:\.\.?[/\\]|[/\\])[^\s@?!,;]+[/\\])(?::(\w+)(?::(.+))?)?'

# Combined pattern
pattern = re.compile(r'@((?:\.\.?[/\\]|[/\\])[^\s@?!,;]+)(?::(\w+)(?::(.+))?)?')
```

#### 4. New expand_refs Function

```python
def expand_refs_in_prompt(prompt, repo_root=".", max_bytes=DEFAULT_MAX_FILE_BYTES):
    """
    Expand file and directory references in prompt.

    Syntax:
        @./file.py           -> inline file content
        @./directory/        -> grant directory access (list structure)
        @./directory/:list   -> list directory contents
        @./directory/:tree   -> show directory tree
        @./directory/:search:TODO  -> search for "TODO" in directory
    """
    from llm_fs_tools import read_file_secure, create_directory_tools

    pattern = re.compile(r'@((?:\.\.?[/\\]|[/\\])[^\s@?!,;]+)(?::(\w+)(?::(.+))?)?')

    def _repl(m):
        path = m.group(1)
        command = m.group(2)  # list, tree, search, or None
        arg = m.group(3)      # search pattern or None

        # Directory reference (ends with / or \)
        if path.endswith('/') or path.endswith('\\'):
            return _handle_directory_ref(path, command, arg, repo_root)

        # File reference (existing behavior)
        return _handle_file_ref(path, repo_root, max_bytes)

    return pattern.sub(_repl, prompt)


def _handle_file_ref(path, repo_root, max_bytes):
    """Handle @./file.py syntax."""
    res = read_file_secure(path, repo_root=repo_root, max_bytes=max_bytes)
    if not res["ok"]:
        return f"\n\n--- FILE: {path} (ERROR: {res['error']}) ---\n"
    return (
        f"\n\n--- FILE: {path} START ---\n"
        f"{res['content']}\n"
        f"--- FILE: {path} END ---\n\n"
    )


def _handle_directory_ref(path, command, arg, repo_root):
    """Handle @./directory/ syntax."""
    from llm_fs_tools import create_directory_tools

    result = create_directory_tools(path, allow_write=False)
    if not result["ok"]:
        return f"\n\n--- DIRECTORY: {path} (ERROR: {result['error']}) ---\n"

    tools = result["tools"]
    resolved = result["directory"]

    # Default command: show tree
    if command is None:
        command = "tree"

    if command == "list":
        output = tools["list"](resolved)
        content = _format_list_output(output)
    elif command == "tree":
        output = tools["tree"](resolved, max_depth=3)
        content = _format_tree_output(output)
    elif command == "search":
        if not arg:
            return f"\n\n--- DIRECTORY: {path} (ERROR: search requires pattern) ---\n"
        output = tools["search"](arg, resolved)
        content = _format_search_output(output)
    else:
        return f"\n\n--- DIRECTORY: {path} (ERROR: unknown command '{command}') ---\n"

    return (
        f"\n\n--- DIRECTORY: {path} ({command.upper()}) START ---\n"
        f"{content}\n"
        f"--- DIRECTORY: {path} ({command.upper()}) END ---\n\n"
    )
```

---

## Implementation Phases

### Phase 1: llm-fs-tools Compatibility Layer (2 hours)

1. Add `read_file_secure()` to `__init__.py` matching ollama-prompt signature
2. Add `secure_open()` to `__init__.py` matching ollama-prompt signature
3. Add `create_directory_tools()` function
4. Write unit tests for compatibility functions
5. Verify return format matches exactly

### Phase 2: ollama-prompt Migration (2 hours)

1. Add `llm-fs-tools` to `requirements.txt` / `pyproject.toml`
2. Update imports in `cli.py`
3. Delete `secure_file.py`
4. Run existing tests to verify no regression
5. Update any tests that imported from `secure_file`

### Phase 3: Directory Syntax Extension (3 hours)

1. Implement new regex pattern in `cli.py`
2. Add `_handle_directory_ref()` function
3. Add formatting functions for list/tree/search output
4. Write tests for new directory syntax
5. Update documentation

### Phase 4: Integration Testing (2 hours)

1. Test `@./file.py` still works (regression)
2. Test `@./directory/` shows tree
3. Test `@./directory/:list` lists contents
4. Test `@./directory/:search:pattern` searches
5. Test security (path containment, symlink blocking)

---

## API Compatibility Matrix

| ollama-prompt Function | llm-fs-tools Equivalent | Drop-in? |
|------------------------|-------------------------|----------|
| `secure_open()` | `secure_open()` | Yes |
| `read_file_secure()` | `read_file_secure()` | Yes |
| `safe_read_file()` | `read_file_secure()` | Yes |
| `check_hardlinks()` | N/A (not needed) | N/A |
| N/A | `create_directory_tools()` | New |
| N/A | `FileSystemTools.list_directory()` | New |
| N/A | `FileSystemTools.get_directory_tree()` | New |
| N/A | `FileSystemTools.search_codebase()` | New |
| N/A | `FileSystemWriteTools.write_file()` | New |

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking existing `@./file` syntax | HIGH | Comprehensive regression tests |
| Return format mismatch | MEDIUM | Exact signature matching in compatibility layer |
| Performance regression | LOW | llm-fs-tools uses same FD-based approach |
| Security regression | HIGH | llm-fs-tools has MORE security features |
| Windows compatibility | MEDIUM | llm-fs-tools already tested on Windows |

---

## Success Criteria

- [ ] `@./file.py` works identically to before
- [ ] `@./directory/` shows directory tree
- [ ] `@./directory/:list` shows flat listing
- [ ] `@./directory/:search:pattern` finds matches
- [ ] All existing ollama-prompt tests pass
- [ ] Security: symlinks blocked, path containment enforced
- [ ] ollama-prompt no longer has `secure_file.py`
- [ ] llm-fs-tools published to PyPI

---

## Estimated Timeline

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1: Compatibility Layer | 2 hours | None |
| Phase 2: Migration | 2 hours | Phase 1 |
| Phase 3: Directory Syntax | 3 hours | Phase 2 |
| Phase 4: Integration Testing | 2 hours | Phase 3 |
| **Total** | **9 hours** | |

---

## Files to Modify

### llm-fs-tools

| File | Change |
|------|--------|
| `llm_fs_tools/__init__.py` | Add `read_file_secure()`, `secure_open()`, `create_directory_tools()` |
| `tests/test_compatibility.py` | New - test ollama-prompt compatibility |

### ollama-prompt

| File | Change |
|------|--------|
| `pyproject.toml` | Add `llm-fs-tools` dependency |
| `ollama_prompt/cli.py` | Update imports, add directory syntax |
| `ollama_prompt/secure_file.py` | DELETE |
| `tests/test_secure_file.py` | Update imports or delete |
| `tests/test_directory_refs.py` | New - test directory syntax |
