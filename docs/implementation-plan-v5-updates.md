# Implementation Plan v5 - Required Updates for ollama-prompt Integration

**Date:** 2024-11-30
**Base Document:** implementation-plan-v5.md
**Purpose:** Document required changes to ensure seamless ollama-prompt integration

---

## Analysis Summary

After reviewing implementation-plan-v5.md against ollama-prompt requirements:

| Aspect | Plan Status | Action Needed |
|--------|-------------|---------------|
| FD-based security | Complete | None |
| Platform-specific open | Complete | None |
| Symlink blocking | Complete | None |
| Return format | Incompatible | Add adapter |
| Convenience API | Missing | Add function |
| Truncation indicator | Missing | Add to read |
| Dependencies | OK (stdlib) | None |
| Integration timeline | Vague | Clarify |

---

## Required Updates

### Update 1: Add Convenience API

**Location:** Add to `__init__.py` (lines 1439-1473)

**Current exports:**
```python
__all__ = [
    "FileSystemPolicy",
    "SecurityError",
    "FileSystemTools",
    "FileSystemWriteTools",
    "ToolSchemaGenerator",
    "ToolExecutor",
    "AuditLogger",
    "StreamingFileReader",
]
```

**Add:**
```python
# NEW: Convenience function for simple use cases (ollama-prompt compatible)
def read_file_secure(
    path: str,
    repo_root: str = ".",
    max_bytes: int = 200_000,
    encoding: str = "utf-8"
) -> dict:
    """
    Simple API for single-file reads with security.

    Compatible with ollama-prompt's read_file_snippet() interface.

    Args:
        path: File path (absolute or relative to repo_root)
        repo_root: Root directory for containment (default: current dir)
        max_bytes: Maximum bytes to read (default: 200KB)
        encoding: Text encoding (default: utf-8)

    Returns:
        Success: {"ok": True, "path": "<resolved_path>", "content": "<file_content>"}
        Failure: {"ok": False, "path": "<requested_path>", "error": "<error_message>"}

    Security:
        - TOCTOU-resistant (FD-based validation)
        - Symlinks blocked (O_NOFOLLOW / FILE_FLAG_OPEN_REPARSE_POINT)
        - Path containment enforced
        - Device files rejected
    """
    from pathlib import Path

    try:
        # Create minimal policy for single-root use
        policy = FileSystemPolicy(
            allowed_roots=[repo_root],
            max_file_size_mb=(max_bytes / (1024 * 1024)) * 1.1,  # 10% margin
            blocked_patterns=[],  # Allow all patterns for compatibility
            blocked_extensions=[]
        )

        tools = FileSystemTools(policy)
        result = tools.read_file(path)

        if result["success"]:
            content = result["data"]["content"]

            # Enforce byte limit and add truncation indicator
            # Use character-safe truncation to avoid corrupting multibyte UTF-8
            if len(content.encode(encoding)) > max_bytes:
                # Truncate at character boundary
                while len(content.encode(encoding)) > max_bytes and content:
                    content = content[:-1]
                content += "\n\n[TRUNCATED: file larger than max_bytes]\n"

            return {
                "ok": True,
                "path": result["metadata"]["path"],
                "content": content
            }
        else:
            return {
                "ok": False,
                "path": str(path),
                "error": result["error"]
            }

    except Exception as e:
        return {
            "ok": False,
            "path": str(path),
            "error": str(e)
        }


__all__ = [
    # Core
    "FileSystemPolicy",
    "SecurityError",

    # Tools
    "FileSystemTools",
    "FileSystemWriteTools",

    # Integration
    "ToolSchemaGenerator",
    "ToolExecutor",

    # Utilities
    "AuditLogger",
    "StreamingFileReader",

    # NEW: Convenience API
    "read_file_secure",
]
```

---

### Update 2: Add Truncation Support to SecureFileHandle

**Location:** `core/file_handle.py` - SecureFileHandle class (lines 453-517)

**Add method:**
```python
def read_limited(
    self,
    max_bytes: int,
    encoding: str = 'utf-8',
    truncation_marker: str = "\n\n[TRUNCATED: file larger than max_bytes]\n"
) -> tuple[str, bool]:
    """
    Read file with byte limit and truncation indicator.

    Args:
        max_bytes: Maximum bytes to read
        encoding: Text encoding
        truncation_marker: String appended if truncated

    Returns:
        (content, was_truncated)

    Raises:
        ValueError: If max_bytes <= 0
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    os.lseek(self.fd, 0, os.SEEK_SET)

    # Read up to max_bytes
    data = os.read(self.fd, max_bytes)

    # Check if there's more data
    extra = os.read(self.fd, 1)
    was_truncated = len(extra) > 0

    content = data.decode(encoding, errors='replace')

    if was_truncated:
        content += truncation_marker

    return content, was_truncated
```

---

### Update 3: Clarify Week 4 Integration Timeline

**Location:** Implementation Timeline section (lines 1421-1426)

**Current:**
```
### Week 4: Production Features
- Day 1-2: Audit logging + streaming support
- Day 3-4: ollama-prompt integration
- Day 5: Integration testing
```

**Updated:**
```
### Week 4: Production Features
- Day 1-2: Audit logging + streaming support
- Day 3-4: ollama-prompt integration
  - Implement read_file_secure() convenience function
  - Add read_limited() method to SecureFileHandle
  - Create ollama-prompt compatible return format
  - Test with ollama-prompt-bug-fixes repo
  - Verify @./ file reference expansion works
  - Document migration path from read_file_snippet()
- Day 5: Integration testing
  - Cross-platform tests (Windows, Linux, macOS)
  - Attack scenario tests with ollama-prompt
  - Performance comparison (old vs new)
```

---

### Update 4: Add Integration Example

**Location:** Add new file `examples/ollama_prompt_integration.py`

```python
"""
Example: Integrating llm-fs-tools with ollama-prompt

This shows how to replace ollama-prompt's read_file_snippet() with
secure file reading from llm-fs-tools.
"""

# Option 1: Direct drop-in replacement
from llm_fs_tools import read_file_secure

def read_file_snippet(path, repo_root=".", max_bytes=200_000):
    """
    Drop-in replacement for ollama_prompt.cli.read_file_snippet()

    Provides:
    - TOCTOU-resistant file reading
    - Symlink blocking
    - FD-based validation
    """
    return read_file_secure(path, repo_root, max_bytes)


# Option 2: With custom policy (more control)
from llm_fs_tools import FileSystemPolicy, FileSystemTools

def create_secure_reader(repo_root: str, max_mb: int = 5):
    """
    Create a reusable secure reader for multiple files.
    More efficient when reading many files from same repo.
    """
    policy = FileSystemPolicy(
        allowed_roots=[repo_root],
        max_file_size_mb=max_mb,
        blocked_patterns=["*.env", "*.key", "*.pem"],  # Security defaults
        blocked_extensions=[".exe", ".dll", ".so"]
    )
    return FileSystemTools(policy)


# Usage example
if __name__ == "__main__":
    # Simple usage (like ollama-prompt)
    result = read_file_secure("./README.md", repo_root=".")

    if result["ok"]:
        print(f"Read {len(result['content'])} chars from {result['path']}")
    else:
        print(f"Error: {result['error']}")

    # Advanced usage (reusable reader)
    reader = create_secure_reader("/path/to/repo")
    for file in ["src/main.py", "src/utils.py", "tests/test_main.py"]:
        result = reader.read_file(file)
        if result["success"]:
            print(f"Read: {file}")
```

---

### Update 5: Add to Success Criteria

**Location:** Success Criteria section (lines 1479-1493)

**Add:**
```markdown
## ollama-prompt Integration Criteria

- [ ] `read_file_secure()` function exported from package
- [ ] Return format: `{"ok": bool, "path": str, "content"|"error": str}`
- [ ] Truncation indicator matches: `[TRUNCATED: file larger than max_bytes]`
- [ ] Drop-in compatible with `read_file_snippet()` signature
- [ ] Works with `@./` file reference syntax
- [ ] No additional dependencies beyond stdlib
- [ ] Integration example in `examples/ollama_prompt_integration.py`
- [ ] Migration guide in README
```

---

### Update 6: Package Structure Addition

**Location:** Package Structure section (lines 25-67)

**Add to examples/:**
```
└── examples/
    ├── ollama_integration.py
    ├── openai_integration.py
    ├── write_example.py
    ├── audit_example.py
    └── ollama_prompt_integration.py   # NEW: ollama-prompt specific
```

---

## Summary of Changes

| Section | Change Type | Priority |
|---------|-------------|----------|
| `__init__.py` exports | Add `read_file_secure()` | HIGH |
| SecureFileHandle | Add `read_limited()` method | MEDIUM |
| Week 4 timeline | Clarify integration tasks | MEDIUM |
| examples/ | Add ollama_prompt_integration.py | MEDIUM |
| Success Criteria | Add integration criteria | LOW |
| Package Structure | Document new example | LOW |

---

## Implementation Order

1. **Day 1:** Add `read_limited()` to SecureFileHandle
2. **Day 2:** Implement `read_file_secure()` convenience function
3. **Day 3:** Create integration example and tests
4. **Day 4:** Test with actual ollama-prompt repo
5. **Day 5:** Document and finalize

---

## Compatibility Matrix

| ollama-prompt Version | llm-fs-tools API | Notes |
|-----------------------|------------------|-------|
| Current (no PR #7) | `read_file_secure()` | Direct replacement |
| With PR #7 | `read_file_secure()` | Same - PR #7 doesn't touch file reading |
| Future | Full `FileSystemTools` | Can upgrade later for more features |
