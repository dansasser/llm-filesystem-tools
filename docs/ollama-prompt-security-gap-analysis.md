# Ollama-Prompt File Security Gap Analysis

**Date:** 2024-11-30
**Related PR:** dansasser/ollama-prompt#7 (Security Hardening - DB/Session focus)
**Related Plan:** implementation-plan-v5.md (llm-fs-tools)

---

## Executive Summary

PR #7 addresses database/session security but leaves **file read operations vulnerable**. The `safe_join_repo()` and `read_file_snippet()` functions in `cli.py` have security weaknesses that require integration with `llm-fs-tools`.

---

## Current File Handling Analysis

### Location: `ollama_prompt/cli.py` lines 12-79

### Function 1: `safe_join_repo()` (lines 12-38)

```python
def safe_join_repo(repo_root, path):
    """Join path to repo_root and prevent path traversal outside repo_root."""
    # ...
    repo_root_resolved = os.path.realpath(os.path.abspath(repo_root))
    target_resolved = os.path.realpath(target)  # <-- PROBLEM: follows symlinks
    # ...
```

**Vulnerabilities:**
| Issue | Severity | Description |
|-------|----------|-------------|
| Symlink following | HIGH | `os.path.realpath()` resolves symlinks, allowing escape from repo_root |
| TOCTOU gap | MEDIUM | Path validated, then file opened separately - race condition window |
| No symlink blocking | HIGH | Attacker can create symlink to sensitive file outside repo |

### Function 2: `read_file_snippet()` (lines 40-51)

```python
def read_file_snippet(path, repo_root=".", max_bytes=DEFAULT_MAX_FILE_BYTES):
    try:
        fp = safe_join_repo(repo_root, path)
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:  # <-- TOCTOU
            content = f.read(max_bytes)
```

**Vulnerabilities:**
| Issue | Severity | Description |
|-------|----------|-------------|
| TOCTOU race | MEDIUM | File can change between `safe_join_repo()` and `open()` |
| No FD validation | MEDIUM | Security check on path, not on opened file descriptor |
| No audit logging | LOW | No record of file access attempts |

---

## Attack Scenarios

### Scenario 1: Symlink Escape

```bash
# Attacker creates malicious repo
cd /tmp/malicious-repo
ln -s /etc/passwd ./config.txt

# User analyzes repo with ollama-prompt
ollama-prompt --prompt "Analyze @./config.txt" --repo-root /tmp/malicious-repo
# Result: /etc/passwd contents exposed!
```

**Why it works:** `os.path.realpath()` resolves the symlink to `/etc/passwd`, and `commonpath` check passes because the check happens on the resolved path.

Wait - let me re-verify this. The code does:
1. `target_resolved = os.path.realpath(target)` - resolves to /etc/passwd
2. `common = os.path.commonpath([repo_root_resolved, target_resolved])`
3. If common != repo_root_resolved, raise error

So /etc/passwd would NOT be under /tmp/malicious-repo... Let me re-check the actual vulnerability.

**Correction:** The current code DOES block this specific attack because commonpath check happens AFTER realpath. The vulnerability is more subtle:

### Scenario 1 (Revised): Race Condition TOCTOU

```bash
# Attacker has write access to repo (e.g., cloned malicious repo)
# Step 1: Create legitimate file
echo "safe content" > /tmp/repo/data.txt

# Step 2: User starts analysis
ollama-prompt --prompt "Analyze @./data.txt" --repo-root /tmp/repo

# Step 3: During the gap between safe_join_repo() and open():
# Attacker replaces file with symlink
rm /tmp/repo/data.txt && ln -s /etc/shadow /tmp/repo/data.txt

# Result: Shadow file potentially read if timing is right
```

### Scenario 2: Hardlink Attack (Unix)

```bash
# Attacker creates hardlink (doesn't require special permissions for files they own)
ln /home/attacker/.ssh/id_rsa /tmp/repo/key.txt

# Hardlinks are NOT detected by realpath or commonpath
# The file appears to be inside repo but shares inode with sensitive file
```

### Scenario 3: Directory Symlink (More Realistic)

```bash
# Create repo with symlinked directory
mkdir /tmp/repo
ln -s /home/victim/.ssh /tmp/repo/configs

# Analysis request
ollama-prompt --prompt "Analyze @./configs/id_rsa" --repo-root /tmp/repo

# realpath of @./configs/id_rsa = /home/victim/.ssh/id_rsa
# commonpath check: /home/victim/.ssh/id_rsa is NOT under /tmp/repo
# This WOULD be blocked by current code
```

---

## Revised Vulnerability Assessment

After deeper analysis:

| Attack Vector | Current Protection | Gap? |
|--------------|-------------------|------|
| Direct symlink to file outside repo | BLOCKED by commonpath | No |
| Symlink directory containing target | BLOCKED by commonpath | No |
| TOCTOU race condition | NOT PROTECTED | **YES** |
| Hardlinks (same filesystem) | NOT PROTECTED | **YES** |
| Device files (/dev/zero, etc.) | NOT PROTECTED | **YES** |
| FIFOs/named pipes | NOT PROTECTED | **YES** |
| No audit trail | NOT PROTECTED | **YES** |

---

## Required Fixes

### Priority 1: TOCTOU Protection (FD-Based Validation)

**Current flow (vulnerable):**
```
1. Validate path (safe_join_repo)
2. --- TOCTOU WINDOW ---
3. Open file
4. Read content
```

**Fixed flow:**
```
1. Minimal syntax validation only
2. Open file with O_NOFOLLOW (blocks symlinks at open time)
3. Validate FD (fstat, real path from FD)
4. Read content from FD
```

### Priority 2: Symlink Blocking at Open Time

Use platform-specific secure open:
- Unix: `os.open(path, os.O_RDONLY | os.O_NOFOLLOW)`
- Windows: `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT`

### Priority 3: File Type Validation

After opening, verify via `fstat`:
- Is regular file (not device, FIFO, socket)
- Size within limits
- Real path within allowed roots

### Priority 4: Audit Logging (Optional but Recommended)

Log all file access attempts with:
- Timestamp
- Requested path
- Resolved path
- Success/failure
- Reason for failure

---

## Integration Path

### Option A: Direct Integration (Recommended)

Replace `read_file_snippet()` with `llm-fs-tools`:

```python
# Before
from .file_utils import read_file_snippet

# After
from llm_fs_tools import read_file_secure

def read_file_snippet(path, repo_root=".", max_bytes=DEFAULT_MAX_FILE_BYTES):
    result = read_file_secure(path, repo_root, max_bytes)
    return result  # Already in compatible format
```

### Option B: Vendored Module

Copy core security module into ollama_prompt package for zero external dependencies.

### Option C: Optional Dependency

```python
try:
    from llm_fs_tools import read_file_secure
    USE_SECURE_READ = True
except ImportError:
    USE_SECURE_READ = False
    # Fall back to current implementation with warning
```

---

## Requirements for llm-fs-tools Integration

For seamless integration, `llm-fs-tools` must provide:

1. **Convenience function** matching ollama-prompt's interface:
   ```python
   def read_file_secure(path: str, repo_root: str = ".", max_bytes: int = 200_000) -> dict:
       """Returns {"ok": bool, "path": str, "content": str} or {"ok": bool, "path": str, "error": str}"""
   ```

2. **Truncation indicator** appended when file exceeds max_bytes

3. **Cross-platform support** (Windows, Linux, macOS)

4. **Minimal dependencies** (stdlib only preferred)

5. **Error messages** compatible with current format

---

## Success Criteria

- [ ] Symlinks blocked at open time (O_NOFOLLOW or equivalent)
- [ ] TOCTOU window eliminated (FD-based validation)
- [ ] Device files, FIFOs, sockets rejected
- [ ] Hardlink detection (optional - check inode/nlink)
- [ ] Return format compatible with existing code
- [ ] Cross-platform (Windows + Linux + macOS)
- [ ] No breaking changes to CLI interface
- [ ] Tests for attack scenarios

---

## Next Steps

1. Review `implementation-plan-v5.md` for compatibility
2. Add convenience API to llm-fs-tools public interface
3. Create integration branch in ollama-prompt
4. Write attack scenario tests
5. Document security improvements in SECURITY.md
