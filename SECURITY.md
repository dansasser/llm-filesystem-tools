# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Threat Model

`llm-fs-tools` is designed to be used by Large Language Models (LLMs) which may generate untrusted or malicious inputs. The primary security goal is to confine the LLM's filesystem access to a specific set of allowed directories and prevent it from escaping these bounds.

### Trusted Boundary
- The `FileSystemPolicy` defines the trusted boundary (allowed roots).
- The application code using `llm-fs-tools` is trusted.
- The operating system kernel is trusted.

### Untrusted Input
- All arguments passed to tools (`read_file`, `write_file`, etc.) are treated as untrusted.
- The filesystem state itself is treated as potentially hostile (e.g., race conditions, symlinks created by attackers).

### Mitigated Threats

| Threat | Mitigation |
| ------ | ---------- |
| **Path Traversal** | Paths are resolved and checked against allowed roots. `..` components are normalized. |
| **Symlink Attacks** | On Unix, `O_NOFOLLOW` is used. On Windows, reparse points are checked. All checks happen on the file descriptor (FD) to prevent TOCTOU. |
| **TOCTOU (Time-of-Check Time-of-Use)** | We use "Check-Use-Check" pattern or atomic open-and-validate using FDs. We do NOT check a path and then open it later. |
| **Resource Exhaustion** | File size limits and directory entry limits are enforced. |
| **Hidden Files** | Access to dotfiles (e.g., `.env`, `.git`) is blocked by default. |

## Reporting a Vulnerability

Please report vulnerabilities to the maintainers via GitHub Issues or email.
