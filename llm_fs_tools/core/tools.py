"""
Read-only filesystem tools for LLMs.

Provides secure, TOCTOU-resistant file system access with:
- read_file: Read file content with optional line range
- list_directory: List immediate directory contents
- get_directory_tree: Hierarchical directory structure
- search_codebase: Grep-style pattern search
"""
import re
from pathlib import Path
from typing import List, Optional, TypedDict

from .security import FileSystemPolicy
from .file_handle import open_secure
from ..exceptions import SecurityError


class DirectoryEntry(TypedDict):
    name: str
    type: str
    size: int | None


class DirectoryTreeNode(TypedDict, total=False):
    name: str
    type: str
    size: int
    children: List["DirectoryTreeNode"]
    truncated: bool
    error: str


class FileSystemTools:
    """
    Read-only filesystem tools for LLMs.

    All operations use FD-based validation to prevent TOCTOU attacks.
    """

    def __init__(self, security_policy: FileSystemPolicy):
        """
        Initialize with security policy.

        Args:
            security_policy: Policy defining allowed roots, size limits, etc.
        """
        self.policy = security_policy

    def read_file(
        self,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> dict:
        """
        Read file content with optional line range.

        Uses secure FD-based file reading to prevent TOCTOU attacks.

        Args:
            path: Path to file (relative or absolute)
            start_line: First line to read (1-indexed, inclusive)
            end_line: Last line to read (1-indexed, inclusive)

        Returns:
            Standardized response dict:
            {
                "success": True,
                "data": {
                    "content": "file content",
                    "lines": ["line1", "line2"],
                    "total_lines": 100,
                    "encoding": "utf-8"
                },
                "metadata": {
                    "tool": "read_file",
                    "path": "/resolved/path",
                    "size_bytes": 1024
                }
            }
        """
        try:
            with open_secure(path, self.policy) as handle:
                lines = handle.read_lines(start_line, end_line)

                return {
                    "success": True,
                    "data": {
                        "content": ''.join(lines),
                        "lines": lines,
                        "total_lines": len(lines),
                        "encoding": "utf-8"
                    },
                    "metadata": {
                        "tool": "read_file",
                        "path": str(handle.real_path),
                        "size_bytes": handle.stat.st_size
                    }
                }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "read_file", "path": str(path)}
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"File not found: {path}",
                "metadata": {"tool": "read_file", "path": str(path)}
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "read_file", "path": str(path)}
            }

    def list_directory(
        self,
        path: str,
        include_hidden: bool = False
    ) -> dict:
        """
        List immediate directory contents.

        Args:
            path: Directory path to list
            include_hidden: Include hidden files/directories (starting with .)

        Returns:
            Standardized response dict:
            {
                "success": True,
                "data": {
                    "entries": [
                        {"name": "file.py", "type": "file", "size": 1024},
                        {"name": "subdir", "type": "directory", "size": null}
                    ],
                    "total": 2
                },
                "metadata": {
                    "tool": "list_directory",
                    "path": "/resolved/path"
                }
            }
        """
        try:
            dir_path = Path(path).resolve(strict=True)

            # Check directory is within allowed roots
            if not self.policy._is_within_roots(dir_path, self.policy.allowed_roots):
                raise SecurityError(f"Directory outside allowed roots: {dir_path}")

            # Verify it's a directory
            if not dir_path.is_dir():
                raise SecurityError(f"Not a directory: {dir_path}")

            entries: List[DirectoryEntry] = []
            for entry in dir_path.iterdir():
                if not include_hidden and entry.name.startswith('.'):
                    continue

                try:
                    stat_info = entry.stat()
                    entry_type = "file" if entry.is_file() else "directory"
                    entry_size = stat_info.st_size if entry.is_file() else None

                    entries.append({
                        "name": entry.name,
                        "type": entry_type,
                        "size": entry_size
                    })
                except (OSError, PermissionError):
                    # Skip entries we can't stat
                    continue

            # Check entry count limit
            if len(entries) > self.policy.max_directory_entries:
                raise SecurityError(
                    f"Too many entries: {len(entries)} > {self.policy.max_directory_entries}"
                )

            # Sort entries: directories first, then by name
            entries.sort(key=lambda e: (0 if e["type"] == "directory" else 1, e["name"].lower()))

            return {
                "success": True,
                "data": {
                    "entries": entries,
                    "total": len(entries)
                },
                "metadata": {
                    "tool": "list_directory",
                    "path": str(dir_path)
                }
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "list_directory", "path": str(path)}
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Directory not found: {path}",
                "metadata": {"tool": "list_directory", "path": str(path)}
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "list_directory", "path": str(path)}
            }

    def get_directory_tree(
        self,
        path: str,
        max_depth: int = 3,
        include_hidden: bool = False
    ) -> dict:
        """
        Get hierarchical directory structure.

        Args:
            path: Root directory path
            max_depth: Maximum recursion depth (default: 3)
            include_hidden: Include hidden files/directories

        Returns:
            Standardized response dict with tree structure:
            {
                "success": True,
                "data": {
                    "name": "root",
                    "type": "directory",
                    "children": [...]
                },
                "metadata": {
                    "tool": "get_directory_tree",
                    "path": "/resolved/path",
                    "max_depth": 3
                }
            }
        """
        try:
            dir_path = Path(path).resolve(strict=True)

            # Security check
            if not self.policy._is_within_roots(dir_path, self.policy.allowed_roots):
                raise SecurityError(f"Directory outside allowed roots: {dir_path}")

            # Verify it's a directory
            if not dir_path.is_dir():
                raise SecurityError(f"Not a directory: {dir_path}")

            # Track total entries for limit enforcement
            entry_count = [0]  # Use list for mutable closure

            def build_tree(current_path: Path, current_depth: int) -> DirectoryTreeNode:
                """Recursively build directory tree."""
                children: List[DirectoryTreeNode] = []
                tree: DirectoryTreeNode = {
                    "name": current_path.name or str(current_path),
                    "type": "directory",
                    "children": children
                }

                # Stop at max depth
                if current_depth >= max_depth:
                    tree["truncated"] = True
                    return tree

                try:
                    for entry in sorted(current_path.iterdir(), key=lambda e: e.name.lower()):
                        # Skip hidden if not requested
                        if not include_hidden and entry.name.startswith('.'):
                            continue

                        # Check entry limit
                        entry_count[0] += 1
                        if entry_count[0] > self.policy.max_directory_entries:
                            tree["truncated"] = True
                            break

                        try:
                            if entry.is_file():
                                children.append({
                                    "name": entry.name,
                                    "type": "file",
                                    "size": entry.stat().st_size
                                })
                            elif entry.is_dir():
                                # Check if child directory is within allowed roots
                                # SECURITY: Resolve to real path to prevent symlink bypass
                                # A symlink inside allowed roots pointing outside must be blocked
                                try:
                                    real_entry = entry.resolve()
                                except OSError:
                                    # Can't resolve - skip this entry
                                    continue
                                if self.policy._is_within_roots(real_entry, self.policy.allowed_roots):
                                    subtree = build_tree(entry, current_depth + 1)
                                    children.append(subtree)
                        except (OSError, PermissionError):
                            # Skip entries we can't access
                            continue

                except PermissionError:
                    tree["error"] = "Permission denied"

                return tree

            tree = build_tree(dir_path, 0)

            return {
                "success": True,
                "data": tree,
                "metadata": {
                    "tool": "get_directory_tree",
                    "path": str(dir_path),
                    "max_depth": max_depth
                }
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "get_directory_tree", "path": str(path)}
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Directory not found: {path}",
                "metadata": {"tool": "get_directory_tree", "path": str(path)}
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "get_directory_tree", "path": str(path)}
            }

    def search_codebase(
        self,
        pattern: str,
        path: str,
        file_pattern: str = "*",
        case_sensitive: bool = False,
        max_results: int = 100
    ) -> dict:
        """
        Grep-style search across files.

        Args:
            pattern: Regex pattern to search for
            path: Directory to search in
            file_pattern: Glob pattern to filter files (e.g., "*.py")
            case_sensitive: Whether search is case-sensitive
            max_results: Maximum number of matches to return

        Returns:
            Standardized response dict:
            {
                "success": True,
                "data": {
                    "matches": [
                        {
                            "file": "relative/path/file.py",
                            "line": 42,
                            "content": "matching line content",
                            "match": "matched text"
                        }
                    ],
                    "total_matches": 1,
                    "truncated": False
                },
                "metadata": {
                    "tool": "search_codebase",
                    "pattern": "pattern",
                    "path": "/resolved/path"
                }
            }
        """
        try:
            dir_path = Path(path).resolve(strict=True)

            # Security check
            if not self.policy._is_within_roots(dir_path, self.policy.allowed_roots):
                raise SecurityError(f"Directory outside allowed roots: {dir_path}")

            # Verify it's a directory
            if not dir_path.is_dir():
                raise SecurityError(f"Not a directory: {dir_path}")

            # Compile regex
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                regex = re.compile(pattern, flags)
            except re.error as e:
                return {
                    "success": False,
                    "error": f"Invalid regex pattern: {e}",
                    "metadata": {"tool": "search_codebase", "pattern": pattern, "path": str(path)}
                }

            matches = []
            files_searched = 0

            # Walk directory tree
            for file_path in dir_path.rglob(file_pattern):
                if not file_path.is_file():
                    continue

                # Skip files matching blocked patterns
                if self.policy._matches_blocked(file_path):
                    continue

                # Check file is within allowed roots
                if not self.policy._is_within_roots(file_path, self.policy.allowed_roots):
                    continue

                # Try to read file securely
                try:
                    with open_secure(file_path, self.policy) as handle:
                        lines = handle.read_lines()
                        files_searched += 1

                        for i, line in enumerate(lines, 1):
                            match = regex.search(line)
                            if match:
                                matches.append({
                                    "file": str(file_path.relative_to(dir_path)),
                                    "line": i,
                                    "content": line.rstrip(),
                                    "match": match.group()
                                })

                                if len(matches) >= max_results:
                                    break

                except SecurityError:
                    # Skip files that fail security check
                    continue
                except Exception:
                    # Skip files we can't read (binary, etc.)
                    continue

                if len(matches) >= max_results:
                    break

            return {
                "success": True,
                "data": {
                    "matches": matches,
                    "total_matches": len(matches),
                    "files_searched": files_searched,
                    "truncated": len(matches) >= max_results
                },
                "metadata": {
                    "tool": "search_codebase",
                    "pattern": pattern,
                    "path": str(dir_path)
                }
            }

        except SecurityError as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "search_codebase", "pattern": pattern, "path": str(path)}
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Directory not found: {path}",
                "metadata": {"tool": "search_codebase", "pattern": pattern, "path": str(path)}
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {"tool": "search_codebase", "pattern": pattern, "path": str(path)}
            }
