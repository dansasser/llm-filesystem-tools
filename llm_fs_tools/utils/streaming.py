"""
File streaming utilities.

Provides memory-efficient reading of large files with:
- Chunk-based streaming (doesn't load entire file in memory)
- Line-by-line streaming
- Configurable chunk sizes
- Integration with security policy
"""
import os
from pathlib import Path
from typing import Callable, Iterator, Union

from ..core.security import FileSystemPolicy
from ..core.file_handle import open_secure


class StreamingFileReader:
    """
    Stream large files in chunks.

    Memory-efficient reading that doesn't load entire file into memory.
    Useful for processing large files that exceed available RAM.
    """

    def __init__(
        self,
        policy: FileSystemPolicy,
        chunk_size: int = 8192
    ):
        """
        Initialize streaming reader.

        Args:
            policy: Security policy for file access
            chunk_size: Size of chunks to read (default: 8KB)
        """
        self.policy = policy
        self.chunk_size = chunk_size

    def stream_file(
        self,
        path: Union[str, Path],
        encoding: str = 'utf-8'
    ) -> Iterator[str]:
        """
        Stream file in chunks.

        Yields decoded text chunks. Does not split on line boundaries.

        Args:
            path: Path to file
            encoding: Text encoding (default: utf-8)

        Yields:
            Chunks of file content as strings
        """
        with open_secure(path, self.policy) as handle:
            os.lseek(handle.fd, 0, os.SEEK_SET)

            while True:
                chunk = os.read(handle.fd, self.chunk_size)
                if not chunk:
                    break

                yield chunk.decode(encoding, errors='replace')

    def stream_bytes(
        self,
        path: Union[str, Path]
    ) -> Iterator[bytes]:
        """
        Stream file as raw bytes.

        Yields raw byte chunks. Useful for binary files or when
        encoding is unknown.

        Args:
            path: Path to file

        Yields:
            Chunks of file content as bytes
        """
        with open_secure(path, self.policy) as handle:
            os.lseek(handle.fd, 0, os.SEEK_SET)

            while True:
                chunk = os.read(handle.fd, self.chunk_size)
                if not chunk:
                    break

                yield chunk

    def stream_lines(
        self,
        path: Union[str, Path],
        encoding: str = 'utf-8'
    ) -> Iterator[str]:
        """
        Stream file line by line.

        Yields complete lines (including newline character).
        Memory-efficient for files with many lines.

        Args:
            path: Path to file
            encoding: Text encoding (default: utf-8)

        Yields:
            Individual lines from file
        """
        buffer = ""

        for chunk in self.stream_file(path, encoding):
            buffer += chunk

            # Yield complete lines
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                yield line + '\n'

        # Yield remaining content (final line without newline)
        if buffer:
            yield buffer

    def stream_lines_numbered(
        self,
        path: Union[str, Path],
        encoding: str = 'utf-8',
        start: int = 1
    ) -> Iterator[tuple[int, str]]:
        """
        Stream file lines with line numbers.

        Yields (line_number, line_content) tuples.

        Args:
            path: Path to file
            encoding: Text encoding (default: utf-8)
            start: Starting line number (default: 1)

        Yields:
            Tuples of (line_number, line_content)
        """
        for i, line in enumerate(self.stream_lines(path, encoding), start=start):
            yield (i, line)

    def count_lines(
        self,
        path: Union[str, Path],
        encoding: str = 'utf-8'
    ) -> int:
        """
        Count lines in file without loading entire file.

        Args:
            path: Path to file
            encoding: Text encoding (default: utf-8)

        Returns:
            Number of lines in file
        """
        count = 0
        for _ in self.stream_lines(path, encoding):
            count += 1
        return count

    def get_file_size(
        self,
        path: Union[str, Path]
    ) -> int:
        """
        Get file size securely.

        Args:
            path: Path to file

        Returns:
            File size in bytes
        """
        with open_secure(path, self.policy) as handle:
            return handle.stat.st_size


class ChunkedProcessor:
    """
    Process files in chunks with a callback.

    Useful for processing large files with custom logic
    without loading entire file into memory.
    """

    def __init__(
        self,
        policy: FileSystemPolicy,
        chunk_size: int = 8192
    ):
        """
        Initialize chunked processor.

        Args:
            policy: Security policy for file access
            chunk_size: Size of chunks to process (default: 8KB)
        """
        self.reader = StreamingFileReader(policy, chunk_size)

    def process_file(
        self,
        path: Union[str, Path],
        processor: Callable[[str, int], object | None],
        encoding: str = 'utf-8'
    ) -> dict:
        """
        Process file chunks with a callback function.

        Args:
            path: Path to file
            processor: Function that takes (chunk: str, chunk_index: int) and returns any result
            encoding: Text encoding (default: utf-8)

        Returns:
            Dict with processing results:
            {
                "success": True,
                "data": {
                    "chunks_processed": 10,
                    "results": [...processor return values...]
                }
            }
        """
        try:
            results = []
            chunk_index = 0

            for chunk in self.reader.stream_file(path, encoding):
                result = processor(chunk, chunk_index)
                if result is not None:
                    results.append(result)
                chunk_index += 1

            return {
                "success": True,
                "data": {
                    "chunks_processed": chunk_index,
                    "results": results
                },
                "metadata": {
                    "path": str(path)
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {
                    "path": str(path)
                }
            }

    def process_lines(
        self,
        path: Union[str, Path],
        processor: Callable[[str, int], object | None],
        encoding: str = 'utf-8'
    ) -> dict:
        """
        Process file lines with a callback function.

        Args:
            path: Path to file
            processor: Function that takes (line: str, line_number: int) and returns any result
            encoding: Text encoding (default: utf-8)

        Returns:
            Dict with processing results
        """
        try:
            results = []
            line_count = 0

            for line_num, line in self.reader.stream_lines_numbered(path, encoding):
                result = processor(line, line_num)
                if result is not None:
                    results.append(result)
                line_count += 1

            return {
                "success": True,
                "data": {
                    "lines_processed": line_count,
                    "results": results
                },
                "metadata": {
                    "path": str(path)
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "metadata": {
                    "path": str(path)
                }
            }
