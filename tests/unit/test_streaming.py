"""
Unit tests for streaming file utilities.

Tests cover:
- StreamingFileReader: Chunk and line-based streaming
- ChunkedProcessor: Callback-based file processing
"""
import os
import sys
import pytest
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from llm_fs_tools import FileSystemPolicy, StreamingFileReader, ChunkedProcessor


class TestStreamingFileReader:
    """Test StreamingFileReader for memory-efficient file reading."""

    @pytest.fixture
    def policy(self, tmp_path):
        """Create a policy allowing access to tmp_path."""
        return FileSystemPolicy(allowed_roots=[str(tmp_path)])

    def test_stream_file_chunks(self, tmp_path, policy):
        """Can stream a file in chunks."""
        test_file = tmp_path / "large.txt"
        content = "A" * 1000
        test_file.write_text(content, encoding="utf-8")

        reader = StreamingFileReader(policy, chunk_size=100)
        chunks = list(reader.stream_file(str(test_file)))

        # Should have multiple chunks
        assert len(chunks) == 10
        # Reassembled content should match
        assert "".join(chunks) == content

    def test_stream_file_small(self, tmp_path, policy):
        """Streams small file in single chunk."""
        test_file = tmp_path / "small.txt"
        content = "Hello, World!"
        test_file.write_text(content, encoding="utf-8")

        reader = StreamingFileReader(policy, chunk_size=8192)
        chunks = list(reader.stream_file(str(test_file)))

        assert len(chunks) == 1
        assert chunks[0] == content

    def test_stream_bytes(self, tmp_path, policy):
        """Can stream raw bytes."""
        test_file = tmp_path / "binary.bin"
        content = b"\x00\x01\x02\x03\x04\x05"
        test_file.write_bytes(content)

        reader = StreamingFileReader(policy, chunk_size=2)
        chunks = list(reader.stream_bytes(str(test_file)))

        assert len(chunks) == 3
        assert b"".join(chunks) == content

    def test_stream_lines(self, tmp_path, policy):
        """Can stream file line by line."""
        test_file = tmp_path / "lines.txt"
        # Write in binary mode to control exact content
        test_file.write_bytes(b"Line 1\nLine 2\nLine 3\n")

        reader = StreamingFileReader(policy)
        result = list(reader.stream_lines(str(test_file)))

        assert len(result) == 3
        assert [line.strip() for line in result] == ["Line 1", "Line 2", "Line 3"]

    def test_stream_lines_no_final_newline(self, tmp_path, policy):
        """Handles files without final newline."""
        test_file = tmp_path / "lines.txt"
        # Write in binary mode to control exact content
        test_file.write_bytes(b"Line 1\nLine 2\nLine 3")

        reader = StreamingFileReader(policy)
        result = list(reader.stream_lines(str(test_file)))

        assert len(result) == 3
        assert [line.strip() for line in result] == ["Line 1", "Line 2", "Line 3"]

    def test_stream_lines_numbered(self, tmp_path, policy):
        """Can stream lines with line numbers."""
        test_file = tmp_path / "lines.txt"
        # Write in binary mode to control exact content
        test_file.write_bytes(b"A\nB\nC\n")

        reader = StreamingFileReader(policy)
        result = list(reader.stream_lines_numbered(str(test_file)))

        assert len(result) == 3
        assert [(n, line.strip()) for n, line in result] == [(1, "A"), (2, "B"), (3, "C")]

    def test_stream_lines_numbered_custom_start(self, tmp_path, policy):
        """Can start line numbers from custom value."""
        test_file = tmp_path / "lines.txt"
        # Write in binary mode to control exact content
        test_file.write_bytes(b"A\nB\nC\n")

        reader = StreamingFileReader(policy)
        result = list(reader.stream_lines_numbered(str(test_file), start=10))

        assert len(result) == 3
        assert [(n, line.strip()) for n, line in result] == [(10, "A"), (11, "B"), (12, "C")]

    def test_count_lines(self, tmp_path, policy):
        """Can count lines without loading entire file."""
        test_file = tmp_path / "lines.txt"
        test_file.write_text("A\nB\nC\nD\nE\n", encoding="utf-8")

        reader = StreamingFileReader(policy)
        count = reader.count_lines(str(test_file))

        assert count == 5

    def test_count_lines_empty_file(self, tmp_path, policy):
        """Empty file has zero lines."""
        test_file = tmp_path / "empty.txt"
        test_file.write_text("", encoding="utf-8")

        reader = StreamingFileReader(policy)
        count = reader.count_lines(str(test_file))

        assert count == 0

    def test_get_file_size(self, tmp_path, policy):
        """Can get file size securely."""
        test_file = tmp_path / "sized.txt"
        content = "Hello, World!"
        test_file.write_text(content, encoding="utf-8")

        reader = StreamingFileReader(policy)
        size = reader.get_file_size(str(test_file))

        assert size == len(content.encode("utf-8"))

    def test_stream_with_encoding(self, tmp_path, policy):
        """Can stream with specified encoding."""
        test_file = tmp_path / "unicode.txt"
        content = "Hello, World!"
        test_file.write_text(content, encoding="utf-8")

        reader = StreamingFileReader(policy)
        chunks = list(reader.stream_file(str(test_file), encoding="utf-8"))

        assert "".join(chunks) == content

    def test_stream_handles_unicode(self, tmp_path, policy):
        """Handles unicode replacement for invalid bytes."""
        test_file = tmp_path / "mixed.bin"
        # Mix of valid UTF-8 and invalid bytes
        test_file.write_bytes(b"Hello\xff\xfeWorld")

        reader = StreamingFileReader(policy)
        chunks = list(reader.stream_file(str(test_file)))

        # Should not raise, uses replacement character
        result = "".join(chunks)
        assert "Hello" in result
        assert "World" in result


class TestChunkedProcessor:
    """Test ChunkedProcessor for callback-based processing."""

    @pytest.fixture
    def policy(self, tmp_path):
        """Create a policy allowing access to tmp_path."""
        return FileSystemPolicy(allowed_roots=[str(tmp_path)])

    def test_process_file_chunks(self, tmp_path, policy):
        """Can process file with chunk callback."""
        test_file = tmp_path / "data.txt"
        test_file.write_text("AAABBBCCC", encoding="utf-8")

        processor = ChunkedProcessor(policy, chunk_size=3)

        results = []
        def callback(chunk, index):
            results.append((index, chunk))
            return len(chunk)

        result = processor.process_file(str(test_file), callback)

        assert result["success"] is True
        assert result["data"]["chunks_processed"] == 3
        assert result["data"]["results"] == [3, 3, 3]

    def test_process_file_returns_metadata(self, tmp_path, policy):
        """Returns path in metadata."""
        test_file = tmp_path / "data.txt"
        test_file.write_text("content", encoding="utf-8")

        processor = ChunkedProcessor(policy)
        result = processor.process_file(str(test_file), lambda c, i: None)

        assert result["metadata"]["path"] == str(test_file)

    def test_process_file_filters_none(self, tmp_path, policy):
        """Filters out None results from callback."""
        test_file = tmp_path / "data.txt"
        test_file.write_text("AAABBB", encoding="utf-8")

        processor = ChunkedProcessor(policy, chunk_size=3)

        def callback(chunk, index):
            # Only return result for first chunk
            if index == 0:
                return "first"
            return None

        result = processor.process_file(str(test_file), callback)

        assert result["data"]["results"] == ["first"]

    def test_process_file_handles_error(self, tmp_path, policy):
        """Handles errors from callback."""
        test_file = tmp_path / "data.txt"
        test_file.write_text("content", encoding="utf-8")

        processor = ChunkedProcessor(policy)

        def bad_callback(chunk, index):
            raise ValueError("Processing error")

        result = processor.process_file(str(test_file), bad_callback)

        assert result["success"] is False
        assert "Processing error" in result["error"]

    def test_process_lines(self, tmp_path, policy):
        """Can process file line by line."""
        test_file = tmp_path / "lines.txt"
        test_file.write_text("A\nB\nC\n", encoding="utf-8")

        processor = ChunkedProcessor(policy)

        def callback(line, line_num):
            return f"{line_num}: {line.strip()}"

        result = processor.process_lines(str(test_file), callback)

        assert result["success"] is True
        assert result["data"]["lines_processed"] == 3
        assert result["data"]["results"] == ["1: A", "2: B", "3: C"]

    def test_process_lines_returns_metadata(self, tmp_path, policy):
        """Returns path in metadata for line processing."""
        test_file = tmp_path / "lines.txt"
        test_file.write_text("A\nB\n", encoding="utf-8")

        processor = ChunkedProcessor(policy)
        result = processor.process_lines(str(test_file), lambda l, n: None)

        assert result["metadata"]["path"] == str(test_file)

    def test_process_lines_handles_error(self, tmp_path, policy):
        """Handles errors in line processing."""
        test_file = tmp_path / "lines.txt"
        test_file.write_text("A\nB\n", encoding="utf-8")

        processor = ChunkedProcessor(policy)

        def bad_callback(line, line_num):
            if line_num == 2:
                raise RuntimeError("Line error")
            return line

        result = processor.process_lines(str(test_file), bad_callback)

        assert result["success"] is False
        assert "Line error" in result["error"]

    def test_process_empty_file(self, tmp_path, policy):
        """Handles empty file gracefully."""
        test_file = tmp_path / "empty.txt"
        test_file.write_text("", encoding="utf-8")

        processor = ChunkedProcessor(policy)
        result = processor.process_file(str(test_file), lambda c, i: c)

        assert result["success"] is True
        assert result["data"]["chunks_processed"] == 0
        assert result["data"]["results"] == []


class TestStreamingIntegration:
    """Integration tests for streaming utilities."""

    @pytest.fixture
    def policy(self, tmp_path):
        """Create a policy allowing access to tmp_path."""
        return FileSystemPolicy(allowed_roots=[str(tmp_path)])

    def test_word_count_streaming(self, tmp_path, policy):
        """Can count words using streaming."""
        test_file = tmp_path / "document.txt"
        test_file.write_text("Hello World\nFoo Bar Baz\n", encoding="utf-8")

        processor = ChunkedProcessor(policy)

        def count_words(line, line_num):
            return len(line.split())

        result = processor.process_lines(str(test_file), count_words)

        assert result["success"] is True
        # 2 words in line 1, 3 words in line 2
        assert sum(result["data"]["results"]) == 5

    def test_search_in_large_file(self, tmp_path, policy):
        """Can search in file without loading entirely."""
        test_file = tmp_path / "log.txt"
        # Generate 100 lines, put ERROR on line 50 (1-indexed, so index 49)
        lines = [f"Line {i}: {'ERROR' if i == 49 else 'INFO'}\n" for i in range(100)]
        test_file.write_bytes("".join(lines).encode("utf-8"))

        processor = ChunkedProcessor(policy)

        def find_errors(line, line_num):
            if "ERROR" in line:
                return line_num
            return None

        result = processor.process_lines(str(test_file), find_errors)

        assert result["success"] is True
        # Line numbers are 1-indexed, so line at index 49 is line 50
        assert result["data"]["results"] == [50]

    def test_checksum_streaming(self, tmp_path, policy):
        """Can calculate checksum via streaming."""
        import hashlib

        test_file = tmp_path / "data.bin"
        content = b"Hello, World!" * 100
        test_file.write_bytes(content)

        reader = StreamingFileReader(policy, chunk_size=50)

        hasher = hashlib.md5()
        for chunk in reader.stream_bytes(str(test_file)):
            hasher.update(chunk)

        # Verify against direct calculation
        expected = hashlib.md5(content).hexdigest()
        assert hasher.hexdigest() == expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
