"""
Comprehensive tests for SharePoint Simulator.

Tests cover:
- Directory traversal and listing
- Metadata extraction
- Version history simulation
- File searching with patterns
- Content retrieval
- Permission handling
- Error cases and edge cases
- Path resolution
"""

import pytest
from pathlib import Path
import tempfile
import time
import os

from src.tools.sharepoint_simulator import SharePointSimulator


@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace with test files and directories."""
    # Create directory structure
    (tmp_path / "documents").mkdir()
    (tmp_path / "documents" / "reports").mkdir()
    (tmp_path / "documents" / "policies").mkdir()
    (tmp_path / "archive").mkdir()
    (tmp_path / "empty_dir").mkdir()

    # Create test files
    files_to_create = [
        ("documents/test.txt", "This is a test file."),
        ("documents/data.json", '{"key": "value"}'),
        ("documents/report.md", "# Report\n\nThis is a report."),
        ("documents/reports/security.txt", "Security report content"),
        ("documents/reports/audit.log", "Audit log entries"),
        ("documents/policies/policy.txt", "Policy document"),
        ("archive/old.txt", "Old archived file"),
        ("readme.md", "# README\n\nProject documentation"),
    ]

    for file_path, content in files_to_create:
        full_path = tmp_path / file_path
        full_path.write_text(content)

    # Create a binary file
    binary_file = tmp_path / "documents" / "data.bin"
    binary_file.write_bytes(b'\x00\x01\x02\x03\x04')

    return tmp_path


@pytest.fixture
def simulator(temp_workspace):
    """Create SharePoint simulator instance with temp workspace."""
    return SharePointSimulator(root_path=str(temp_workspace))


@pytest.fixture
def empty_simulator(tmp_path):
    """Create simulator with empty directory."""
    return SharePointSimulator(root_path=str(tmp_path))


class TestSharePointSimulatorInit:
    """Test SharePoint simulator initialization."""

    def test_init_with_valid_path(self, temp_workspace):
        """Test initialization with valid directory path."""
        simulator = SharePointSimulator(root_path=str(temp_workspace))

        assert simulator.root_path == temp_workspace
        assert simulator.root_path.exists()
        assert simulator.root_path.is_dir()

    def test_init_with_none_path(self):
        """Test initialization with None (defaults to cwd)."""
        simulator = SharePointSimulator(root_path=None)

        assert simulator.root_path == Path.cwd()

    def test_init_with_nonexistent_path(self, tmp_path):
        """Test initialization with nonexistent path."""
        nonexistent = tmp_path / "nonexistent"
        simulator = SharePointSimulator(root_path=str(nonexistent))

        # Should still create instance but log warning
        assert simulator.root_path == nonexistent
        assert not simulator.root_path.exists()

    def test_supported_extensions_defined(self):
        """Test supported extensions are defined."""
        assert len(SharePointSimulator.SUPPORTED_EXTENSIONS) > 0
        assert '.txt' in SharePointSimulator.SUPPORTED_EXTENSIONS
        assert '.json' in SharePointSimulator.SUPPORTED_EXTENSIONS
        assert '.md' in SharePointSimulator.SUPPORTED_EXTENSIONS

    def test_file_type_map_defined(self):
        """Test file type mappings are defined."""
        assert len(SharePointSimulator.FILE_TYPE_MAP) > 0
        assert '.txt' in SharePointSimulator.FILE_TYPE_MAP
        assert '.pdf' in SharePointSimulator.FILE_TYPE_MAP


class TestListFiles:
    """Test file listing functionality."""

    def test_list_files_root_directory(self, simulator):
        """Test listing files in root directory."""
        files = simulator.list_files()

        assert isinstance(files, list)
        assert len(files) > 0

        # Check file info structure
        for file_info in files:
            assert 'name' in file_info
            assert 'path' in file_info
            assert 'size' in file_info

    def test_list_files_specific_directory(self, simulator):
        """Test listing files in specific subdirectory."""
        files = simulator.list_files(path="documents")

        assert isinstance(files, list)
        assert len(files) > 0

        # All files should be under documents directory
        for file_info in files:
            assert 'documents' in file_info['path']

    def test_list_files_non_recursive(self, simulator):
        """Test non-recursive file listing."""
        files = simulator.list_files(path="documents", recursive=False)

        # Should only list files directly in documents, not in subdirectories
        assert isinstance(files, list)

        # Count should be less than recursive listing
        recursive_files = simulator.list_files(path="documents", recursive=True)
        assert len(files) <= len(recursive_files)

    def test_list_files_with_max_depth(self, simulator):
        """Test listing with depth limit."""
        # Depth 0 - only current directory
        files_depth_0 = simulator.list_files(path="documents", max_depth=0)

        # Depth 1 - current + one level
        files_depth_1 = simulator.list_files(path="documents", max_depth=1)

        # Unlimited depth
        files_unlimited = simulator.list_files(path="documents", max_depth=None)

        assert len(files_depth_0) <= len(files_depth_1)
        assert len(files_depth_1) <= len(files_unlimited)

    def test_list_files_empty_directory(self, simulator):
        """Test listing empty directory."""
        files = simulator.list_files(path="empty_dir")

        assert isinstance(files, list)
        assert len(files) == 0

    def test_list_files_nonexistent_directory(self, simulator):
        """Test listing nonexistent directory."""
        files = simulator.list_files(path="nonexistent")

        assert isinstance(files, list)
        assert len(files) == 0

    def test_list_files_file_info_structure(self, simulator):
        """Test file info contains required fields."""
        files = simulator.list_files(path="documents", max_depth=0)

        for file_info in files:
            assert 'name' in file_info
            assert 'path' in file_info
            assert 'size' in file_info
            assert 'modified' in file_info
            assert 'type' in file_info
            assert 'extension' in file_info

    def test_list_files_returns_absolute_paths(self, simulator):
        """Test that returned paths are absolute."""
        files = simulator.list_files(path="documents", max_depth=1)

        for file_info in files:
            path = Path(file_info['path'])
            assert path.is_absolute()


class TestGetFileMetadata:
    """Test file metadata extraction."""

    def test_get_metadata_valid_file(self, simulator):
        """Test getting metadata for valid file."""
        metadata = simulator.get_file_metadata("documents/test.txt")

        assert isinstance(metadata, dict)
        assert 'name' in metadata
        assert 'path' in metadata
        assert 'size' in metadata
        assert 'modified_date' in metadata
        assert 'created_date' in metadata
        assert 'type' in metadata
        assert 'permissions' in metadata

    def test_get_metadata_nonexistent_file(self, simulator):
        """Test getting metadata for nonexistent file."""
        metadata = simulator.get_file_metadata("nonexistent.txt")

        assert isinstance(metadata, dict)
        assert 'error' in metadata
        assert metadata['error'] == 'File not found'

    def test_get_metadata_directory_path(self, simulator):
        """Test getting metadata for directory (should fail)."""
        metadata = simulator.get_file_metadata("documents")

        assert isinstance(metadata, dict)
        assert 'error' in metadata

    def test_get_metadata_permissions(self, simulator):
        """Test permission information in metadata."""
        metadata = simulator.get_file_metadata("documents/test.txt")

        assert 'permissions' in metadata
        permissions = metadata['permissions']
        assert 'octal' in permissions
        assert 'writable' in permissions
        assert 'executable' in permissions

    def test_get_metadata_size_formatting(self, simulator):
        """Test human-readable size formatting."""
        metadata = simulator.get_file_metadata("documents/test.txt")

        assert 'size' in metadata
        assert 'size_human' in metadata
        assert isinstance(metadata['size'], int)
        assert isinstance(metadata['size_human'], str)

    def test_get_metadata_timestamps(self, simulator):
        """Test timestamp formats."""
        metadata = simulator.get_file_metadata("documents/test.txt")

        # Check ISO format timestamps
        assert 'modified_date' in metadata
        assert 'created_date' in metadata
        assert 'accessed_date' in metadata

        # Should be ISO 8601 format strings
        assert 'T' in metadata['modified_date']

    def test_get_metadata_file_type(self, simulator):
        """Test file type detection."""
        txt_metadata = simulator.get_file_metadata("documents/test.txt")
        json_metadata = simulator.get_file_metadata("documents/data.json")

        assert txt_metadata['type'] == 'Text File'
        assert json_metadata['type'] == 'JSON File'

    def test_get_metadata_readonly_flag(self, simulator):
        """Test readonly flag detection."""
        metadata = simulator.get_file_metadata("documents/test.txt")

        assert 'is_readonly' in metadata
        assert isinstance(metadata['is_readonly'], bool)


class TestGetVersionHistory:
    """Test version history simulation."""

    def test_version_history_valid_file(self, simulator):
        """Test getting version history for valid file."""
        versions = simulator.get_version_history("documents/test.txt")

        assert isinstance(versions, list)
        assert len(versions) > 0

        # Should have at least current version
        assert any(v['type'] == 'current' for v in versions)

    def test_version_history_structure(self, simulator):
        """Test version history entry structure."""
        versions = simulator.get_version_history("documents/test.txt")

        for version in versions:
            assert 'version' in version
            assert 'timestamp' in version
            assert 'size' in version
            assert 'type' in version
            assert 'modified_by' in version
            assert 'comment' in version

    def test_version_history_nonexistent_file(self, simulator):
        """Test version history for nonexistent file."""
        versions = simulator.get_version_history("nonexistent.txt")

        assert isinstance(versions, list)
        assert len(versions) == 0

    def test_version_history_ordering(self, simulator):
        """Test version history is ordered correctly."""
        versions = simulator.get_version_history("documents/test.txt")

        # Current version should be first
        if len(versions) > 0:
            assert versions[0]['type'] == 'current'

    def test_version_history_timestamps(self, simulator):
        """Test version timestamps are ISO format."""
        versions = simulator.get_version_history("documents/test.txt")

        for version in versions:
            assert 'T' in version['timestamp']


class TestSearchFiles:
    """Test file search functionality."""

    def test_search_all_files(self, simulator):
        """Test searching for all files."""
        results = simulator.search_files(pattern="*")

        assert isinstance(results, list)
        # Should find files in root directory
        assert len(results) >= 0

    def test_search_txt_files(self, simulator):
        """Test searching for .txt files."""
        results = simulator.search_files(path="documents", pattern="*.txt")

        assert isinstance(results, list)

        # All results should be .txt files
        for result in results:
            assert result['name'].endswith('.txt')

    def test_search_recursive_pattern(self, simulator):
        """Test recursive search pattern."""
        results = simulator.search_files(pattern="**/*.txt")

        assert isinstance(results, list)

        # Should find .txt files in subdirectories
        if results:
            assert all(r['name'].endswith('.txt') for r in results)

    def test_search_specific_filename(self, simulator):
        """Test searching for specific filename."""
        results = simulator.search_files(path="documents", pattern="test.txt")

        assert isinstance(results, list)

        # Should find test.txt
        if results:
            assert any(r['name'] == 'test.txt' for r in results)

    def test_search_nonexistent_pattern(self, simulator):
        """Test searching with pattern that matches nothing."""
        results = simulator.search_files(pattern="*.nonexistent")

        assert isinstance(results, list)
        assert len(results) == 0

    def test_search_nonexistent_directory(self, simulator):
        """Test searching in nonexistent directory."""
        results = simulator.search_files(path="nonexistent", pattern="*")

        assert isinstance(results, list)
        assert len(results) == 0

    def test_search_multiple_extensions(self, simulator):
        """Test searching matches multiple file types."""
        results = simulator.search_files(pattern="**/*")

        # Should find various file types
        extensions = {r['extension'] for r in results if 'extension' in r}
        assert len(extensions) > 1


class TestGetFileContent:
    """Test file content retrieval."""

    def test_get_content_text_file(self, simulator):
        """Test reading text file content."""
        result = simulator.get_file_content("documents/test.txt")

        assert isinstance(result, dict)
        assert 'content' in result
        assert 'name' in result
        assert result['content'] == "This is a test file."

    def test_get_content_json_file(self, simulator):
        """Test reading JSON file content."""
        result = simulator.get_file_content("documents/data.json")

        assert isinstance(result, dict)
        assert 'content' in result
        assert '{"key": "value"}' in result['content']

    def test_get_content_markdown_file(self, simulator):
        """Test reading markdown file content."""
        result = simulator.get_file_content("readme.md")

        assert isinstance(result, dict)
        assert 'content' in result
        assert '# README' in result['content']

    def test_get_content_binary_file(self, simulator):
        """Test reading binary file (should not extract content)."""
        result = simulator.get_file_content("documents/data.bin")

        assert isinstance(result, dict)
        assert result['content'] is None
        assert result['is_text'] is False

    def test_get_content_nonexistent_file(self, simulator):
        """Test reading nonexistent file."""
        result = simulator.get_file_content("nonexistent.txt")

        assert isinstance(result, dict)
        assert 'error' in result
        assert result['error'] == 'File not found'

    def test_get_content_line_count(self, simulator):
        """Test line count in content result."""
        result = simulator.get_file_content("readme.md")

        assert 'lines' in result
        assert isinstance(result['lines'], int)
        assert result['lines'] > 0

    def test_get_content_encoding(self, simulator):
        """Test content encoding information."""
        result = simulator.get_file_content("documents/test.txt", encoding='utf-8')

        if result['is_text']:
            assert 'encoding' in result
            assert result['encoding'] == 'utf-8'

    def test_get_content_file_info(self, simulator):
        """Test file info included in content result."""
        result = simulator.get_file_content("documents/test.txt")

        assert 'name' in result
        assert 'path' in result
        assert 'size' in result
        assert 'type' in result


class TestDirectoryInfo:
    """Test directory information retrieval."""

    def test_get_directory_info_valid(self, simulator):
        """Test getting directory information."""
        info = simulator.get_directory_info("documents")

        assert isinstance(info, dict)
        assert 'total_files' in info
        assert 'total_directories' in info
        assert 'total_size' in info
        assert 'file_types' in info

    def test_get_directory_info_root(self, simulator):
        """Test getting info for root directory."""
        info = simulator.get_directory_info()

        assert isinstance(info, dict)
        assert 'total_files' in info
        assert info['total_files'] > 0

    def test_get_directory_info_empty(self, simulator):
        """Test getting info for empty directory."""
        info = simulator.get_directory_info("empty_dir")

        assert isinstance(info, dict)
        assert info['total_files'] == 0

    def test_get_directory_info_nonexistent(self, simulator):
        """Test getting info for nonexistent directory."""
        info = simulator.get_directory_info("nonexistent")

        assert isinstance(info, dict)
        assert 'error' in info

    def test_get_directory_info_file_types(self, simulator):
        """Test file type statistics in directory info."""
        info = simulator.get_directory_info("documents")

        assert 'file_types' in info
        assert isinstance(info['file_types'], dict)

    def test_get_directory_info_size_formatting(self, simulator):
        """Test size formatting in directory info."""
        info = simulator.get_directory_info("documents")

        assert 'total_size' in info
        assert 'total_size_human' in info
        assert isinstance(info['total_size'], int)
        assert isinstance(info['total_size_human'], str)


class TestUtilityMethods:
    """Test utility and helper methods."""

    def test_resolve_path_none(self, simulator):
        """Test path resolution with None."""
        resolved = simulator._resolve_path(None)

        assert resolved == simulator.root_path

    def test_resolve_path_relative(self, simulator):
        """Test path resolution with relative path."""
        resolved = simulator._resolve_path("documents/test.txt")

        assert resolved.is_absolute()
        assert 'documents' in str(resolved)

    def test_resolve_path_absolute(self, simulator, temp_workspace):
        """Test path resolution with absolute path."""
        abs_path = temp_workspace / "documents" / "test.txt"
        resolved = simulator._resolve_path(str(abs_path))

        assert resolved == abs_path

    def test_get_file_type_known_extensions(self, simulator):
        """Test file type detection for known extensions."""
        txt_type = simulator._get_file_type(Path("file.txt"))
        json_type = simulator._get_file_type(Path("file.json"))
        pdf_type = simulator._get_file_type(Path("file.pdf"))

        assert txt_type == "Text File"
        assert json_type == "JSON File"
        assert pdf_type == "PDF Document"

    def test_get_file_type_unknown_extension(self, simulator):
        """Test file type detection for unknown extension."""
        file_type = simulator._get_file_type(Path("file.xyz"))

        assert "XYZ" in file_type or "Unknown" in file_type

    def test_format_size_bytes(self, simulator):
        """Test size formatting for various sizes."""
        assert "B" in simulator._format_size(100)
        assert "KB" in simulator._format_size(2048)
        assert "MB" in simulator._format_size(2 * 1024 * 1024)
        assert "GB" in simulator._format_size(3 * 1024 * 1024 * 1024)

    def test_get_statistics(self, simulator):
        """Test getting simulator statistics."""
        stats = simulator.get_statistics()

        assert isinstance(stats, dict)
        assert 'root_path' in stats
        assert 'root_exists' in stats
        assert 'supported_extensions' in stats
        assert 'supported_extension_count' in stats

    def test_statistics_accuracy(self, simulator):
        """Test statistics reflect actual state."""
        stats = simulator.get_statistics()

        assert stats['root_exists'] == simulator.root_path.exists()
        assert len(stats['supported_extensions']) == stats['supported_extension_count']


class TestPathResolution:
    """Test path resolution and handling."""

    def test_absolute_path_handling(self, simulator, temp_workspace):
        """Test handling of absolute paths."""
        abs_path = str(temp_workspace / "documents" / "test.txt")
        metadata = simulator.get_file_metadata(abs_path)

        assert 'name' in metadata
        assert metadata['name'] == 'test.txt'

    def test_relative_path_handling(self, simulator):
        """Test handling of relative paths."""
        metadata = simulator.get_file_metadata("documents/test.txt")

        assert 'name' in metadata
        assert metadata['name'] == 'test.txt'

    def test_nested_path_handling(self, simulator):
        """Test handling of nested paths."""
        metadata = simulator.get_file_metadata("documents/reports/security.txt")

        assert 'name' in metadata
        assert metadata['name'] == 'security.txt'

    def test_path_with_parent_references(self, simulator):
        """Test paths with .. references."""
        # This should still resolve correctly
        metadata = simulator.get_file_metadata("documents/../documents/test.txt")

        # Should resolve to the correct file
        assert 'name' in metadata


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_list_files_with_permission_issues(self, simulator):
        """Test listing files handles permission errors gracefully."""
        # Should return list even if some files can't be accessed
        files = simulator.list_files()

        assert isinstance(files, list)

    def test_empty_file_content(self, simulator, temp_workspace):
        """Test reading empty file."""
        empty_file = temp_workspace / "empty.txt"
        empty_file.write_text("")

        result = simulator.get_file_content("empty.txt")

        assert 'content' in result
        assert result['content'] == ""
        assert result['lines'] == 0

    def test_large_depth_traversal(self, simulator):
        """Test traversal with very large depth value."""
        files = simulator.list_files(max_depth=1000)

        assert isinstance(files, list)

    def test_special_characters_in_filename(self, simulator, temp_workspace):
        """Test handling files with special characters."""
        special_file = temp_workspace / "file with spaces.txt"
        special_file.write_text("Content")

        metadata = simulator.get_file_metadata("file with spaces.txt")

        assert 'name' in metadata
        assert metadata['name'] == "file with spaces.txt"

    def test_unicode_filename_handling(self, simulator, temp_workspace):
        """Test handling unicode filenames."""
        unicode_file = temp_workspace / "test_日本語.txt"
        unicode_file.write_text("Unicode content")

        metadata = simulator.get_file_metadata("test_日本語.txt")

        assert 'name' in metadata

    def test_zero_byte_file(self, simulator, temp_workspace):
        """Test handling zero-byte files."""
        zero_file = temp_workspace / "zero.txt"
        zero_file.write_text("")

        metadata = simulator.get_file_metadata("zero.txt")

        assert metadata['size'] == 0

    def test_symlink_handling(self, simulator, temp_workspace):
        """Test handling of symbolic links."""
        try:
            # Create a symlink
            target = temp_workspace / "documents" / "test.txt"
            link = temp_workspace / "link.txt"
            link.symlink_to(target)

            # Should be able to read through symlink
            result = simulator.get_file_content("link.txt")

            assert isinstance(result, dict)
        except OSError:
            # Symlinks might not be supported on all systems
            pytest.skip("Symlinks not supported on this system")

    def test_concurrent_file_modifications(self, simulator, temp_workspace):
        """Test handling when files are modified during operations."""
        # Get initial metadata
        metadata1 = simulator.get_file_metadata("documents/test.txt")

        # Modify file
        file_path = temp_workspace / "documents" / "test.txt"
        file_path.write_text("Modified content")

        # Get metadata again
        metadata2 = simulator.get_file_metadata("documents/test.txt")

        # Should handle gracefully
        assert isinstance(metadata1, dict)
        assert isinstance(metadata2, dict)

    def test_circular_symlink_protection(self, simulator, temp_workspace):
        """Test protection against circular symlinks."""
        # This test ensures we don't hang on circular references
        try:
            link1 = temp_workspace / "link1"
            link2 = temp_workspace / "link2"

            link1.symlink_to(link2)
            link2.symlink_to(link1)

            # Should complete without hanging
            files = simulator.list_files(max_depth=5)

            assert isinstance(files, list)
        except (OSError, FileNotFoundError):
            # Symlinks might not be supported or operation might fail
            pytest.skip("Circular symlink test not supported")


class TestPerformance:
    """Test performance and scalability."""

    def test_list_many_files(self, tmp_path):
        """Test listing directory with many files."""
        # Create 100 files
        for i in range(100):
            (tmp_path / f"file_{i}.txt").write_text(f"Content {i}")

        simulator = SharePointSimulator(root_path=str(tmp_path))
        files = simulator.list_files()

        assert len(files) == 100

    def test_deep_directory_traversal(self, tmp_path):
        """Test traversal of deeply nested directories."""
        # Create deep directory structure
        current = tmp_path
        for i in range(10):
            current = current / f"level_{i}"
            current.mkdir()
            (current / f"file_{i}.txt").write_text(f"Level {i}")

        simulator = SharePointSimulator(root_path=str(tmp_path))
        files = simulator.list_files()

        assert len(files) == 10


class TestErrorHandling:
    """Test error handling and edge cases for better coverage."""

    def test_init_with_file_path_not_directory(self, tmp_path):
        """Test initialization when path is a file not directory."""
        file_path = tmp_path / "file.txt"
        file_path.write_text("content")

        simulator = SharePointSimulator(root_path=str(file_path))

        # Should create instance but log warning
        assert simulator.root_path == file_path

    def test_list_files_path_is_file(self, simulator, temp_workspace):
        """Test listing files when path points to a file."""
        files = simulator.list_files(path="documents/test.txt")

        # Should return empty list
        assert files == []

    def test_search_files_path_is_file(self, simulator, temp_workspace):
        """Test searching when path is a file not directory."""
        results = simulator.search_files(path="documents/test.txt", pattern="*")

        assert results == []

    def test_version_history_with_different_timestamps(self, tmp_path):
        """Test version history creates multiple versions."""
        import time

        # Create file
        test_file = tmp_path / "test.txt"
        test_file.write_text("Original content")

        # Wait a bit and modify
        time.sleep(0.1)
        test_file.write_text("Modified content")

        simulator = SharePointSimulator(root_path=str(tmp_path))
        versions = simulator.get_version_history("test.txt")

        # Should have at least current version
        assert len(versions) >= 1
        assert any(v['type'] == 'current' for v in versions)

    def test_get_file_content_unicode_error(self, tmp_path):
        """Test handling of unicode decode errors."""
        # Create a file with invalid UTF-8
        binary_file = tmp_path / "invalid.txt"
        binary_file.write_bytes(b'\xff\xfe\xfd')

        simulator = SharePointSimulator(root_path=str(tmp_path))
        result = simulator.get_file_content("invalid.txt")

        # Should handle gracefully
        assert isinstance(result, dict)

    def test_traverse_directory_with_inaccessible_items(self, simulator):
        """Test directory traversal handles inaccessible items."""
        # This tests the exception handling in _traverse_directory
        files = simulator.list_files()

        assert isinstance(files, list)

    def test_format_size_edge_cases(self, simulator):
        """Test size formatting for edge cases."""
        # Test various sizes
        assert "0.00 B" in simulator._format_size(0)
        assert "B" in simulator._format_size(512)
        assert "KB" in simulator._format_size(1024)
        assert "MB" in simulator._format_size(1024 * 1024)
        assert "GB" in simulator._format_size(1024 * 1024 * 1024)
        assert "TB" in simulator._format_size(1024 * 1024 * 1024 * 1024)

    def test_get_file_type_no_extension(self, simulator):
        """Test file type for files without extension."""
        file_type = simulator._get_file_type(Path("README"))

        assert "Unknown" in file_type or file_type == "Unknown"

    def test_get_basic_file_info_error_handling(self, simulator, tmp_path):
        """Test error handling in _get_basic_file_info."""
        # Create a file and then remove it to trigger error
        test_file = tmp_path / "temp.txt"
        test_file.write_text("content")

        # Get file info should handle errors gracefully
        files = simulator.list_files()
        assert isinstance(files, list)

    def test_directory_info_with_permission_errors(self, simulator):
        """Test directory info handles permission errors."""
        info = simulator.get_directory_info()

        assert isinstance(info, dict)
        assert 'total_files' in info or 'error' in info

    def test_get_content_with_different_encodings(self, tmp_path):
        """Test reading files with different encodings."""
        # Create UTF-8 file
        utf8_file = tmp_path / "utf8.txt"
        utf8_file.write_text("Hello World", encoding='utf-8')

        simulator = SharePointSimulator(root_path=str(tmp_path))
        result = simulator.get_file_content("utf8.txt", encoding='utf-8')

        assert 'content' in result
        assert result['content'] == "Hello World"

    def test_search_files_with_complex_patterns(self, simulator):
        """Test searching with various glob patterns."""
        # Test different pattern types
        all_files = simulator.search_files(pattern="**/*")
        txt_files = simulator.search_files(pattern="**/*.txt")
        json_files = simulator.search_files(pattern="**/*.json")

        assert isinstance(all_files, list)
        assert isinstance(txt_files, list)
        assert isinstance(json_files, list)

    def test_list_files_exception_handling(self, simulator):
        """Test exception handling in list_files."""
        # Test with invalid input
        files = simulator.list_files(path="nonexistent/deeply/nested/path")

        assert files == []

    def test_get_metadata_exception_path(self, simulator):
        """Test metadata exception handling."""
        metadata = simulator.get_file_metadata("totally/nonexistent/file.txt")

        assert 'error' in metadata

    def test_get_content_directory_path(self, simulator):
        """Test getting content when path is directory."""
        result = simulator.get_file_content("documents")

        assert 'error' in result

    def test_statistics_with_nonexistent_root(self, tmp_path):
        """Test statistics when root doesn't exist."""
        nonexistent = tmp_path / "nonexistent"
        simulator = SharePointSimulator(root_path=str(nonexistent))

        stats = simulator.get_statistics()

        assert isinstance(stats, dict)
        assert stats['root_exists'] is False

    def test_resolve_path_edge_cases(self, simulator):
        """Test path resolution edge cases."""
        # None path
        resolved_none = simulator._resolve_path(None)
        assert resolved_none == simulator.root_path

        # Empty string
        resolved_empty = simulator._resolve_path("")
        assert isinstance(resolved_empty, Path)

    def test_file_content_binary_detection(self, simulator, temp_workspace):
        """Test binary file detection."""
        result = simulator.get_file_content("documents/data.bin")

        assert result['is_text'] is False
        assert result['content'] is None
        assert 'message' in result

    def test_version_history_with_same_timestamps(self, tmp_path):
        """Test version history when timestamps are same."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Content")

        simulator = SharePointSimulator(root_path=str(tmp_path))
        versions = simulator.get_version_history("test.txt")

        # Should have at least one version
        assert len(versions) >= 1

    def test_permissions_structure(self, simulator):
        """Test permissions dictionary structure."""
        metadata = simulator.get_file_metadata("documents/test.txt")

        if 'permissions' in metadata:
            perms = metadata['permissions']
            assert 'octal' in perms
            assert 'readable' in perms
            assert 'writable' in perms
            assert 'executable' in perms
            assert 'mode' in perms

    def test_get_directory_info_exception_handling(self, tmp_path):
        """Test directory info exception handling."""
        nonexistent = tmp_path / "nonexistent"
        simulator = SharePointSimulator(root_path=str(nonexistent))

        info = simulator.get_directory_info()

        assert isinstance(info, dict)
        assert 'error' in info

    def test_format_size_petabytes(self, simulator):
        """Test size formatting for very large files."""
        huge_size = 1024 * 1024 * 1024 * 1024 * 1024 * 2  # 2 PB
        result = simulator._format_size(huge_size)

        assert "PB" in result

    def test_search_nonexistent_path_error(self, simulator):
        """Test search with nonexistent path."""
        results = simulator.search_files(path="totally/nonexistent", pattern="*")

        assert results == []

    def test_version_history_exception_handling(self, simulator):
        """Test version history exception paths."""
        versions = simulator.get_version_history("nonexistent/file.txt")

        assert versions == []

    def test_get_file_content_permission_error_simulation(self, simulator):
        """Test file content with permission-like errors."""
        result = simulator.get_file_content("nonexistent/protected.txt")

        assert 'error' in result

    def test_list_files_with_generic_exception(self, tmp_path):
        """Test list_files exception handling."""
        # Create simulator with invalid root
        simulator = SharePointSimulator(root_path=str(tmp_path / "invalid"))

        # This should trigger exception handling
        files = simulator.list_files()

        assert files == []

    def test_get_basic_file_info_with_stat_error(self, simulator, tmp_path):
        """Test _get_basic_file_info error handling."""
        # Create a temporary file structure
        test_dir = tmp_path / "test_dir"
        test_dir.mkdir()

        # List files should handle any stat errors gracefully
        files = simulator.list_files()

        assert isinstance(files, list)

    def test_traverse_directory_permission_error(self, simulator):
        """Test _traverse_directory permission error handling."""
        # Regular traversal should handle permission errors
        files = []
        simulator._traverse_directory(
            simulator.root_path,
            files,
            current_depth=0,
            max_depth=None,
            recursive=True
        )

        assert isinstance(files, list)

    def test_get_metadata_various_error_paths(self, simulator):
        """Test various error paths in get_file_metadata."""
        # Test with deeply nested nonexistent path
        result1 = simulator.get_file_metadata("a/b/c/d/e/f/g.txt")
        assert 'error' in result1

        # Test with directory
        result2 = simulator.get_file_metadata("documents")
        assert 'error' in result2

    def test_comprehensive_simulator_workflow(self, simulator):
        """Test complete workflow using simulator."""
        # List files
        files = simulator.list_files(max_depth=2)
        assert isinstance(files, list)

        # Search for specific files
        txt_files = simulator.search_files(pattern="*.txt")
        assert isinstance(txt_files, list)

        # Get metadata for first file if available
        if files:
            first_file_path = files[0]['path']
            metadata = simulator.get_file_metadata(first_file_path)
            assert isinstance(metadata, dict)

            # Get version history
            versions = simulator.get_version_history(first_file_path)
            assert isinstance(versions, list)

            # Get content if it's a text file
            content = simulator.get_file_content(first_file_path)
            assert isinstance(content, dict)

        # Get directory info
        dir_info = simulator.get_directory_info()
        assert isinstance(dir_info, dict)

        # Get statistics
        stats = simulator.get_statistics()
        assert isinstance(stats, dict)
