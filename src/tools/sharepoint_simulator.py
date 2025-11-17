"""
SharePoint Simulator for filesystem-based document management.

This module simulates SharePoint functionality using local filesystem:
- Recursive directory traversal
- File metadata extraction
- Version history simulation
- File search capabilities
- Content retrieval
- Permission checking
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class SharePointSimulator:
    """
    Enterprise-grade SharePoint simulator using local filesystem.

    Features:
    - Recursive directory traversal with depth control
    - Comprehensive metadata extraction
    - Version history simulation via timestamps
    - Pattern-based file search
    - Content retrieval with encoding support
    - Permission and access checks
    """

    # Supported file extensions for content extraction
    SUPPORTED_EXTENSIONS = {
        '.txt', '.md', '.json', '.csv', '.log', '.xml',
        '.py', '.js', '.java', '.cpp', '.c', '.h',
        '.html', '.css', '.sql', '.sh', '.yaml', '.yml',
        '.ini', '.cfg', '.conf', '.properties'
    }

    # File type mappings
    FILE_TYPE_MAP = {
        '.pdf': 'PDF Document',
        '.docx': 'Word Document',
        '.doc': 'Word Document',
        '.xlsx': 'Excel Spreadsheet',
        '.xls': 'Excel Spreadsheet',
        '.pptx': 'PowerPoint Presentation',
        '.ppt': 'PowerPoint Presentation',
        '.txt': 'Text File',
        '.md': 'Markdown File',
        '.json': 'JSON File',
        '.xml': 'XML File',
        '.csv': 'CSV File',
        '.py': 'Python Script',
        '.js': 'JavaScript File',
        '.html': 'HTML File',
        '.css': 'CSS File',
        '.log': 'Log File'
    }

    def __init__(self, root_path: Optional[str] = None):
        """
        Initialize SharePoint simulator.

        Args:
            root_path: Root directory for file operations (defaults to cwd)
        """
        self.root_path = Path(root_path) if root_path else Path.cwd()

        if not self.root_path.exists():
            logger.warning(f"Root path does not exist: {self.root_path}")
        elif not self.root_path.is_dir():
            logger.warning(f"Root path is not a directory: {self.root_path}")

        logger.info(f"SharePoint Simulator initialized with root: {self.root_path}")

    def list_files(
        self,
        path: Optional[str] = None,
        max_depth: Optional[int] = None,
        recursive: bool = True
    ) -> List[Dict[str, Any]]:
        """
        List files in directory with optional recursion and depth control.

        Args:
            path: Directory path to list (relative to root or absolute)
            max_depth: Maximum recursion depth (None for unlimited)
            recursive: Whether to recurse into subdirectories

        Returns:
            List of file information dictionaries
        """
        try:
            target_path = self._resolve_path(path)

            if not target_path.exists():
                logger.error(f"Path does not exist: {target_path}")
                return []

            if not target_path.is_dir():
                logger.error(f"Path is not a directory: {target_path}")
                return []

            files = []
            self._traverse_directory(
                target_path,
                files,
                current_depth=0,
                max_depth=max_depth,
                recursive=recursive
            )

            logger.info(f"Listed {len(files)} files from {target_path}")
            return files

        except PermissionError as e:
            logger.error(f"Permission denied accessing {path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error listing files from {path}: {e}")
            return []

    def _traverse_directory(
        self,
        directory: Path,
        files: List[Dict[str, Any]],
        current_depth: int,
        max_depth: Optional[int],
        recursive: bool
    ):
        """
        Recursively traverse directory and collect file information.

        Args:
            directory: Directory to traverse
            files: List to append file information to
            current_depth: Current recursion depth
            max_depth: Maximum depth to traverse
            recursive: Whether to recurse
        """
        try:
            # Check depth limit
            if max_depth is not None and current_depth >= max_depth:
                return

            for item in directory.iterdir():
                try:
                    if item.is_file():
                        file_info = self._get_basic_file_info(item)
                        files.append(file_info)
                    elif item.is_dir() and recursive:
                        # Recurse into subdirectory
                        self._traverse_directory(
                            item,
                            files,
                            current_depth + 1,
                            max_depth,
                            recursive
                        )
                except (PermissionError, OSError) as e:
                    logger.warning(f"Cannot access {item}: {e}")
                    continue

        except PermissionError as e:
            logger.warning(f"Permission denied for directory {directory}: {e}")
        except Exception as e:
            logger.error(f"Error traversing {directory}: {e}")

    def _get_basic_file_info(self, filepath: Path) -> Dict[str, Any]:
        """
        Get basic file information for listing.

        Args:
            filepath: Path to file

        Returns:
            Dictionary with basic file info
        """
        try:
            stat = filepath.stat()
            return {
                'name': filepath.name,
                'path': str(filepath.absolute()),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'type': self._get_file_type(filepath),
                'extension': filepath.suffix.lower()
            }
        except Exception as e:
            logger.error(f"Error getting file info for {filepath}: {e}")
            return {
                'name': filepath.name,
                'path': str(filepath.absolute()),
                'error': str(e)
            }

    def get_file_metadata(self, filepath: str) -> Dict[str, Any]:
        """
        Get comprehensive metadata for a file.

        Args:
            filepath: Path to file (relative to root or absolute)

        Returns:
            Dictionary with file metadata including:
            - modified_date: Last modification timestamp
            - size: File size in bytes
            - type: File type description
            - permissions: File permission information
            - created_date: Creation timestamp (if available)
            - accessed_date: Last access timestamp
            - is_readonly: Whether file is read-only
        """
        try:
            file_path = self._resolve_path(filepath)

            if not file_path.exists():
                logger.error(f"File does not exist: {file_path}")
                return {
                    'error': 'File not found',
                    'path': str(file_path)
                }

            if not file_path.is_file():
                logger.error(f"Path is not a file: {file_path}")
                return {
                    'error': 'Not a file',
                    'path': str(file_path)
                }

            stat = file_path.stat()

            metadata = {
                'name': file_path.name,
                'path': str(file_path.absolute()),
                'size': stat.st_size,
                'size_human': self._format_size(stat.st_size),
                'modified_date': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'created_date': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'accessed_date': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'type': self._get_file_type(file_path),
                'extension': file_path.suffix.lower(),
                'permissions': self._get_permissions(file_path, stat),
                'is_readonly': not os.access(file_path, os.W_OK),
                'is_executable': os.access(file_path, os.X_OK),
                'owner_uid': stat.st_uid,
                'group_gid': stat.st_gid,
                'inode': stat.st_ino
            }

            logger.info(f"Retrieved metadata for {file_path.name}")
            return metadata

        except PermissionError as e:
            logger.error(f"Permission denied for {filepath}: {e}")
            return {
                'error': 'Permission denied',
                'path': filepath
            }
        except Exception as e:
            logger.error(f"Error getting metadata for {filepath}: {e}")
            return {
                'error': str(e),
                'path': filepath
            }

    def get_version_history(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Simulate version history using file timestamps.

        Args:
            filepath: Path to file

        Returns:
            List of version information dictionaries
        """
        try:
            file_path = self._resolve_path(filepath)

            if not file_path.exists():
                logger.error(f"File does not exist: {file_path}")
                return []

            stat = file_path.stat()

            # Simulate versions based on timestamps
            versions = []

            # Current version (most recent)
            versions.append({
                'version': '1.0',
                'timestamp': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'size': stat.st_size,
                'type': 'current',
                'modified_by': f"uid_{stat.st_uid}",
                'comment': 'Current version'
            })

            # Simulated historical version based on creation time
            if stat.st_ctime != stat.st_mtime:
                versions.append({
                    'version': '0.9',
                    'timestamp': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'size': stat.st_size,
                    'type': 'historical',
                    'modified_by': f"uid_{stat.st_uid}",
                    'comment': 'Initial version'
                })

            # Add simulated version based on access time if different
            if stat.st_atime != stat.st_mtime and stat.st_atime != stat.st_ctime:
                # Only add if it's between creation and modification
                if stat.st_ctime < stat.st_atime < stat.st_mtime:
                    versions.insert(1, {
                        'version': '0.95',
                        'timestamp': datetime.fromtimestamp(stat.st_atime).isoformat(),
                        'size': stat.st_size,
                        'type': 'historical',
                        'modified_by': f"uid_{stat.st_uid}",
                        'comment': 'Intermediate version'
                    })

            logger.info(f"Retrieved {len(versions)} version(s) for {file_path.name}")
            return versions

        except Exception as e:
            logger.error(f"Error getting version history for {filepath}: {e}")
            return []

    def search_files(
        self,
        path: Optional[str] = None,
        pattern: str = "*"
    ) -> List[Dict[str, Any]]:
        """
        Search for files matching pattern.

        Args:
            path: Directory to search in (defaults to root)
            pattern: Glob pattern to match files (e.g., "*.txt", "**/*.pdf")

        Returns:
            List of matching file information dictionaries
        """
        try:
            search_path = self._resolve_path(path)

            if not search_path.exists():
                logger.error(f"Search path does not exist: {search_path}")
                return []

            if not search_path.is_dir():
                logger.error(f"Search path is not a directory: {search_path}")
                return []

            # Use glob to find matching files
            matches = []

            # Handle recursive patterns
            if "**" in pattern:
                matched_paths = search_path.glob(pattern)
            else:
                # Non-recursive glob
                matched_paths = search_path.glob(pattern)

            for matched_path in matched_paths:
                if matched_path.is_file():
                    file_info = self._get_basic_file_info(matched_path)
                    matches.append(file_info)

            logger.info(f"Found {len(matches)} files matching '{pattern}' in {search_path}")
            return matches

        except Exception as e:
            logger.error(f"Error searching files with pattern '{pattern}': {e}")
            return []

    def get_file_content(
        self,
        filepath: str,
        encoding: str = 'utf-8'
    ) -> Dict[str, Any]:
        """
        Read and return file content.

        Args:
            filepath: Path to file
            encoding: Text encoding (default: utf-8)

        Returns:
            Dictionary with content and metadata
        """
        try:
            file_path = self._resolve_path(filepath)

            if not file_path.exists():
                logger.error(f"File does not exist: {file_path}")
                return {
                    'error': 'File not found',
                    'path': str(file_path)
                }

            if not file_path.is_file():
                logger.error(f"Path is not a file: {file_path}")
                return {
                    'error': 'Not a file',
                    'path': str(file_path)
                }

            # Check if file type is supported for text reading
            is_text_file = file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS

            result = {
                'name': file_path.name,
                'path': str(file_path.absolute()),
                'size': file_path.stat().st_size,
                'type': self._get_file_type(file_path),
                'is_text': is_text_file
            }

            if is_text_file:
                try:
                    content = file_path.read_text(encoding=encoding)
                    result['content'] = content
                    result['lines'] = len(content.splitlines())
                    result['encoding'] = encoding
                    logger.info(f"Read {result['lines']} lines from {file_path.name}")
                except UnicodeDecodeError as e:
                    logger.warning(f"Unicode decode error for {file_path}: {e}")
                    result['error'] = 'Encoding error'
                    result['content'] = None
            else:
                # Binary file
                result['content'] = None
                result['message'] = 'Binary file - content not extracted'
                logger.info(f"Binary file detected: {file_path.name}")

            return result

        except PermissionError as e:
            logger.error(f"Permission denied reading {filepath}: {e}")
            return {
                'error': 'Permission denied',
                'path': filepath
            }
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {e}")
            return {
                'error': str(e),
                'path': filepath
            }

    def _resolve_path(self, path: Optional[str]) -> Path:
        """
        Resolve path relative to root or as absolute.

        Args:
            path: Path string (None defaults to root)

        Returns:
            Resolved Path object
        """
        if path is None:
            return self.root_path

        path_obj = Path(path)

        if path_obj.is_absolute():
            return path_obj
        else:
            return self.root_path / path_obj

    def _get_file_type(self, filepath: Path) -> str:
        """
        Get human-readable file type.

        Args:
            filepath: Path to file

        Returns:
            File type description
        """
        extension = filepath.suffix.lower()
        return self.FILE_TYPE_MAP.get(extension, f"{extension.upper()[1:]} File" if extension else "Unknown")

    def _get_permissions(self, filepath: Path, stat_result) -> Dict[str, Any]:
        """
        Extract permission information from stat result.

        Args:
            filepath: Path to the file
            stat_result: os.stat_result object

        Returns:
            Dictionary with permission details
        """
        mode = stat_result.st_mode

        return {
            'octal': oct(mode)[-3:],
            'readable': os.access(filepath, os.R_OK),
            'writable': bool(mode & 0o200),
            'executable': bool(mode & 0o100),
            'mode': mode
        }

    def _format_size(self, size_bytes: int) -> str:
        """
        Format file size in human-readable format.

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def get_directory_info(self, path: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive directory information.

        Args:
            path: Directory path (defaults to root)

        Returns:
            Dictionary with directory statistics
        """
        try:
            dir_path = self._resolve_path(path)

            if not dir_path.exists():
                return {
                    'error': 'Directory not found',
                    'path': str(dir_path)
                }

            if not dir_path.is_dir():
                return {
                    'error': 'Not a directory',
                    'path': str(dir_path)
                }

            # Collect statistics
            total_files = 0
            total_dirs = 0
            total_size = 0
            file_types = {}

            for item in dir_path.rglob('*'):
                try:
                    if item.is_file():
                        total_files += 1
                        size = item.stat().st_size
                        total_size += size

                        file_type = self._get_file_type(item)
                        file_types[file_type] = file_types.get(file_type, 0) + 1
                    elif item.is_dir():
                        total_dirs += 1
                except (PermissionError, OSError):
                    continue

            return {
                'path': str(dir_path.absolute()),
                'name': dir_path.name,
                'total_files': total_files,
                'total_directories': total_dirs,
                'total_size': total_size,
                'total_size_human': self._format_size(total_size),
                'file_types': file_types,
                'exists': True
            }

        except Exception as e:
            logger.error(f"Error getting directory info for {path}: {e}")
            return {
                'error': str(e),
                'path': path
            }

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get simulator statistics.

        Returns:
            Dictionary with simulator information
        """
        return {
            'root_path': str(self.root_path.absolute()),
            'root_exists': self.root_path.exists(),
            'root_is_directory': self.root_path.is_dir() if self.root_path.exists() else False,
            'supported_extensions': sorted(self.SUPPORTED_EXTENSIONS),
            'supported_extension_count': len(self.SUPPORTED_EXTENSIONS)
        }
