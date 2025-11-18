"""Filesystem scanner for discovering security controls in documentation.

This scanner searches local directories and files for security control references
and extracts structured control metadata from various document formats.
"""

import os
import re
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime
import mimetypes

logger = logging.getLogger(__name__)


class FilesystemControlScanner:
    """Scanner for discovering security controls in filesystem documents.

    Scans directories for control documentation in various formats (MD, TXT, DOCX)
    and extracts structured control references using regex patterns.
    """

    def __init__(self):
        """Initialize filesystem control scanner."""
        self.supported_extensions = [".md", ".txt", ".docx", ".doc", ".pdf"]

        # Regex patterns for different control frameworks
        self.control_patterns = {
            "NIST SP 800-53": re.compile(
                r"NIST\s+(AC|AU|AT|CA|CM|CP|IA|IR|MA|MP|PE|PL|PS|RA|SA|SC|SI|SR|PM)-(\d+)",
                re.IGNORECASE
            ),
            "CIS Controls v8": re.compile(
                r"CIS\s+(\d+)\.(\d+)",
                re.IGNORECASE
            ),
            "ISO 27001:2022": re.compile(
                r"ISO\s+A\.(\d+)\.(\d+)",
                re.IGNORECASE
            ),
        }

        logger.info("Filesystem control scanner initialized")

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        patterns: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan directory for control documentation files.

        Args:
            path: Directory path to scan
            recursive: If True, scan subdirectories recursively
            patterns: File name patterns to match (e.g., ['*.md', '*.txt'])

        Returns:
            List of file metadata dictionaries

        Example:
            >>> scanner = FilesystemControlScanner()
            >>> files = scanner.scan_directory('./docs', recursive=True)
        """
        if patterns is None:
            patterns = ["*.md", "*.txt", "*.docx"]

        path_obj = Path(path)
        if not path_obj.exists():
            logger.error(f"Directory not found: {path}")
            return []

        if not path_obj.is_dir():
            logger.error(f"Path is not a directory: {path}")
            return []

        logger.info(f"Scanning directory: {path} (recursive={recursive})")

        found_files = []

        try:
            if recursive:
                # Recursive search
                for pattern in patterns:
                    for file_path in path_obj.rglob(pattern):
                        if file_path.is_file():
                            file_info = self._get_file_metadata(file_path)
                            found_files.append(file_info)
            else:
                # Non-recursive search
                for pattern in patterns:
                    for file_path in path_obj.glob(pattern):
                        if file_path.is_file():
                            file_info = self._get_file_metadata(file_path)
                            found_files.append(file_info)

            logger.info(f"Found {len(found_files)} files matching patterns")
            return found_files

        except Exception as e:
            logger.error(f"Error scanning directory: {str(e)}")
            return []

    def _get_file_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from a file.

        Args:
            file_path: Path object for the file

        Returns:
            File metadata dictionary
        """
        stat = file_path.stat()

        return {
            "path": str(file_path.absolute()),
            "name": file_path.name,
            "extension": file_path.suffix,
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        }

    def extract_controls_from_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Extract security controls from a single file.

        Args:
            filepath: Path to the file

        Returns:
            List of control dictionaries

        Example:
            >>> scanner = FilesystemControlScanner()
            >>> controls = scanner.extract_controls_from_file('./docs/security_controls.md')
        """
        file_path = Path(filepath)

        if not file_path.exists():
            logger.error(f"File not found: {filepath}")
            return []

        if not file_path.is_file():
            logger.error(f"Path is not a file: {filepath}")
            return []

        logger.info(f"Extracting controls from: {filepath}")

        try:
            # Determine file type and extract text
            text = self._read_file_content(file_path)

            if not text:
                logger.warning(f"No content extracted from {filepath}")
                return []

            # Parse controls from text
            controls = self.parse_control_references(text)

            # Add file metadata to each control
            for control in controls:
                control["source"] = "filesystem"
                control["source_file"] = str(file_path.absolute())
                control["file_name"] = file_path.name

            logger.info(f"Extracted {len(controls)} controls from {file_path.name}")
            return controls

        except Exception as e:
            logger.error(f"Error extracting controls from {filepath}: {str(e)}")
            return []

    def _read_file_content(self, file_path: Path) -> str:
        """Read text content from a file based on its extension.

        Args:
            file_path: Path object for the file

        Returns:
            Text content of the file
        """
        extension = file_path.suffix.lower()

        if extension in [".md", ".txt"]:
            # Plain text files
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return f.read()
            except UnicodeDecodeError:
                # Try with different encoding
                with open(file_path, "r", encoding="latin-1") as f:
                    return f.read()

        elif extension in [".docx"]:
            # Word documents (requires python-docx)
            try:
                import docx
                doc = docx.Document(file_path)
                return "\n".join([para.text for para in doc.paragraphs])
            except ImportError:
                logger.warning("python-docx not installed, cannot read .docx files")
                return ""
            except Exception as e:
                logger.warning(f"Error reading .docx file: {str(e)}")
                return ""

        elif extension == ".pdf":
            # PDF files (requires PyPDF2 or pdfplumber)
            try:
                import PyPDF2
                with open(file_path, "rb") as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    text = ""
                    for page in pdf_reader.pages:
                        text += page.extract_text()
                    return text
            except ImportError:
                logger.warning("PyPDF2 not installed, cannot read .pdf files")
                return ""
            except Exception as e:
                logger.warning(f"Error reading .pdf file: {str(e)}")
                return ""

        else:
            logger.warning(f"Unsupported file extension: {extension}")
            return ""

    def parse_control_references(self, text: str) -> List[Dict[str, Any]]:
        """Parse security control references from text.

        Args:
            text: Text content to parse

        Returns:
            List of control dictionaries with metadata

        Example:
            >>> scanner = FilesystemControlScanner()
            >>> text = "Implementation of NIST AC-1 and CIS 1.1 controls"
            >>> controls = scanner.parse_control_references(text)
        """
        controls = []
        discovered_ids = set()  # Avoid duplicates

        for framework, pattern in self.control_patterns.items():
            matches = pattern.finditer(text)

            for match in matches:
                # Generate control ID based on framework
                if framework == "NIST SP 800-53":
                    control_id = f"NIST-{match.group(1)}-{match.group(2)}"
                elif framework == "CIS Controls v8":
                    control_id = f"CIS-{match.group(1)}.{match.group(2)}"
                else:  # ISO 27001
                    control_id = f"ISO-A.{match.group(1)}.{match.group(2)}"

                # Skip if already found
                if control_id in discovered_ids:
                    continue

                discovered_ids.add(control_id)

                # Extract context around the match (up to 200 chars)
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                context = text[start:end].strip()

                # Try to extract title/description from context
                title, description = self._extract_control_details(context, control_id)

                control = {
                    "id": control_id,
                    "framework": framework,
                    "title": title,
                    "description": description,
                    "context": context,
                    "discovered_at": datetime.utcnow().isoformat(),
                }

                controls.append(control)

        logger.info(f"Parsed {len(controls)} unique control references")
        return controls

    def _extract_control_details(self, context: str, control_id: str) -> tuple:
        """Extract title and description from context text.

        Args:
            context: Context text containing the control reference
            control_id: Control identifier

        Returns:
            Tuple of (title, description)
        """
        # Try to extract title from common patterns
        escaped_id = re.escape(control_id.replace('-', r'[-\s]'))
        title_patterns = [
            # Pattern: "NIST AC-1: Title - Description"
            rf"{escaped_id}:?\s*([^-\n]+)[-\s]*(.+)",
            # Pattern: "Control: NIST AC-1 - Title"
            rf"Control:?\s*{escaped_id}\s*[-:]\s*([^\n]+)",
            # Pattern: "**NIST AC-1**: Title"
            rf"\*\*{escaped_id}\*\*:?\s*([^\n]+)",
        ]

        title = ""
        description = context

        for pattern in title_patterns:
            match = re.search(pattern, context, re.IGNORECASE)
            if match:
                title = match.group(1).strip()
                if len(match.groups()) > 1:
                    description = match.group(2).strip()
                else:
                    description = context
                break

        # Clean up title and description
        title = re.sub(r'\s+', ' ', title)[:200]
        description = re.sub(r'\s+', ' ', description)[:500]

        return title, description

    def scan_and_extract(
        self,
        directory: str,
        recursive: bool = True,
        patterns: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan directory and extract all controls from found files.

        Args:
            directory: Directory path to scan
            recursive: If True, scan subdirectories recursively
            patterns: File name patterns to match

        Returns:
            List of all discovered control dictionaries

        Example:
            >>> scanner = FilesystemControlScanner()
            >>> controls = scanner.scan_and_extract('./docs/compliance')
        """
        logger.info(f"Scanning and extracting controls from: {directory}")

        # Scan for files
        files = self.scan_directory(directory, recursive, patterns)

        if not files:
            logger.warning(f"No files found in {directory}")
            return []

        # Extract controls from each file
        all_controls = []

        for file_info in files:
            filepath = file_info["path"]

            try:
                controls = self.extract_controls_from_file(filepath)
                all_controls.extend(controls)
            except Exception as e:
                logger.error(f"Failed to process {filepath}: {str(e)}")
                continue

        logger.info(f"Total controls extracted: {len(all_controls)}")
        return all_controls

    def get_controls_by_framework(
        self,
        controls: List[Dict[str, Any]],
        framework: str,
    ) -> List[Dict[str, Any]]:
        """Filter controls by framework.

        Args:
            controls: List of control dictionaries
            framework: Framework name (e.g., 'NIST SP 800-53')

        Returns:
            Filtered list of controls
        """
        filtered = [c for c in controls if c.get("framework") == framework]
        logger.info(f"Filtered {len(filtered)} controls for framework {framework}")
        return filtered

    def get_controls_by_file(
        self,
        controls: List[Dict[str, Any]],
        filename: str,
    ) -> List[Dict[str, Any]]:
        """Filter controls by source file.

        Args:
            controls: List of control dictionaries
            filename: Source filename

        Returns:
            Filtered list of controls
        """
        filtered = [c for c in controls if filename in c.get("source_file", "")]
        logger.info(f"Filtered {len(filtered)} controls from file {filename}")
        return filtered
