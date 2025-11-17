"""
Filesystem Control Scanner

Recursively scans directories for security control documentation in files
(Markdown, Word docs, PDFs, etc.) and extracts control information.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class FileControlMatch:
    """Control found in a file."""
    control_id: str
    framework: str
    title: str
    description: str
    file_path: str
    line_number: int
    confidence: float
    extracted_text: str
    metadata: Dict


class FilesystemControlScanner:
    """Scans filesystem for security control documentation."""

    # File extensions to scan
    SUPPORTED_EXTENSIONS = {'.md', '.txt', '.rst', '.adoc', '.doc', '.docx', '.pdf'}

    # Control patterns
    NIST_PATTERN = r'(?:NIST\s+)?([A-Z]{2})-(\d+(?:\(\d+\))?)[:\s]+(.*?)(?:\n|$)'
    CIS_PATTERN = r'CIS\s+(?:Control\s+)?(\d+)\.(\d+)[:\s]+(.*?)(?:\n|$)'
    ISO_PATTERN = r'(?:ISO\s+27001\s+)?A\.(\d+)\.(\d+)[:\s]+(.*?)(?:\n|$)'

    def __init__(self, max_file_size_mb: int = 10):
        """
        Initialize scanner.

        Args:
            max_file_size_mb: Skip files larger than this (in MB)
        """
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        logger.info(f"Initialized FilesystemControlScanner (max_file_size={max_file_size_mb}MB)")

    def scan_directory(self, directory: str,
                      frameworks: Optional[List[str]] = None,
                      recursive: bool = True,
                      exclude_patterns: Optional[List[str]] = None) -> List[FileControlMatch]:
        """
        Scan directory for control documentation.

        Args:
            directory: Path to scan
            frameworks: Filter by frameworks (e.g., ["NIST", "CIS", "ISO27001"])
            recursive: Scan subdirectories
            exclude_patterns: Exclude paths matching these patterns (e.g., ["node_modules", ".git"])

        Returns:
            List of discovered controls
        """
        logger.info(f"Scanning directory: {directory} (recursive={recursive})")

        if not os.path.exists(directory):
            logger.warning(f"Directory not found: {directory}")
            return []

        exclude_patterns = exclude_patterns or ['.git', 'node_modules', '__pycache__', '.venv']
        all_controls = []

        # Walk directory
        if recursive:
            for root, dirs, files in os.walk(directory):
                # Filter out excluded directories
                dirs[:] = [d for d in dirs if not self._should_exclude(d, exclude_patterns)]

                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_scan_file(file_path, exclude_patterns):
                        controls = self.scan_file(file_path, frameworks)
                        all_controls.extend(controls)
        else:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path) and self._should_scan_file(file_path, exclude_patterns):
                    controls = self.scan_file(file_path, frameworks)
                    all_controls.extend(controls)

        logger.info(f"Found {len(all_controls)} controls in {directory}")
        return all_controls

    def scan_file(self, file_path: str,
                  frameworks: Optional[List[str]] = None) -> List[FileControlMatch]:
        """
        Scan single file for controls.

        Args:
            file_path: Path to file
            frameworks: Filter by frameworks

        Returns:
            List of controls found in file
        """
        try:
            # Check file size
            if os.path.getsize(file_path) > self.max_file_size_bytes:
                logger.debug(f"Skipping large file: {file_path}")
                return []

            # Read file content
            content = self._read_file(file_path)
            if not content:
                return []

            # Extract controls
            controls = self.extract_controls_from_text(content, file_path, frameworks)
            return controls

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []

    def extract_controls_from_text(self, text: str, file_path: str,
                                  frameworks: Optional[List[str]] = None) -> List[FileControlMatch]:
        """Extract controls from text content."""
        controls = []

        # Extract NIST controls
        if not frameworks or "NIST" in frameworks:
            controls.extend(self._extract_nist_controls(text, file_path))

        # Extract CIS controls
        if not frameworks or "CIS" in frameworks:
            controls.extend(self._extract_cis_controls(text, file_path))

        # Extract ISO controls
        if not frameworks or "ISO27001" in frameworks or "ISO" in frameworks:
            controls.extend(self._extract_iso_controls(text, file_path))

        return controls

    def _extract_nist_controls(self, text: str, file_path: str) -> List[FileControlMatch]:
        """Extract NIST controls from text."""
        controls = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(self.NIST_PATTERN, line, re.IGNORECASE)
            for match in matches:
                family = match.group(1)
                number = match.group(2)
                title = match.group(3).strip()

                control_id = f"NIST-{family}-{number}"

                # Get context (next few lines)
                context_lines = lines[line_num:min(line_num + 5, len(lines))]
                description = ' '.join([l.strip() for l in context_lines if l.strip()])[:300]

                controls.append(FileControlMatch(
                    control_id=control_id,
                    framework="NIST",
                    title=title,
                    description=description,
                    file_path=file_path,
                    line_number=line_num,
                    confidence=0.85,
                    extracted_text=match.group(0),
                    metadata={
                        "file_name": os.path.basename(file_path),
                        "file_extension": os.path.splitext(file_path)[1]
                    }
                ))

        return controls

    def _extract_cis_controls(self, text: str, file_path: str) -> List[FileControlMatch]:
        """Extract CIS controls from text."""
        controls = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(self.CIS_PATTERN, line, re.IGNORECASE)
            for match in matches:
                major = match.group(1)
                minor = match.group(2)
                title = match.group(3).strip()

                control_id = f"CIS-{major}.{minor}"

                context_lines = lines[line_num:min(line_num + 5, len(lines))]
                description = ' '.join([l.strip() for l in context_lines if l.strip()])[:300]

                controls.append(FileControlMatch(
                    control_id=control_id,
                    framework="CIS",
                    title=title,
                    description=description,
                    file_path=file_path,
                    line_number=line_num,
                    confidence=0.82,
                    extracted_text=match.group(0),
                    metadata={
                        "file_name": os.path.basename(file_path),
                        "file_extension": os.path.splitext(file_path)[1]
                    }
                ))

        return controls

    def _extract_iso_controls(self, text: str, file_path: str) -> List[FileControlMatch]:
        """Extract ISO 27001 controls from text."""
        controls = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, 1):
            matches = re.finditer(self.ISO_PATTERN, line, re.IGNORECASE)
            for match in matches:
                section = match.group(1)
                subsection = match.group(2)
                title = match.group(3).strip()

                control_id = f"ISO-A.{section}.{subsection}"

                context_lines = lines[line_num:min(line_num + 5, len(lines))]
                description = ' '.join([l.strip() for l in context_lines if l.strip()])[:300]

                controls.append(FileControlMatch(
                    control_id=control_id,
                    framework="ISO27001",
                    title=title,
                    description=description,
                    file_path=file_path,
                    line_number=line_num,
                    confidence=0.80,
                    extracted_text=match.group(0),
                    metadata={
                        "file_name": os.path.basename(file_path),
                        "file_extension": os.path.splitext(file_path)[1]
                    }
                ))

        return controls

    def _read_file(self, file_path: str) -> Optional[str]:
        """Read file content based on extension."""
        ext = os.path.splitext(file_path)[1].lower()

        # Text files
        if ext in {'.md', '.txt', '.rst', '.adoc'}:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            except Exception as e:
                logger.debug(f"Error reading text file {file_path}: {e}")
                return None

        # Word documents (basic extraction)
        elif ext in {'.doc', '.docx'}:
            return self._read_docx(file_path)

        # PDF files (placeholder - would need pdfplumber/pypdf)
        elif ext == '.pdf':
            return self._read_pdf(file_path)

        return None

    def _read_docx(self, file_path: str) -> Optional[str]:
        """Read Word document (requires python-docx)."""
        try:
            from docx import Document
            doc = Document(file_path)
            return '\n'.join([para.text for para in doc.paragraphs])
        except ImportError:
            logger.debug("python-docx not available, skipping .docx files")
            return None
        except Exception as e:
            logger.debug(f"Error reading docx {file_path}: {e}")
            return None

    def _read_pdf(self, file_path: str) -> Optional[str]:
        """Read PDF file (requires pypdf)."""
        try:
            from pypdf import PdfReader
            reader = PdfReader(file_path)
            text = []
            for page in reader.pages:
                text.append(page.extract_text())
            return '\n'.join(text)
        except ImportError:
            logger.debug("pypdf not available, skipping PDF files")
            return None
        except Exception as e:
            logger.debug(f"Error reading PDF {file_path}: {e}")
            return None

    def _should_scan_file(self, file_path: str, exclude_patterns: List[str]) -> bool:
        """Check if file should be scanned."""
        # Check extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            return False

        # Check exclusions
        if self._should_exclude(file_path, exclude_patterns):
            return False

        return True

    def _should_exclude(self, path: str, exclude_patterns: List[str]) -> bool:
        """Check if path matches exclusion patterns."""
        for pattern in exclude_patterns:
            if pattern in path:
                return True
        return False

    def to_dict(self, controls: List[FileControlMatch]) -> List[Dict]:
        """Convert controls to dictionary format."""
        return [asdict(control) for control in controls]
