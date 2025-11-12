"""Document parsing utilities for PDF, DOCX, and XLSX files.

This module provides functions to parse various document formats and extract
text content, metadata, and structured data for security analysis.
"""

import os
import re
from typing import Optional, Dict, Any, List
from pathlib import Path
import logging

# PDF parsing
from pypdf import PdfReader

# DOCX parsing
from docx import Document

# Excel parsing
import openpyxl
import pandas as pd

from ..models.schemas import DocumentMetadata, ExtractedEntity, DocumentAnalysis

logger = logging.getLogger(__name__)


class DocumentParser:
    """Parser for various document formats.

    Supports PDF, DOCX, and XLSX files with metadata extraction
    and text content parsing.
    """

    SUPPORTED_FORMATS = {".pdf", ".docx", ".xlsx", ".xls"}

    def __init__(self):
        """Initialize document parser."""
        logger.info("Document parser initialized")

    def parse_document(self, file_path: str) -> Optional[DocumentAnalysis]:
        """Parse a document and return analysis.

        Args:
            file_path: Path to document file

        Returns:
            DocumentAnalysis object or None if parsing fails

        Example:
            >>> parser = DocumentParser()
            >>> analysis = parser.parse_document("report.pdf")
            >>> if analysis:
            ...     print(f"Text length: {len(analysis.text_content)}")
            ...     print(f"Entities found: {len(analysis.entities)}")
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None

        file_ext = Path(file_path).suffix.lower()

        if file_ext not in self.SUPPORTED_FORMATS:
            logger.error(f"Unsupported file format: {file_ext}")
            return None

        try:
            # Parse based on file type
            if file_ext == ".pdf":
                return self._parse_pdf(file_path)
            elif file_ext == ".docx":
                return self._parse_docx(file_path)
            elif file_ext in {".xlsx", ".xls"}:
                return self._parse_excel(file_path)

        except Exception as e:
            logger.error(f"Error parsing document {file_path}: {e}")
            return None

    def _parse_pdf(self, file_path: str) -> DocumentAnalysis:
        """Parse PDF file.

        Args:
            file_path: Path to PDF file

        Returns:
            DocumentAnalysis object
        """
        logger.info(f"Parsing PDF: {file_path}")

        reader = PdfReader(file_path)

        # Extract metadata
        metadata_dict = reader.metadata or {}
        metadata = DocumentMetadata(
            filename=os.path.basename(file_path),
            file_type="pdf",
            page_count=len(reader.pages),
            author=metadata_dict.get("/Author"),
            created_date=str(metadata_dict.get("/CreationDate", "")),
            modified_date=str(metadata_dict.get("/ModDate", "")),
        )

        # Extract text from all pages
        text_parts = []
        for page_num, page in enumerate(reader.pages, 1):
            try:
                text = page.extract_text()
                if text:
                    text_parts.append(text)
            except Exception as e:
                logger.warning(f"Error extracting text from page {page_num}: {e}")

        full_text = "\n".join(text_parts)

        # Extract entities
        entities = self._extract_entities(full_text)

        # Generate summary
        summary = self._generate_summary(full_text, len(reader.pages))

        return DocumentAnalysis(
            metadata=metadata,
            text_content=full_text,
            entities=entities,
            summary=summary,
        )

    def _parse_docx(self, file_path: str) -> DocumentAnalysis:
        """Parse DOCX file.

        Args:
            file_path: Path to DOCX file

        Returns:
            DocumentAnalysis object
        """
        logger.info(f"Parsing DOCX: {file_path}")

        doc = Document(file_path)

        # Extract metadata from core properties
        core_props = doc.core_properties
        metadata = DocumentMetadata(
            filename=os.path.basename(file_path),
            file_type="docx",
            page_count=None,  # DOCX doesn't have reliable page count
            author=core_props.author,
            created_date=str(core_props.created) if core_props.created else None,
            modified_date=str(core_props.modified) if core_props.modified else None,
        )

        # Extract text from paragraphs
        text_parts = []
        for paragraph in doc.paragraphs:
            if paragraph.text.strip():
                text_parts.append(paragraph.text)

        # Extract text from tables
        for table in doc.tables:
            for row in table.rows:
                row_text = " | ".join(cell.text for cell in row.cells)
                if row_text.strip():
                    text_parts.append(row_text)

        full_text = "\n".join(text_parts)

        # Extract entities
        entities = self._extract_entities(full_text)

        # Generate summary
        summary = self._generate_summary(full_text, len(doc.paragraphs))

        return DocumentAnalysis(
            metadata=metadata,
            text_content=full_text,
            entities=entities,
            summary=summary,
        )

    def _parse_excel(self, file_path: str) -> DocumentAnalysis:
        """Parse Excel file.

        Args:
            file_path: Path to Excel file

        Returns:
            DocumentAnalysis object
        """
        logger.info(f"Parsing Excel: {file_path}")

        # Load workbook for metadata
        wb = openpyxl.load_workbook(file_path, data_only=True)

        metadata = DocumentMetadata(
            filename=os.path.basename(file_path),
            file_type="xlsx",
            page_count=len(wb.sheetnames),
            author=wb.properties.creator,
            created_date=str(wb.properties.created) if wb.properties.created else None,
            modified_date=str(wb.properties.modified) if wb.properties.modified else None,
        )

        # Extract text from all sheets using pandas
        text_parts = []

        try:
            # Read all sheets
            excel_file = pd.ExcelFile(file_path)

            for sheet_name in excel_file.sheet_names:
                df = pd.read_excel(excel_file, sheet_name=sheet_name)

                # Add sheet name
                text_parts.append(f"\n=== Sheet: {sheet_name} ===\n")

                # Convert dataframe to text
                # Include headers and data
                text_parts.append(df.to_string())

        except Exception as e:
            logger.warning(f"Error reading Excel sheets with pandas: {e}")

            # Fallback to openpyxl
            for sheet in wb.worksheets:
                text_parts.append(f"\n=== Sheet: {sheet.title} ===\n")

                for row in sheet.iter_rows(values_only=True):
                    row_text = " | ".join(str(cell) for cell in row if cell is not None)
                    if row_text.strip():
                        text_parts.append(row_text)

        full_text = "\n".join(text_parts)

        # Extract entities
        entities = self._extract_entities(full_text)

        # Generate summary
        summary = self._generate_summary(full_text, len(wb.sheetnames))

        wb.close()

        return DocumentAnalysis(
            metadata=metadata,
            text_content=full_text,
            entities=entities,
            summary=summary,
        )

    def _extract_entities(self, text: str) -> List[ExtractedEntity]:
        """Extract security-related entities from text.

        Uses regex patterns to identify CVEs, controls, assets, risks, and findings.

        Args:
            text: Text to analyze

        Returns:
            List of ExtractedEntity objects
        """
        entities = []

        # CVE pattern
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        for match in re.finditer(cve_pattern, text, re.IGNORECASE):
            cve_id = match.group().upper()
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end].replace("\n", " ")

            entities.append(
                ExtractedEntity(
                    entity_type="cve",
                    value=cve_id,
                    confidence=1.0,
                    context=context,
                )
            )

        # Control identifiers (e.g., NIST controls, ISO controls)
        control_patterns = [
            r"\b(AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PS|RA|SA|SC|SI)-\d+",  # NIST
            r"\bISO[\s-]?\d{5}",  # ISO
            r"\b(CIS|PCI|SOX|HIPAA|GDPR)[\s-]?\d+",  # Various frameworks
        ]

        for pattern in control_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                control_id = match.group()
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].replace("\n", " ")

                entities.append(
                    ExtractedEntity(
                        entity_type="control",
                        value=control_id,
                        confidence=0.9,
                        context=context,
                    )
                )

        # Asset patterns (servers, databases, etc.)
        asset_patterns = [
            r"\b(server|database|web[-\s]?server|app[-\s]?server|db|host)[-\s]?\w+",
            r"\b\w+[-\s]?(prod|production|dev|development|test|staging)\b",
        ]

        for pattern in asset_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                asset_name = match.group()
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].replace("\n", " ")

                entities.append(
                    ExtractedEntity(
                        entity_type="asset",
                        value=asset_name,
                        confidence=0.7,
                        context=context,
                    )
                )

        # Risk keywords
        risk_keywords = [
            "critical risk",
            "high risk",
            "medium risk",
            "low risk",
            "vulnerability",
            "threat",
            "weakness",
        ]

        for keyword in risk_keywords:
            for match in re.finditer(re.escape(keyword), text, re.IGNORECASE):
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 100)
                context = text[start:end].replace("\n", " ")

                entities.append(
                    ExtractedEntity(
                        entity_type="risk",
                        value=match.group(),
                        confidence=0.8,
                        context=context,
                    )
                )

        # Finding keywords
        finding_keywords = [
            "finding",
            "observation",
            "recommendation",
            "remediation",
            "mitigation",
        ]

        for keyword in finding_keywords:
            for match in re.finditer(re.escape(keyword), text, re.IGNORECASE):
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 100)
                context = text[start:end].replace("\n", " ")

                entities.append(
                    ExtractedEntity(
                        entity_type="finding",
                        value=match.group(),
                        confidence=0.7,
                        context=context,
                    )
                )

        # Remove duplicate entities
        unique_entities = []
        seen = set()

        for entity in entities:
            key = (entity.entity_type, entity.value.lower())
            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)

        logger.info(f"Extracted {len(unique_entities)} entities from document")
        return unique_entities

    def _generate_summary(self, text: str, element_count: int) -> str:
        """Generate a summary of the document.

        Args:
            text: Full document text
            element_count: Number of pages/paragraphs/sheets

        Returns:
            Summary string
        """
        word_count = len(text.split())

        # Count entity types
        cves = len(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE))
        risks = len(re.findall(r"\b(critical|high|medium|low)\s+risk\b", text, re.IGNORECASE))

        summary = (
            f"Document contains {word_count:,} words across {element_count} sections. "
            f"Identified {cves} CVE references and {risks} risk statements."
        )

        return summary

    def extract_cves_from_document(self, file_path: str) -> List[str]:
        """Extract just CVE IDs from a document.

        Args:
            file_path: Path to document

        Returns:
            List of unique CVE IDs

        Example:
            >>> parser = DocumentParser()
            >>> cves = parser.extract_cves_from_document("vuln_report.pdf")
            >>> print(f"Found CVEs: {cves}")
        """
        analysis = self.parse_document(file_path)

        if not analysis:
            return []

        cves = [
            entity.value
            for entity in analysis.entities
            if entity.entity_type == "cve"
        ]

        return list(set(cves))  # Return unique CVEs
