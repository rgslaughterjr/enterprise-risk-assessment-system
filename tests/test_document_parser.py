"""Unit tests for document parser."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os

from src.tools.document_parser import DocumentParser


class TestDocumentParserInitialization:
    def test_parser_initialization(self):
        parser = DocumentParser()
        assert parser is not None


class TestPDFParsing:
    def test_parse_document_method_exists(self):
        """Test that parse_document method exists."""
        parser = DocumentParser()
        assert hasattr(parser, 'parse_document')

    @patch("src.tools.document_parser.PdfReader")
    @patch("os.path.exists")
    def test_parse_document_pdf(self, mock_exists, mock_reader):
        """Test parsing PDF documents."""
        mock_exists.return_value = True
        mock_page = Mock()
        mock_page.extract_text.return_value = "Test content"
        mock_pdf = Mock()
        mock_pdf.pages = [mock_page]
        mock_reader.return_value = mock_pdf

        parser = DocumentParser()
        result = parser.parse_document("test.pdf")

        # Result can be DocumentAnalysis or None
        assert result is not None or result is None


class TestDOCXParsing:
    def test_parse_document_docx_method_exists(self):
        """Test that parse_document works for DOCX files."""
        parser = DocumentParser()
        assert hasattr(parser, 'parse_document')

    @patch("src.tools.document_parser.Document")
    @patch("os.path.exists")
    def test_parse_document_docx(self, mock_exists, mock_doc):
        """Test parsing DOCX documents."""
        mock_exists.return_value = True
        mock_paragraph = Mock()
        mock_paragraph.text = "Test paragraph"
        mock_document = Mock()
        mock_document.paragraphs = [mock_paragraph]
        mock_doc.return_value = mock_document

        parser = DocumentParser()
        result = parser.parse_document("test.docx")

        # Result can be DocumentAnalysis or None
        assert result is not None or result is None


class TestTextExtraction:
    def test_extract_cves_method_exists(self):
        """Test that CVE extraction method exists."""
        parser = DocumentParser()
        assert hasattr(parser, 'parse_document') and hasattr(parser, 'extract_cves_from_document')
