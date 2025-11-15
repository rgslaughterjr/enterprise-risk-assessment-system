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
    def test_parse_pdf_method_exists(self):
        parser = DocumentParser()
        assert hasattr(parser, 'parse_pdf')

    @patch("src.tools.document_parser.PdfReader")
    def test_parse_pdf_basic(self, mock_reader):
        mock_page = Mock()
        mock_page.extract_text.return_value = "Test content"
        mock_pdf = Mock()
        mock_pdf.pages = [mock_page]
        mock_reader.return_value = mock_pdf

        parser = DocumentParser()
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = parser.parse_pdf(tmp_path)
            assert isinstance(result, (str, dict))
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestDOCXParsing:
    def test_parse_docx_method_exists(self):
        parser = DocumentParser()
        assert hasattr(parser, 'parse_docx')

    @patch("src.tools.document_parser.Document")
    def test_parse_docx_basic(self, mock_doc):
        mock_paragraph = Mock()
        mock_paragraph.text = "Test paragraph"
        mock_doc.return_value.paragraphs = [mock_paragraph]

        parser = DocumentParser()
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = parser.parse_docx(tmp_path)
            assert isinstance(result, (str, dict))
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestTextExtraction:
    def test_extract_text_method_exists(self):
        parser = DocumentParser()
        assert hasattr(parser, 'extract_text') or hasattr(parser, 'parse')
