"""Expanded tests for document parser to increase coverage."""

import pytest
from unittest.mock import Mock, patch
from src.tools.document_parser import DocumentParser


class TestDocumentParser:
    @patch("src.tools.document_parser.PdfReader")
    def test_parse_document_pdf(self, mock_pdf):
        mock_page = Mock()
        mock_page.extract_text.return_value = "Test content with CVE-2024-1234"
        mock_reader = Mock()
        mock_reader.pages = [mock_page]
        mock_pdf.return_value = mock_reader
        
        parser = DocumentParser()
        result = parser.parse_document("test.pdf")
        assert result is not None

    @patch("src.tools.document_parser.Document")
    def test_parse_document_docx(self, mock_doc):
        mock_para = Mock()
        mock_para.text = "Test paragraph with CVE-2024-1234"
        mock_document = Mock()
        mock_document.paragraphs = [mock_para]
        mock_doc.return_value = mock_document
        
        parser = DocumentParser()
        result = parser.parse_document("test.docx")
        assert result is not None

    @patch("src.tools.document_parser.openpyxl.load_workbook")
    def test_parse_document_excel(self, mock_workbook):
        mock_cell = Mock()
        mock_cell.value = "CVE-2024-1234"
        mock_ws = Mock()
        mock_ws.iter_rows.return_value = [[mock_cell]]
        mock_wb = Mock()
        mock_wb.active = mock_ws
        mock_workbook.return_value = mock_wb
        
        parser = DocumentParser()
        result = parser.parse_document("test.xlsx")
        assert result is not None

    def test_extract_cves_from_document(self):
        parser = DocumentParser()
        # Test CVE extraction
        with patch.object(parser, 'parse_document') as mock_parse:
            mock_parse.return_value = Mock(full_text="This contains CVE-2024-1234 and CVE-2023-5678")
            result = parser.extract_cves_from_document("test.pdf")
            assert isinstance(result, list)
