"""
Integration tests for Document Parser Intelligence Features.

Tests verify that new methods exist and basic functionality works.
"""

import pytest
from pathlib import Path

from src.tools.document_parser import DocumentParser


@pytest.fixture
def document_parser():
    """Create document parser instance."""
    return DocumentParser()


class TestMethodsExist:
    """Test that new intelligence methods exist."""

    def test_parse_scanned_pdf_method_exists(self, document_parser):
        """Test parse_scanned_pdf method exists."""
        assert hasattr(document_parser, 'parse_scanned_pdf')
        assert callable(document_parser.parse_scanned_pdf)

    def test_extract_tables_method_exists(self, document_parser):
        """Test extract_tables method exists."""
        assert hasattr(document_parser, 'extract_tables')
        assert callable(document_parser.extract_tables)

    def test_classify_document_type_method_exists(self, document_parser):
        """Test classify_document_type method exists."""
        assert hasattr(document_parser, 'classify_document_type')
        assert callable(document_parser.classify_document_type)

    def test_parse_pptx_method_exists(self, document_parser):
        """Test parse_pptx method exists."""
        assert hasattr(document_parser, 'parse_pptx')
        assert callable(document_parser.parse_pptx)

    def test_auto_detect_format_method_exists(self, document_parser):
        """Test auto_detect_format method exists."""
        assert hasattr(document_parser, 'auto_detect_format')
        assert callable(document_parser.auto_detect_format)


class TestSupportedFormats:
    """Test supported formats."""

    def test_pptx_in_supported_formats(self):
        """Test that .pptx is in SUPPORTED_FORMATS."""
        assert '.pptx' in DocumentParser.SUPPORTED_FORMATS

    def test_all_expected_formats_supported(self):
        """Test all expected formats are supported."""
        expected = {'.pdf', '.docx', '.xlsx', '.xls', '.txt', '.md', '.csv', '.pptx'}
        assert expected.issubset(DocumentParser.SUPPORTED_FORMATS)


class TestAutoDetectFormat:
    """Test auto-format detection."""

    def test_auto_detect_pptx(self, document_parser, tmp_path):
        """Test detection of PowerPoint file."""
        test_file = tmp_path / "presentation.pptx"
        test_file.write_bytes(b"fake pptx")

        format_type = document_parser.auto_detect_format(str(test_file))
        assert format_type == 'pptx'

    def test_auto_detect_docx(self, document_parser, tmp_path):
        """Test detection of Word document."""
        test_file = tmp_path / "document.docx"
        test_file.write_bytes(b"fake docx")

        format_type = document_parser.auto_detect_format(str(test_file))
        assert format_type == 'docx'

    def test_auto_detect_excel(self, document_parser, tmp_path):
        """Test detection of Excel file."""
        test_file = tmp_path / "spreadsheet.xlsx"
        test_file.write_bytes(b"fake xlsx")

        format_type = document_parser.auto_detect_format(str(test_file))
        assert format_type == 'excel'

    def test_auto_detect_text(self, document_parser, tmp_path):
        """Test detection of text file."""
        test_file = tmp_path / "document.txt"
        test_file.write_text("text content")

        format_type = document_parser.auto_detect_format(str(test_file))
        assert format_type == 'text'

    def test_auto_detect_markdown(self, document_parser, tmp_path):
        """Test detection of markdown file."""
        test_file = tmp_path / "README.md"
        test_file.write_text("# Markdown")

        format_type = document_parser.auto_detect_format(str(test_file))
        assert format_type == 'markdown'

    def test_auto_detect_csv(self, document_parser, tmp_path):
        """Test detection of CSV file."""
        test_file = tmp_path / "data.csv"
        test_file.write_text("col1,col2\nval1,val2")

        format_type = document_parser.auto_detect_format(str(test_file))
        assert format_type == 'csv'

    def test_auto_detect_unknown(self, document_parser, tmp_path):
        """Test detection of unknown format."""
        test_file = tmp_path / "file.xyz"
        test_file.write_bytes(b"unknown")

        format_type = document_parser.auto_detect_format(str(test_file))
        assert format_type == 'unknown'


class TestClassifyDocumentType:
    """Test document classification."""

    def test_classify_returns_tuple(self, document_parser):
        """Test classify returns tuple of (type, confidence)."""
        result = document_parser.classify_document_type("Test security vulnerability report")

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], str)
        assert isinstance(result[1], float)
        assert 0 <= result[1] <= 1

    def test_classify_empty_text(self, document_parser):
        """Test classification with empty text."""
        doc_type, confidence = document_parser.classify_document_type("")

        assert isinstance(doc_type, str)
        assert isinstance(confidence, float)


class TestExtractTables:
    """Test table extraction."""

    def test_extract_tables_unsupported_format(self, document_parser, tmp_path):
        """Test table extraction from unsupported format."""
        test_file = tmp_path / "document.txt"
        test_file.write_text("text content")

        tables = document_parser.extract_tables(str(test_file))

        assert isinstance(tables, list)
        assert tables == []

    def test_extract_tables_nonexistent_file(self, document_parser):
        """Test table extraction from non-existent file."""
        tables = document_parser.extract_tables("/nonexistent/file.pdf")

        assert isinstance(tables, list)


class TestParseScannedPDF:
    """Test scanned PDF parsing."""

    def test_parse_scanned_pdf_nonexistent_file(self, document_parser):
        """Test parsing non-existent file."""
        result = document_parser.parse_scanned_pdf("/nonexistent/file.pdf")

        # Should handle gracefully
        assert result is None or hasattr(result, 'metadata')


class TestParsePPTX:
    """Test PowerPoint parsing."""

    def test_parse_pptx_nonexistent_file(self, document_parser):
        """Test parsing non-existent file."""
        result = document_parser.parse_pptx("/nonexistent/file.pptx")

        # Should handle gracefully
        assert result is None or hasattr(result, 'metadata')
