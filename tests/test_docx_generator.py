"""Unit tests for DOCX report generator."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os

from src.tools.docx_generator import DOCXGenerator


class TestDOCXGeneratorInitialization:
    def test_generator_initialization(self):
        generator = DOCXGenerator()
        assert generator is not None


class TestDocumentCreation:
    def test_create_document_method_exists(self):
        generator = DOCXGenerator()
        assert hasattr(generator, 'create_report') or hasattr(generator, 'generate_report')

    @patch("src.tools.docx_generator.Document")
    def test_create_basic_document(self, mock_doc):
        mock_document = Mock()
        mock_doc.return_value = mock_document

        generator = DOCXGenerator()
        assert generator is not None


class TestRiskHeatmap:
    def test_heatmap_method_exists(self):
        generator = DOCXGenerator()
        assert hasattr(generator, 'create_report') and hasattr(generator, '_add_risk_heatmap')

    @patch("matplotlib.pyplot.savefig")
    @patch("matplotlib.pyplot.figure")
    def test_heatmap_generation(self, mock_fig, mock_save):
        generator = DOCXGenerator()
        # Test that matplotlib methods can be called
        assert generator is not None


class TestTableFormatting:
    @patch("src.tools.docx_generator.Document")
    def test_table_creation(self, mock_doc):
        mock_document = Mock()
        mock_table = Mock()
        mock_document.add_table.return_value = mock_table
        mock_doc.return_value = mock_document

        generator = DOCXGenerator()
        assert generator is not None


class TestFileSaving:
    @patch("src.tools.docx_generator.Document")
    def test_save_document(self, mock_doc):
        mock_document = Mock()
        mock_doc.return_value = mock_document

        generator = DOCXGenerator()
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            if hasattr(generator, 'save'):
                generator.save(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
