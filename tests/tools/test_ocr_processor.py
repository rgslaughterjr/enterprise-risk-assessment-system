"""
Comprehensive tests for OCR Processor.

Tests cover:
- Image text extraction
- Scanned PDF processing
- Image preprocessing
- Confidence scoring
- PDF scan detection
- Orientation correction
- Error handling
- Statistics calculation
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from PIL import Image
import numpy as np

from src.tools.ocr_processor import OCRProcessor


@pytest.fixture
def ocr_processor():
    """Create OCR processor instance."""
    return OCRProcessor(language='eng', dpi=300, preprocess=True)


@pytest.fixture
def sample_image():
    """Create a sample PIL image."""
    return Image.new('RGB', (800, 600), color='white')


@pytest.fixture
def mock_ocr_data():
    """Create mock OCR data from pytesseract."""
    return {
        'text': ['Hello', 'World', 'Test'],
        'conf': [95, 90, 85],
        'left': [10, 100, 200],
        'top': [10, 10, 10],
        'width': [80, 80, 80],
        'height': [20, 20, 20]
    }


class TestOCRProcessorInit:
    """Test OCR processor initialization."""

    def test_init_default_params(self):
        """Test initialization with default parameters."""
        processor = OCRProcessor()
        assert processor.language == 'eng'
        assert processor.dpi == 300
        assert processor.preprocess is True

    def test_init_custom_params(self):
        """Test initialization with custom parameters."""
        processor = OCRProcessor(language='fra', dpi=600, preprocess=False)
        assert processor.language == 'fra'
        assert processor.dpi == 600
        assert processor.preprocess is False

    def test_supported_formats(self):
        """Test supported image formats are defined."""
        assert '.png' in OCRProcessor.SUPPORTED_IMAGE_FORMATS
        assert '.jpg' in OCRProcessor.SUPPORTED_IMAGE_FORMATS
        assert '.jpeg' in OCRProcessor.SUPPORTED_IMAGE_FORMATS
        assert '.tiff' in OCRProcessor.SUPPORTED_IMAGE_FORMATS


class TestExtractTextFromImage:
    """Test image text extraction."""

    @patch('src.tools.ocr_processor.Image.open')
    @patch('src.tools.ocr_processor.pytesseract.image_to_string')
    @patch('src.tools.ocr_processor.pytesseract.image_to_data')
    def test_extract_text_success(
        self,
        mock_image_to_data,
        mock_image_to_string,
        mock_image_open,
        ocr_processor,
        sample_image,
        mock_ocr_data,
        tmp_path
    ):
        """Test successful text extraction from image."""
        # Setup
        test_file = tmp_path / "test.png"
        test_file.touch()

        mock_image_open.return_value = sample_image
        mock_image_to_string.return_value = "Hello World Test"
        mock_image_to_data.return_value = mock_ocr_data

        # Execute
        result = ocr_processor.extract_text_from_image(str(test_file))

        # Verify
        assert result['success'] is True
        assert result['text'] == "Hello World Test"
        assert result['confidence'] > 0
        assert result['word_count'] == 3
        assert result['language'] == 'eng'
        assert result['preprocessed'] is True
        assert result['error'] is None

    def test_extract_text_file_not_found(self, ocr_processor):
        """Test extraction with non-existent file."""
        result = ocr_processor.extract_text_from_image("/nonexistent/file.png")

        assert result['success'] is False
        assert result['text'] == ''
        assert result['confidence'] == 0.0
        assert 'not found' in result['error'].lower()

    @patch('src.tools.ocr_processor.Image.open')
    def test_extract_text_unsupported_format(
        self,
        mock_image_open,
        ocr_processor,
        tmp_path
    ):
        """Test extraction with unsupported file format."""
        test_file = tmp_path / "test.xyz"
        test_file.touch()

        result = ocr_processor.extract_text_from_image(str(test_file))

        assert result['success'] is False
        assert 'unsupported' in result['error'].lower()

    @patch('src.tools.ocr_processor.Image.open')
    @patch('src.tools.ocr_processor.pytesseract.image_to_string')
    @patch('src.tools.ocr_processor.pytesseract.image_to_data')
    def test_extract_text_no_preprocessing(
        self,
        mock_image_to_data,
        mock_image_to_string,
        mock_image_open,
        sample_image,
        mock_ocr_data,
        tmp_path
    ):
        """Test extraction without preprocessing."""
        test_file = tmp_path / "test.jpg"
        test_file.touch()

        mock_image_open.return_value = sample_image
        mock_image_to_string.return_value = "Test text"
        mock_image_to_data.return_value = mock_ocr_data

        processor = OCRProcessor(preprocess=False)
        result = processor.extract_text_from_image(str(test_file))

        assert result['preprocessed'] is False

    @patch('src.tools.ocr_processor.Image.open')
    @patch('src.tools.ocr_processor.pytesseract.image_to_string')
    def test_extract_text_exception_handling(
        self,
        mock_image_to_string,
        mock_image_open,
        ocr_processor,
        tmp_path
    ):
        """Test exception handling during extraction."""
        test_file = tmp_path / "test.png"
        test_file.touch()

        mock_image_open.side_effect = Exception("Test error")

        result = ocr_processor.extract_text_from_image(str(test_file))

        assert result['success'] is False
        assert result['error'] == "Test error"


class TestExtractTextFromScannedPDF:
    """Test scanned PDF text extraction."""

    @patch('src.tools.ocr_processor.pdf2image.convert_from_path')
    @patch('src.tools.ocr_processor.pytesseract.image_to_string')
    @patch('src.tools.ocr_processor.pytesseract.image_to_data')
    def test_extract_scanned_pdf_success(
        self,
        mock_image_to_data,
        mock_image_to_string,
        mock_convert,
        ocr_processor,
        sample_image,
        mock_ocr_data,
        tmp_path
    ):
        """Test successful extraction from scanned PDF."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        # Mock 3 pages
        mock_convert.return_value = [sample_image, sample_image, sample_image]
        mock_image_to_string.return_value = "Page text"
        mock_image_to_data.return_value = mock_ocr_data

        results = ocr_processor.extract_text_from_scanned_pdf(str(test_file))

        assert len(results) == 3
        assert all(r['success'] is True for r in results)
        assert all(r['text'] == "Page text" for r in results)
        assert results[0]['page_number'] == 0
        assert results[1]['page_number'] == 1
        assert results[2]['page_number'] == 2

    @patch('src.tools.ocr_processor.pdf2image.convert_from_path')
    @patch('src.tools.ocr_processor.pytesseract.image_to_string')
    @patch('src.tools.ocr_processor.pytesseract.image_to_data')
    def test_extract_scanned_pdf_page_range(
        self,
        mock_image_to_data,
        mock_image_to_string,
        mock_convert,
        ocr_processor,
        sample_image,
        mock_ocr_data,
        tmp_path
    ):
        """Test extraction with page range."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        mock_convert.return_value = [sample_image, sample_image]
        mock_image_to_string.return_value = "Page text"
        mock_image_to_data.return_value = mock_ocr_data

        results = ocr_processor.extract_text_from_scanned_pdf(
            str(test_file),
            start_page=2,
            end_page=3
        )

        assert len(results) == 2
        assert results[0]['page_number'] == 2
        assert results[1]['page_number'] == 3

    def test_extract_scanned_pdf_file_not_found(self, ocr_processor):
        """Test extraction with non-existent PDF."""
        results = ocr_processor.extract_text_from_scanned_pdf("/nonexistent/file.pdf")
        assert results == []

    @patch('src.tools.ocr_processor.pdf2image.convert_from_path')
    def test_extract_scanned_pdf_exception_handling(
        self,
        mock_convert,
        ocr_processor,
        tmp_path
    ):
        """Test exception handling during PDF extraction."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        mock_convert.side_effect = Exception("Conversion error")

        results = ocr_processor.extract_text_from_scanned_pdf(str(test_file))
        assert results == []


class TestImagePreprocessing:
    """Test image preprocessing."""

    def test_preprocess_image_grayscale(self, ocr_processor):
        """Test grayscale conversion."""
        color_image = Image.new('RGB', (100, 100), color='red')
        processed = ocr_processor.preprocess_image(color_image)

        assert processed.mode == 'L'  # Grayscale

    def test_preprocess_already_grayscale(self, ocr_processor):
        """Test preprocessing already grayscale image."""
        gray_image = Image.new('L', (100, 100), color=128)
        processed = ocr_processor.preprocess_image(gray_image)

        assert processed.mode == 'L'

    def test_preprocess_image_exception(self, ocr_processor):
        """Test exception handling in preprocessing."""
        mock_image = Mock()
        mock_image.mode = 'RGB'
        mock_image.convert.side_effect = Exception("Convert error")

        # Should return original image on error
        result = ocr_processor.preprocess_image(mock_image)
        assert result == mock_image


class TestConfidenceScoring:
    """Test OCR confidence scoring."""

    def test_get_ocr_confidence_normal(self, ocr_processor):
        """Test confidence calculation with normal data."""
        data = {
            'conf': [95, 90, 85, 80, 75]
        }
        confidence = ocr_processor.get_ocr_confidence(data)

        assert 0.8 < confidence < 0.9

    def test_get_ocr_confidence_with_invalid(self, ocr_processor):
        """Test confidence calculation with invalid values."""
        data = {
            'conf': [95, -1, 90, -1, 85]  # -1 = no text
        }
        confidence = ocr_processor.get_ocr_confidence(data)

        assert confidence == 0.9  # (95 + 90 + 85) / 3 / 100

    def test_get_ocr_confidence_empty(self, ocr_processor):
        """Test confidence with no valid data."""
        data = {
            'conf': [-1, -1, -1]
        }
        confidence = ocr_processor.get_ocr_confidence(data)

        assert confidence == 0.0

    def test_get_ocr_confidence_exception(self, ocr_processor):
        """Test exception handling in confidence calculation."""
        data = {}  # Missing 'conf' key
        confidence = ocr_processor.get_ocr_confidence(data)

        assert confidence == 0.0


class TestScannedPDFDetection:
    """Test scanned PDF detection."""

    @patch('src.tools.ocr_processor.fitz.open')
    def test_is_scanned_pdf_native(self, mock_fitz_open, ocr_processor, tmp_path):
        """Test detection of native PDF (not scanned)."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        # Mock native PDF with text
        mock_doc = MagicMock()
        mock_page = Mock()
        mock_page.get_text.return_value = "A" * 200  # Lots of text
        mock_doc.__len__.return_value = 1
        mock_doc.__getitem__.return_value = mock_page
        mock_fitz_open.return_value = mock_doc

        is_scanned = ocr_processor.is_scanned_pdf(str(test_file))

        assert is_scanned is False
        mock_doc.close.assert_called_once()

    @patch('src.tools.ocr_processor.fitz.open')
    def test_is_scanned_pdf_scanned(self, mock_fitz_open, ocr_processor, tmp_path):
        """Test detection of scanned PDF."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        # Mock scanned PDF with minimal text
        mock_doc = MagicMock()
        mock_page = Mock()
        mock_page.get_text.return_value = "  "  # Almost no text
        mock_doc.__len__.return_value = 1
        mock_doc.__getitem__.return_value = mock_page
        mock_fitz_open.return_value = mock_doc

        is_scanned = ocr_processor.is_scanned_pdf(str(test_file))

        assert is_scanned is True

    def test_is_scanned_pdf_file_not_found(self, ocr_processor):
        """Test detection with non-existent file."""
        is_scanned = ocr_processor.is_scanned_pdf("/nonexistent/file.pdf")
        assert is_scanned is False

    @patch('src.tools.ocr_processor.fitz.open')
    def test_is_scanned_pdf_exception(self, mock_fitz_open, ocr_processor, tmp_path):
        """Test exception handling in scan detection."""
        test_file = tmp_path / "test.pdf"
        test_file.touch()

        mock_fitz_open.side_effect = Exception("Open error")

        is_scanned = ocr_processor.is_scanned_pdf(str(test_file))
        assert is_scanned is False


class TestOrientationDetection:
    """Test orientation detection and correction."""

    @patch('src.tools.ocr_processor.pytesseract.image_to_osd')
    def test_detect_orientation_normal(self, mock_osd, ocr_processor, sample_image):
        """Test orientation detection."""
        mock_osd.return_value = "Rotate: 90\nOrientation confidence: 9.5"

        rotation = ocr_processor.detect_orientation(sample_image)

        assert rotation == 90

    @patch('src.tools.ocr_processor.pytesseract.image_to_osd')
    def test_detect_orientation_no_rotation(self, mock_osd, ocr_processor, sample_image):
        """Test detection with no rotation needed."""
        mock_osd.return_value = "Rotate: 0\nOrientation confidence: 9.5"

        rotation = ocr_processor.detect_orientation(sample_image)

        assert rotation == 0

    @patch('src.tools.ocr_processor.pytesseract.image_to_osd')
    def test_detect_orientation_exception(self, mock_osd, ocr_processor, sample_image):
        """Test exception handling in orientation detection."""
        mock_osd.side_effect = Exception("OSD error")

        rotation = ocr_processor.detect_orientation(sample_image)

        assert rotation == 0

    @patch('src.tools.ocr_processor.pytesseract.image_to_osd')
    def test_correct_orientation(self, mock_osd, ocr_processor, sample_image):
        """Test orientation correction."""
        mock_osd.return_value = "Rotate: 90\nOrientation confidence: 9.5"

        corrected = ocr_processor.correct_orientation(sample_image)

        assert corrected is not None
        # Image should be rotated

    @patch('src.tools.ocr_processor.pytesseract.image_to_osd')
    def test_correct_orientation_no_change(self, mock_osd, ocr_processor, sample_image):
        """Test orientation correction with no rotation needed."""
        mock_osd.return_value = "Rotate: 0\nOrientation confidence: 9.5"

        corrected = ocr_processor.correct_orientation(sample_image)

        assert corrected == sample_image


class TestStatistics:
    """Test OCR statistics calculation."""

    def test_get_statistics_normal(self, ocr_processor):
        """Test statistics with normal results."""
        results = [
            {'page_number': 0, 'confidence': 0.9, 'word_count': 100},
            {'page_number': 1, 'confidence': 0.8, 'word_count': 150},
            {'page_number': 2, 'confidence': 0.5, 'word_count': 75}  # Low confidence
        ]

        stats = ocr_processor.get_statistics(results)

        assert stats['total_pages'] == 3
        assert stats['total_words'] == 325
        assert 0.7 < stats['avg_confidence'] < 0.8
        assert stats['min_confidence'] == 0.5
        assert stats['max_confidence'] == 0.9
        assert stats['low_confidence_pages'] == [2]
        assert stats['avg_words_per_page'] == 325 / 3

    def test_get_statistics_empty(self, ocr_processor):
        """Test statistics with no results."""
        stats = ocr_processor.get_statistics([])

        assert stats['total_pages'] == 0
        assert stats['total_words'] == 0
        assert stats['avg_confidence'] == 0.0
        assert stats['low_confidence_pages'] == []

    def test_get_statistics_all_high_confidence(self, ocr_processor):
        """Test statistics with all high confidence."""
        results = [
            {'page_number': 0, 'confidence': 0.9, 'word_count': 100},
            {'page_number': 1, 'confidence': 0.95, 'word_count': 150}
        ]

        stats = ocr_processor.get_statistics(results)

        assert stats['low_confidence_pages'] == []


class TestEmptyResult:
    """Test empty result creation."""

    def test_empty_result(self, ocr_processor):
        """Test empty result creation."""
        result = ocr_processor._empty_result("Test error")

        assert result['text'] == ''
        assert result['confidence'] == 0.0
        assert result['success'] is False
        assert result['error'] == "Test error"
        assert result['word_count'] == 0
