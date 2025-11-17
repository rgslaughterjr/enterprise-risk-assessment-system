"""
OCR Processor for extracting text from images and scanned PDFs.

This module provides OCR (Optical Character Recognition) capabilities for:
- Extracting text from image files (PNG, JPG, TIFF)
- Processing scanned PDFs
- Image preprocessing for better OCR accuracy
- Confidence scoring and quality metrics
- Layout preservation and structure detection
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import io

try:
    import pytesseract
    from PIL import Image, ImageEnhance, ImageFilter
    import pdf2image
    import fitz  # PyMuPDF
    import numpy as np
except ImportError as e:
    raise ImportError(f"Missing required dependencies for OCR: {e}")

logger = logging.getLogger(__name__)


class OCRProcessor:
    """
    Enterprise-grade OCR processor for extracting text from images and scanned PDFs.

    Features:
    - Multi-format image support (PNG, JPG, TIFF, BMP)
    - Scanned PDF detection and processing
    - Image preprocessing and enhancement
    - Confidence scoring per page
    - Language detection support
    - Orientation correction
    """

    SUPPORTED_IMAGE_FORMATS = {'.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp'}
    DEFAULT_DPI = 300
    MIN_CONFIDENCE_THRESHOLD = 0.6

    def __init__(
        self,
        language: str = 'eng',
        dpi: int = DEFAULT_DPI,
        preprocess: bool = True
    ):
        """
        Initialize OCR processor.

        Args:
            language: Tesseract language code (default: 'eng')
            dpi: DPI for PDF to image conversion (default: 300)
            preprocess: Whether to preprocess images (default: True)
        """
        self.language = language
        self.dpi = dpi
        self.preprocess = preprocess

        # Verify tesseract is available
        try:
            pytesseract.get_tesseract_version()
        except Exception as e:
            logger.warning(f"Tesseract not available: {e}")

    def extract_text_from_image(
        self,
        image_path: str,
        preprocess: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Extract text from an image file.

        Args:
            image_path: Path to image file
            preprocess: Override preprocessing setting

        Returns:
            Dictionary containing:
                - text: Extracted text
                - confidence: OCR confidence score (0-1)
                - language: Detected language
                - image_size: Original image dimensions
                - preprocessed: Whether image was preprocessed
        """
        try:
            image_path = Path(image_path)

            if not image_path.exists():
                logger.error(f"Image file not found: {image_path}")
                return self._empty_result(f"File not found: {image_path}")

            if image_path.suffix.lower() not in self.SUPPORTED_IMAGE_FORMATS:
                logger.error(f"Unsupported format: {image_path.suffix}")
                return self._empty_result(f"Unsupported format: {image_path.suffix}")

            # Load image
            image = Image.open(image_path)
            original_size = image.size

            # Preprocess if enabled
            should_preprocess = preprocess if preprocess is not None else self.preprocess
            if should_preprocess:
                image = self.preprocess_image(image)

            # Extract text with detailed data
            ocr_data = pytesseract.image_to_data(
                image,
                lang=self.language,
                output_type=pytesseract.Output.DICT
            )

            # Extract text
            text = pytesseract.image_to_string(image, lang=self.language)

            # Calculate confidence
            confidence = self.get_ocr_confidence(ocr_data)

            result = {
                'text': text.strip(),
                'confidence': confidence,
                'language': self.language,
                'image_size': original_size,
                'preprocessed': should_preprocess,
                'word_count': len([w for w in text.split() if w.strip()]),
                'success': True,
                'error': None
            }

            logger.info(
                f"Extracted {result['word_count']} words from {image_path.name} "
                f"(confidence: {confidence:.2f})"
            )

            return result

        except Exception as e:
            logger.error(f"Error extracting text from image: {e}")
            return self._empty_result(str(e))

    def extract_text_from_scanned_pdf(
        self,
        pdf_path: str,
        start_page: int = 0,
        end_page: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Extract text from scanned PDF by converting pages to images.

        Args:
            pdf_path: Path to PDF file
            start_page: First page to process (0-indexed)
            end_page: Last page to process (None = all pages)

        Returns:
            List of dictionaries, one per page, containing:
                - page_number: Page number (0-indexed)
                - text: Extracted text
                - confidence: OCR confidence score
                - image_size: Page dimensions
        """
        try:
            pdf_path = Path(pdf_path)

            if not pdf_path.exists():
                logger.error(f"PDF file not found: {pdf_path}")
                return []

            # Convert PDF pages to images
            logger.info(f"Converting PDF to images: {pdf_path.name}")
            images = pdf2image.convert_from_path(
                pdf_path,
                dpi=self.dpi,
                first_page=start_page + 1,  # pdf2image uses 1-indexed
                last_page=end_page + 1 if end_page is not None else None
            )

            results = []

            for i, image in enumerate(images):
                page_num = start_page + i
                logger.info(f"Processing page {page_num + 1}/{len(images)}")

                # Preprocess if enabled
                if self.preprocess:
                    image = self.preprocess_image(image)

                # Extract text with detailed data
                ocr_data = pytesseract.image_to_data(
                    image,
                    lang=self.language,
                    output_type=pytesseract.Output.DICT
                )

                # Extract text
                text = pytesseract.image_to_string(image, lang=self.language)

                # Calculate confidence
                confidence = self.get_ocr_confidence(ocr_data)

                page_result = {
                    'page_number': page_num,
                    'text': text.strip(),
                    'confidence': confidence,
                    'image_size': image.size,
                    'word_count': len([w for w in text.split() if w.strip()]),
                    'success': True
                }

                results.append(page_result)

                logger.info(
                    f"Page {page_num}: {page_result['word_count']} words "
                    f"(confidence: {confidence:.2f})"
                )

            logger.info(
                f"Processed {len(results)} pages from {pdf_path.name} "
                f"(avg confidence: {np.mean([r['confidence'] for r in results]):.2f})"
            )

            return results

        except Exception as e:
            logger.error(f"Error extracting text from scanned PDF: {e}")
            return []

    def preprocess_image(self, image: Image.Image) -> Image.Image:
        """
        Preprocess image for better OCR accuracy.

        Applies:
        - Grayscale conversion
        - Contrast enhancement
        - Sharpening
        - Noise reduction

        Args:
            image: PIL Image object

        Returns:
            Preprocessed PIL Image
        """
        try:
            # Convert to grayscale
            if image.mode != 'L':
                image = image.convert('L')

            # Increase contrast
            enhancer = ImageEnhance.Contrast(image)
            image = enhancer.enhance(2.0)

            # Sharpen
            image = image.filter(ImageFilter.SHARPEN)

            # Reduce noise
            image = image.filter(ImageFilter.MedianFilter(size=3))

            return image

        except Exception as e:
            logger.warning(f"Error preprocessing image: {e}")
            return image

    def get_ocr_confidence(self, text_data: Dict[str, List]) -> float:
        """
        Calculate average OCR confidence score from detailed OCR data.

        Args:
            text_data: Dictionary from pytesseract.image_to_data()

        Returns:
            Average confidence score (0-1)
        """
        try:
            confidences = [
                float(conf) / 100.0
                for conf in text_data.get('conf', [])
                if conf != -1  # -1 indicates no text detected
            ]

            if not confidences:
                return 0.0

            return np.mean(confidences)

        except Exception as e:
            logger.warning(f"Error calculating confidence: {e}")
            return 0.0

    def is_scanned_pdf(self, pdf_path: str, sample_pages: int = 3) -> bool:
        """
        Detect if PDF is scanned (image-based) vs native (text-based).

        Checks first N pages for extractable text. If text is minimal,
        PDF is likely scanned.

        Args:
            pdf_path: Path to PDF file
            sample_pages: Number of pages to sample

        Returns:
            True if PDF appears to be scanned
        """
        try:
            pdf_path = Path(pdf_path)

            if not pdf_path.exists():
                logger.error(f"PDF file not found: {pdf_path}")
                return False

            doc = fitz.open(pdf_path)
            pages_to_check = min(sample_pages, len(doc))

            total_text_length = 0

            for page_num in range(pages_to_check):
                page = doc[page_num]
                text = page.get_text()
                total_text_length += len(text.strip())

            doc.close()

            # If average text per page is less than 100 chars, likely scanned
            avg_text_length = total_text_length / pages_to_check
            is_scanned = avg_text_length < 100

            logger.info(
                f"PDF scan detection for {pdf_path.name}: "
                f"avg {avg_text_length:.0f} chars/page -> "
                f"{'SCANNED' if is_scanned else 'NATIVE'}"
            )

            return is_scanned

        except Exception as e:
            logger.error(f"Error detecting scanned PDF: {e}")
            return False

    def detect_orientation(self, image: Image.Image) -> int:
        """
        Detect image orientation using Tesseract OSD (Orientation and Script Detection).

        Args:
            image: PIL Image object

        Returns:
            Rotation angle (0, 90, 180, or 270)
        """
        try:
            osd = pytesseract.image_to_osd(image)

            # Parse rotation from OSD output
            for line in osd.split('\n'):
                if 'Rotate:' in line:
                    rotation = int(line.split(':')[1].strip())
                    return rotation

            return 0

        except Exception as e:
            logger.warning(f"Error detecting orientation: {e}")
            return 0

    def correct_orientation(self, image: Image.Image) -> Image.Image:
        """
        Automatically correct image orientation.

        Args:
            image: PIL Image object

        Returns:
            Rotated image (if needed)
        """
        try:
            rotation = self.detect_orientation(image)

            if rotation != 0:
                logger.info(f"Correcting orientation: rotating {rotation} degrees")
                # Rotate counter-clockwise
                image = image.rotate(360 - rotation, expand=True)

            return image

        except Exception as e:
            logger.warning(f"Error correcting orientation: {e}")
            return image

    def _empty_result(self, error: str) -> Dict[str, Any]:
        """
        Return empty result with error message.

        Args:
            error: Error message

        Returns:
            Empty result dictionary
        """
        return {
            'text': '',
            'confidence': 0.0,
            'language': self.language,
            'image_size': (0, 0),
            'preprocessed': False,
            'word_count': 0,
            'success': False,
            'error': error
        }

    def get_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate statistics from OCR results.

        Args:
            results: List of OCR results

        Returns:
            Dictionary with statistics
        """
        if not results:
            return {
                'total_pages': 0,
                'total_words': 0,
                'avg_confidence': 0.0,
                'min_confidence': 0.0,
                'max_confidence': 0.0,
                'low_confidence_pages': []
            }

        confidences = [r['confidence'] for r in results]
        word_counts = [r.get('word_count', 0) for r in results]

        low_confidence_pages = [
            r['page_number']
            for r in results
            if r['confidence'] < self.MIN_CONFIDENCE_THRESHOLD
        ]

        return {
            'total_pages': len(results),
            'total_words': sum(word_counts),
            'avg_confidence': np.mean(confidences),
            'min_confidence': min(confidences),
            'max_confidence': max(confidences),
            'low_confidence_pages': low_confidence_pages,
            'avg_words_per_page': np.mean(word_counts)
        }
