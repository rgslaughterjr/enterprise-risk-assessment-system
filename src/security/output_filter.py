"""
Output Filter - PII Detection and Redaction

Detects and redacts personally identifiable information (PII) from output
using Microsoft Presidio analyzer.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import re
import logging

logger = logging.getLogger(__name__)


class PIIType(Enum):
    """Types of PII."""
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    PHONE = "phone"
    EMAIL = "email"
    IP_ADDRESS = "ip_address"
    PERSON_NAME = "person"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    MEDICAL_LICENSE = "medical_license"
    US_DRIVER_LICENSE = "us_driver_license"


@dataclass
class PIIDetection:
    """Detected PII in text."""
    pii_type: PIIType
    text: str
    start: int
    end: int
    confidence: float
    entity_type: str


class OutputFilter:
    """Filter output to detect and redact PII."""

    # Regex patterns for PII detection (fallback if Presidio unavailable)
    PATTERNS = {
        PIIType.SSN: r'\b\d{3}-\d{2}-\d{4}\b',
        PIIType.CREDIT_CARD: r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        PIIType.PHONE: r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        PIIType.EMAIL: r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        PIIType.IP_ADDRESS: r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    }

    def __init__(self, use_presidio: bool = True, redaction_char: str = "*"):
        """
        Initialize output filter.

        Args:
            use_presidio: Use Presidio analyzer if available
            redaction_char: Character to use for redaction
        """
        self.use_presidio = use_presidio
        self.redaction_char = redaction_char
        self.analyzer = None
        self.anonymizer = None

        if use_presidio:
            try:
                from presidio_analyzer import AnalyzerEngine
                from presidio_anonymizer import AnonymizerEngine
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
                logger.info("Initialized OutputFilter with Presidio")
            except ImportError:
                logger.warning("Presidio not available, using regex patterns")
                self.use_presidio = False
        else:
            logger.info("Initialized OutputFilter with regex patterns")

    def detect_pii(self, output_text: str, language: str = "en") -> List[PIIDetection]:
        """
        Detect PII in output text.

        Args:
            output_text: Text to analyze
            language: Language code (default: "en")

        Returns:
            List of PII detections
        """
        if not output_text:
            return []

        if self.use_presidio and self.analyzer:
            return self._detect_with_presidio(output_text, language)
        else:
            return self._detect_with_regex(output_text)

    def _detect_with_presidio(self, text: str, language: str) -> List[PIIDetection]:
        """Detect PII using Presidio."""
        try:
            results = self.analyzer.analyze(
                text=text,
                language=language,
                entities=[
                    "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD",
                    "US_SSN", "PERSON", "LOCATION", "DATE_TIME",
                    "US_DRIVER_LICENSE", "IP_ADDRESS", "MEDICAL_LICENSE"
                ]
            )

            detections = []
            for result in results:
                pii_type = self._map_presidio_type(result.entity_type)
                if pii_type:
                    detections.append(PIIDetection(
                        pii_type=pii_type,
                        text=text[result.start:result.end],
                        start=result.start,
                        end=result.end,
                        confidence=result.score,
                        entity_type=result.entity_type
                    ))

            return detections
        except Exception as e:
            logger.error(f"Presidio detection error: {e}")
            return self._detect_with_regex(text)

    def _detect_with_regex(self, text: str) -> List[PIIDetection]:
        """Detect PII using regex patterns."""
        detections = []

        for pii_type, pattern in self.PATTERNS.items():
            for match in re.finditer(pattern, text):
                detections.append(PIIDetection(
                    pii_type=pii_type,
                    text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.85,
                    entity_type=pii_type.value
                ))

        return detections

    def redact_pii(self, output_text: str, pii_types: Optional[List[PIIType]] = None) -> str:
        """
        Redact PII from output text.

        Args:
            output_text: Text to redact
            pii_types: Specific PII types to redact (default: all)

        Returns:
            Redacted text
        """
        if not output_text:
            return output_text

        detections = self.detect_pii(output_text)

        # Filter by requested types
        if pii_types:
            detections = [d for d in detections if d.pii_type in pii_types]

        # Redact in reverse order to preserve positions
        redacted = output_text
        for detection in sorted(detections, key=lambda d: d.start, reverse=True):
            replacement = self._get_replacement(detection)
            redacted = redacted[:detection.start] + replacement + redacted[detection.end:]

        return redacted

    def _get_replacement(self, detection: PIIDetection) -> str:
        """Get replacement text for detected PII."""
        length = detection.end - detection.start

        # Use labeled placeholders
        labels = {
            PIIType.SSN: "[SSN REDACTED]",
            PIIType.CREDIT_CARD: "[CREDIT CARD REDACTED]",
            PIIType.PHONE: "[PHONE REDACTED]",
            PIIType.EMAIL: "[EMAIL REDACTED]",
            PIIType.PERSON_NAME: "[NAME REDACTED]",
            PIIType.ADDRESS: "[ADDRESS REDACTED]",
            PIIType.IP_ADDRESS: "[IP REDACTED]",
        }

        return labels.get(detection.pii_type, self.redaction_char * length)

    def _map_presidio_type(self, entity_type: str) -> Optional[PIIType]:
        """Map Presidio entity type to PIIType."""
        mapping = {
            "US_SSN": PIIType.SSN,
            "CREDIT_CARD": PIIType.CREDIT_CARD,
            "PHONE_NUMBER": PIIType.PHONE,
            "EMAIL_ADDRESS": PIIType.EMAIL,
            "IP_ADDRESS": PIIType.IP_ADDRESS,
            "PERSON": PIIType.PERSON_NAME,
            "LOCATION": PIIType.ADDRESS,
            "US_DRIVER_LICENSE": PIIType.US_DRIVER_LICENSE,
            "MEDICAL_LICENSE": PIIType.MEDICAL_LICENSE,
        }
        return mapping.get(entity_type)

    def has_pii(self, output_text: str, threshold: float = 0.5) -> bool:
        """
        Check if text contains PII above confidence threshold.

        Args:
            output_text: Text to check
            threshold: Confidence threshold (0.0-1.0)

        Returns:
            True if PII detected above threshold
        """
        detections = self.detect_pii(output_text)
        return any(d.confidence >= threshold for d in detections)
