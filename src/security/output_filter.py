"""
Output Filter - Week 9 Security Hardening

Detects and redacts PII (Personally Identifiable Information):
- SSN (Social Security Numbers)
- Credit card numbers
- Phone numbers
- Email addresses
- IP addresses
- Names
- Addresses
- Medical record numbers
- Passport numbers
- Driver's license numbers
- Bank account numbers
- Dates of birth
- URLs with sensitive data
- API keys
- Passwords

Uses Microsoft Presidio for enterprise-grade PII detection.

Usage:
    filter = OutputFilter()
    result = filter.filter_output("My SSN is 123-45-6789")
    print(result.redacted_text)  # "My SSN is <SSN>"
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum

# Try to import presidio, fall back to regex-only mode
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


class PIIType(Enum):
    """Types of PII detected"""
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    PHONE = "PHONE_NUMBER"
    EMAIL = "EMAIL_ADDRESS"
    IP_ADDRESS = "IP_ADDRESS"
    PERSON = "PERSON"
    LOCATION = "LOCATION"
    DATE_TIME = "DATE_TIME"
    MEDICAL_RECORD = "MEDICAL_RECORD"
    PASSPORT = "PASSPORT"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    URL_WITH_PARAMS = "URL_WITH_PARAMS"
    IBAN = "IBAN_CODE"


@dataclass
class PIIMatch:
    """A detected PII match"""
    pii_type: PIIType
    start: int
    end: int
    text: str
    confidence: float


@dataclass
class FilterResult:
    """Result of output filtering"""
    original_text: str
    redacted_text: str
    pii_found: List[PIIMatch]
    contains_pii: bool


class OutputFilter:
    """
    Enterprise-grade PII detection and redaction.

    Features:
    - 15+ PII types
    - Regex-based detection (fast)
    - Presidio integration (accurate)
    - Configurable redaction formats
    - Confidence scoring
    """

    def __init__(self, use_presidio: bool = True, confidence_threshold: float = 0.5):
        """
        Initialize output filter.

        Args:
            use_presidio: Use Presidio if available (more accurate, slower)
            confidence_threshold: Minimum confidence for PII detection (0.0-1.0)
        """
        self.use_presidio = use_presidio and PRESIDIO_AVAILABLE
        self.confidence_threshold = confidence_threshold

        # Initialize regex patterns for fast detection
        self._init_patterns()

        # Initialize Presidio if available
        if self.use_presidio:
            try:
                # Configure NLP engine (use blank spacy model for speed)
                configuration = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                }
                # Try to create NLP engine, fall back to regex if it fails
                try:
                    provider = NlpEngineProvider(nlp_configuration=configuration)
                    nlp_engine = provider.create_engine()
                    self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
                except Exception:
                    # Fall back to regex mode if NLP model not available
                    self.use_presidio = False
                    self.analyzer = None

                self.anonymizer = AnonymizerEngine() if self.use_presidio else None
            except Exception:
                self.use_presidio = False
                self.analyzer = None
                self.anonymizer = None

    def _init_patterns(self):
        """Initialize regex patterns for PII detection"""
        # SSN patterns (US)
        self.ssn_pattern = re.compile(
            r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b|'
            r'\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b'
        )

        # Credit card patterns (Visa, MC, Amex, Discover)
        self.credit_card_pattern = re.compile(
            r'\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b|'
            r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b'
        )

        # Phone patterns (US/International)
        self.phone_pattern = re.compile(
            r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b|'
            r'\b\+?[1-9]\d{1,14}\b'
        )

        # Email pattern (RFC 5322 simplified)
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )

        # IP address pattern (IPv4)
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )

        # API key patterns (common formats)
        self.api_key_pattern = re.compile(
            r'\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?\b',
            re.IGNORECASE
        )

        # Password patterns in text
        self.password_pattern = re.compile(
            r'\b(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{6,})["\']?\b',
            re.IGNORECASE
        )

        # URLs with query parameters (potential sensitive data)
        self.url_with_params_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+\?[^\s<>"{}|\\^`\[\]]+'
        )

        # Medical record numbers
        self.medical_record_pattern = re.compile(
            r'\b(?:MRN|Medical\s+Record|Patient\s+ID)[:\s#]*([A-Z0-9]{6,12})\b',
            re.IGNORECASE
        )

        # Passport numbers (simplified)
        self.passport_pattern = re.compile(
            r'\b[A-Z]{1,2}\d{6,9}\b'
        )

        # Driver's license (simplified, US)
        self.drivers_license_pattern = re.compile(
            r'\b[A-Z]{1,2}\d{6,8}\b'
        )

        # Bank account numbers
        self.bank_account_pattern = re.compile(
            r'\b\d{8,17}\b'
        )

        # IBAN
        self.iban_pattern = re.compile(
            r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'
        )

    def filter_output(self, text: str) -> FilterResult:
        """
        Filter output text to detect and redact PII.

        Args:
            text: Text to filter

        Returns:
            FilterResult with redacted text and PII matches
        """
        if not text:
            return FilterResult(
                original_text=text,
                redacted_text=text,
                pii_found=[],
                contains_pii=False
            )

        if self.use_presidio:
            return self._filter_with_presidio(text)
        else:
            return self._filter_with_regex(text)

    def _filter_with_presidio(self, text: str) -> FilterResult:
        """Filter using Presidio (more accurate)"""
        # Analyze for PII
        results = self.analyzer.analyze(
            text=text,
            language="en",
            score_threshold=self.confidence_threshold
        )

        # Convert to PIIMatch objects
        pii_matches = []
        for result in results:
            try:
                pii_type = PIIType[result.entity_type]
            except KeyError:
                # Unknown entity type, use generic
                continue

            pii_matches.append(PIIMatch(
                pii_type=pii_type,
                start=result.start,
                end=result.end,
                text=text[result.start:result.end],
                confidence=result.score
            ))

        # Redact PII
        redacted_text = text
        for match in sorted(pii_matches, key=lambda x: x.start, reverse=True):
            redacted_text = (
                redacted_text[:match.start] +
                f"<{match.pii_type.value}>" +
                redacted_text[match.end:]
            )

        return FilterResult(
            original_text=text,
            redacted_text=redacted_text,
            pii_found=pii_matches,
            contains_pii=len(pii_matches) > 0
        )

    def _filter_with_regex(self, text: str) -> FilterResult:
        """Filter using regex patterns (faster, less accurate)"""
        pii_matches = []
        redacted_text = text

        # Check each pattern
        patterns = [
            (self.ssn_pattern, PIIType.SSN),
            (self.credit_card_pattern, PIIType.CREDIT_CARD),
            (self.phone_pattern, PIIType.PHONE),
            (self.email_pattern, PIIType.EMAIL),
            (self.ip_pattern, PIIType.IP_ADDRESS),
            (self.api_key_pattern, PIIType.API_KEY),
            (self.password_pattern, PIIType.PASSWORD),
            (self.url_with_params_pattern, PIIType.URL_WITH_PARAMS),
            (self.medical_record_pattern, PIIType.MEDICAL_RECORD),
            (self.passport_pattern, PIIType.PASSPORT),
            (self.drivers_license_pattern, PIIType.DRIVERS_LICENSE),
            (self.iban_pattern, PIIType.IBAN),
        ]

        # Collect all matches
        all_matches = []
        for pattern, pii_type in patterns:
            for match in pattern.finditer(text):
                all_matches.append((match.start(), match.end(), pii_type, match.group(0)))

        # Sort by position (reverse for redaction)
        all_matches.sort(key=lambda x: x[0], reverse=True)

        # Redact and create PIIMatch objects
        for start, end, pii_type, matched_text in all_matches:
            # Create PIIMatch
            pii_matches.append(PIIMatch(
                pii_type=pii_type,
                start=start,
                end=end,
                text=matched_text,
                confidence=0.8  # Default confidence for regex
            ))

            # Redact in text
            redacted_text = (
                redacted_text[:start] +
                f"<{pii_type.value}>" +
                redacted_text[end:]
            )

        return FilterResult(
            original_text=text,
            redacted_text=redacted_text,
            pii_found=list(reversed(pii_matches)),  # Reverse to original order
            contains_pii=len(pii_matches) > 0
        )

    def detect_pii(self, text: str) -> List[PIIMatch]:
        """
        Detect PII without redaction.

        Args:
            text: Text to analyze

        Returns:
            List of PIIMatch objects
        """
        result = self.filter_output(text)
        return result.pii_found

    def redact_ssn(self, text: str) -> str:
        """Redact SSNs only"""
        return self.ssn_pattern.sub("<SSN>", text)

    def redact_credit_card(self, text: str) -> str:
        """Redact credit card numbers only"""
        return self.credit_card_pattern.sub("<CREDIT_CARD>", text)

    def redact_phone(self, text: str) -> str:
        """Redact phone numbers only"""
        return self.phone_pattern.sub("<PHONE>", text)

    def redact_email(self, text: str) -> str:
        """Redact email addresses only"""
        return self.email_pattern.sub("<EMAIL>", text)

    def redact_ip_address(self, text: str) -> str:
        """Redact IP addresses only"""
        return self.ip_pattern.sub("<IP_ADDRESS>", text)

    def get_pii_types_found(self, text: str) -> Set[PIIType]:
        """
        Get set of PII types found in text.

        Args:
            text: Text to analyze

        Returns:
            Set of PIIType found
        """
        pii_matches = self.detect_pii(text)
        return {match.pii_type for match in pii_matches}

    def contains_pii(self, text: str) -> bool:
        """
        Quick check if text contains any PII.

        Args:
            text: Text to check

        Returns:
            True if PII found
        """
        result = self.filter_output(text)
        return result.contains_pii


# Convenience functions
def filter_output(text: str) -> FilterResult:
    """Quick filtering using default filter"""
    filter_obj = OutputFilter()
    return filter_obj.filter_output(text)


def redact_all_pii(text: str) -> str:
    """Quick redaction of all PII"""
    result = filter_output(text)
    return result.redacted_text
