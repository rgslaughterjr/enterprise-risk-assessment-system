"""
Input Validator - Security Threat Detection

Detects and blocks malicious input including SQL injection, prompt injection,
XSS, path traversal, and command injection attacks.
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Types of security threats."""
    SQL_INJECTION = "sql_injection"
    PROMPT_INJECTION = "prompt_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"


class ThreatSeverity(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatDetection:
    """Detected security threat."""
    threat_type: ThreatType
    severity: ThreatSeverity
    pattern_matched: str
    location: int
    description: str
    should_block: bool


class InputValidator:
    """Validates and sanitizes user input to detect security threats."""

    # SQL Injection patterns
    SQL_PATTERNS = [
        (r"(?i)(\bUNION\b.*\bSELECT\b)", ThreatSeverity.CRITICAL),
        (r"(?i)(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)", ThreatSeverity.CRITICAL),
        (r"(?i)(\bAND\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)", ThreatSeverity.HIGH),
        (r"(?i)(;\s*DROP\s+TABLE)", ThreatSeverity.CRITICAL),
        (r"(?i)(;\s*DELETE\s+FROM)", ThreatSeverity.CRITICAL),
        (r"(?i)(;\s*UPDATE\s+.*\s+SET)", ThreatSeverity.CRITICAL),
        (r"(?i)(\bEXEC\b\s*\()", ThreatSeverity.HIGH),
        (r"(?i)('.*--)", ThreatSeverity.HIGH),
        (r"(?i)(xp_cmdshell)", ThreatSeverity.CRITICAL),
    ]

    # Prompt Injection patterns (LLM-specific)
    PROMPT_INJECTION_PATTERNS = [
        (r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|commands))", ThreatSeverity.CRITICAL),
        (r"(?i)(disregard\s+(all\s+)?(previous|prior)\s+(instructions|prompts))", ThreatSeverity.CRITICAL),
        (r"(?i)(system\s*:?\s*(you\s+are|pretend|act\s+as))", ThreatSeverity.HIGH),
        (r"(?i)(new\s+instructions?:)", ThreatSeverity.HIGH),
        (r"(?i)(forget\s+(everything|all)\s+(you|that))", ThreatSeverity.HIGH),
        (r"(?i)(now\s+you\s+(are|must|will)\s+)", ThreatSeverity.MEDIUM),
        (r"(?i)(reveal\s+(your\s+)?(system\s+)?(prompt|instructions))", ThreatSeverity.HIGH),
        (r"(?i)(show\s+me\s+your\s+(system\s+)?prompt)", ThreatSeverity.HIGH),
        (r"(?i)(<\|.*\|>)", ThreatSeverity.MEDIUM),  # Special tokens
    ]

    # XSS patterns
    XSS_PATTERNS = [
        (r"(?i)(<script[^>]*>)", ThreatSeverity.CRITICAL),
        (r"(?i)(javascript:)", ThreatSeverity.HIGH),
        (r"(?i)(on\w+\s*=)", ThreatSeverity.HIGH),  # onerror=, onclick=, etc.
        (r"(?i)(<iframe)", ThreatSeverity.HIGH),
        (r"(?i)(<object)", ThreatSeverity.HIGH),
        (r"(?i)(<embed)", ThreatSeverity.HIGH),
        (r"(?i)(eval\s*\()", ThreatSeverity.HIGH),
    ]

    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        (r"(\.\.[\\/]){2,}", ThreatSeverity.CRITICAL),
        (r"(?i)(\.\.%2[fF])", ThreatSeverity.CRITICAL),
        (r"(?i)(%2e%2e[\\/])", ThreatSeverity.HIGH),
        (r"(?i)(/etc/passwd)", ThreatSeverity.CRITICAL),
        (r"(?i)(/etc/shadow)", ThreatSeverity.CRITICAL),
        (r"(?i)(C:\\\\Windows)", ThreatSeverity.HIGH),
    ]

    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        (r"(;\s*\w+)", ThreatSeverity.HIGH),
        (r"(\|\s*\w+)", ThreatSeverity.HIGH),
        (r"(\$\(.*\))", ThreatSeverity.CRITICAL),
        (r"(`.*`)", ThreatSeverity.CRITICAL),
        (r"(&&\s*\w+)", ThreatSeverity.HIGH),
        (r"(\|\|\s*\w+)", ThreatSeverity.MEDIUM),
    ]

    def __init__(self, block_on_severity: Optional[ThreatSeverity] = None):
        """
        Initialize input validator.

        Args:
            block_on_severity: Block input if threat >= this severity (default: HIGH)
        """
        self.block_on_severity = block_on_severity or ThreatSeverity.HIGH
        self._severity_levels = {
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4
        }
        logger.info(f"Initialized InputValidator (block_on={self.block_on_severity.value})")

    def detect_threats(self, input_text: str) -> List[ThreatDetection]:
        """
        Detect security threats in input text.

        Args:
            input_text: User input to validate

        Returns:
            List of detected threats
        """
        if not input_text:
            return []

        threats = []

        # Check SQL injection
        threats.extend(self._check_patterns(input_text, self.SQL_PATTERNS, ThreatType.SQL_INJECTION))

        # Check prompt injection
        threats.extend(self._check_patterns(input_text, self.PROMPT_INJECTION_PATTERNS,
                                           ThreatType.PROMPT_INJECTION))

        # Check XSS
        threats.extend(self._check_patterns(input_text, self.XSS_PATTERNS, ThreatType.XSS))

        # Check path traversal
        threats.extend(self._check_patterns(input_text, self.PATH_TRAVERSAL_PATTERNS,
                                           ThreatType.PATH_TRAVERSAL))

        # Check command injection
        threats.extend(self._check_patterns(input_text, self.COMMAND_INJECTION_PATTERNS,
                                           ThreatType.COMMAND_INJECTION))

        # Determine if should block
        for threat in threats:
            threat.should_block = self._should_block(threat.severity)

        if threats:
            logger.warning(f"Detected {len(threats)} threats in input (length={len(input_text)})")

        return threats

    def _check_patterns(self, text: str, patterns: List[tuple],
                       threat_type: ThreatType) -> List[ThreatDetection]:
        """Check text against patterns."""
        threats = []
        for pattern, severity in patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                threats.append(ThreatDetection(
                    threat_type=threat_type,
                    severity=severity,
                    pattern_matched=match.group(0),
                    location=match.start(),
                    description=self._get_threat_description(threat_type, match.group(0)),
                    should_block=False  # Will be set later
                ))
        return threats

    def _should_block(self, severity: ThreatSeverity) -> bool:
        """Determine if threat should block the request."""
        return self._severity_levels[severity] >= self._severity_levels[self.block_on_severity]

    def _get_threat_description(self, threat_type: ThreatType, pattern: str) -> str:
        """Get human-readable threat description."""
        descriptions = {
            ThreatType.SQL_INJECTION: f"Potential SQL injection attack detected: {pattern[:50]}",
            ThreatType.PROMPT_INJECTION: f"Prompt injection attempt detected: {pattern[:50]}",
            ThreatType.XSS: f"Cross-site scripting (XSS) pattern detected: {pattern[:50]}",
            ThreatType.PATH_TRAVERSAL: f"Path traversal attack detected: {pattern[:50]}",
            ThreatType.COMMAND_INJECTION: f"Command injection attempt detected: {pattern[:50]}",
        }
        return descriptions.get(threat_type, f"Security threat detected: {pattern[:50]}")

    def sanitize_input(self, input_text: str, remove_on_detect: bool = False) -> str:
        """
        Sanitize input by removing or escaping malicious content.

        Args:
            input_text: Text to sanitize
            remove_on_detect: If True, remove detected threats; if False, escape them

        Returns:
            Sanitized text
        """
        if not input_text:
            return input_text

        threats = self.detect_threats(input_text)
        sanitized = input_text

        if remove_on_detect:
            # Remove detected threat patterns (in reverse order to preserve positions)
            for threat in sorted(threats, key=lambda t: t.location, reverse=True):
                pattern_len = len(threat.pattern_matched)
                sanitized = sanitized[:threat.location] + sanitized[threat.location + pattern_len:]
        else:
            # Escape HTML special characters
            sanitized = (sanitized
                        .replace('&', '&amp;')
                        .replace('<', '&lt;')
                        .replace('>', '&gt;')
                        .replace('"', '&quot;')
                        .replace("'", '&#x27;'))

        return sanitized

    def is_safe(self, input_text: str) -> bool:
        """
        Check if input is safe (no blockable threats).

        Args:
            input_text: Text to check

        Returns:
            True if safe, False if contains blockable threats
        """
        threats = self.detect_threats(input_text)
        return not any(t.should_block for t in threats)
