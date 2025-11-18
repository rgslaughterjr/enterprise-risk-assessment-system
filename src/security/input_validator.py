"""
Input Validator - Week 9 Security Hardening

Detects and blocks malicious inputs:
- SQL injection (40+ patterns)
- Prompt injection
- XSS attacks
- Path traversal
- Command injection

Usage:
    validator = InputValidator()
    result = validator.validate_input("user input")
    if result.is_malicious:
        raise SecurityError(f"Attack detected: {result.attack_type}")
"""

import re
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
import html
import urllib.parse


class AttackType(Enum):
    """Types of attacks detected"""
    SQL_INJECTION = "sql_injection"
    PROMPT_INJECTION = "prompt_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    SAFE = "safe"


class SeverityLevel(Enum):
    """Severity levels for detected attacks"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class ValidationResult:
    """Result of input validation"""
    is_malicious: bool
    attack_type: AttackType
    severity: SeverityLevel
    matched_pattern: Optional[str] = None
    confidence: float = 0.0  # 0.0 to 1.0
    sanitized_input: Optional[str] = None


class InputValidator:
    """
    Comprehensive input validation to detect and block malicious inputs.

    Features:
    - 40+ attack patterns across 7 attack categories
    - Severity scoring
    - Input sanitization
    - Pattern matching with confidence scores
    """

    def __init__(self):
        """Initialize validator with attack patterns"""
        self._init_sql_patterns()
        self._init_prompt_patterns()
        self._init_xss_patterns()
        self._init_path_traversal_patterns()
        self._init_command_injection_patterns()
        self._init_ldap_patterns()
        self._init_xml_patterns()

    def _init_sql_patterns(self):
        """Initialize SQL injection patterns (15 patterns)"""
        self.sql_patterns = [
            # Classic SQL injection
            (r"(?i)(\bUNION\b.*\bSELECT\b)", SeverityLevel.CRITICAL),
            (r"(?i)(\bSELECT\b.*\bFROM\b.*\bWHERE\b)", SeverityLevel.HIGH),
            (r"(?i)(\bINSERT\b.*\bINTO\b.*\bVALUES\b)", SeverityLevel.CRITICAL),
            (r"(?i)(\bDELETE\b.*\bFROM\b)", SeverityLevel.CRITICAL),
            (r"(?i)(\bDROP\b.*\b(TABLE|DATABASE)\b)", SeverityLevel.CRITICAL),
            (r"(?i)(\bUPDATE\b.*\bSET\b)", SeverityLevel.HIGH),

            # SQL comments for bypassing
            (r"(--|\#|\/\*|\*\/)", SeverityLevel.MEDIUM),

            # Boolean-based blind injection
            (r"(?i)(\bOR\b.*=.*)", SeverityLevel.HIGH),
            (r"(?i)(\bAND\b.*=.*)", SeverityLevel.HIGH),
            (r"(?i)(1\s*=\s*1)", SeverityLevel.HIGH),
            (r"(?i)(1\s*=\s*0)", SeverityLevel.HIGH),

            # Time-based blind injection
            (r"(?i)(\bSLEEP\b\s*\()", SeverityLevel.HIGH),
            (r"(?i)(\bBENCHMARK\b\s*\()", SeverityLevel.HIGH),
            (r"(?i)(\bWAITFOR\b.*\bDELAY\b)", SeverityLevel.HIGH),

            # Stacked queries
            (r";\s*(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)", SeverityLevel.CRITICAL),
        ]

    def _init_prompt_patterns(self):
        """Initialize prompt injection patterns (10 patterns)"""
        self.prompt_patterns = [
            # System prompt overrides
            (r"(?i)(ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?))", SeverityLevel.CRITICAL),
            (r"(?i)(disregard\s+(previous|above|all)\s+(instructions?|prompts?|rules?))", SeverityLevel.CRITICAL),
            (r"(?i)(forget\s+(previous|above|all)\s+(instructions?|prompts?|rules?))", SeverityLevel.CRITICAL),

            # Role manipulation
            (r"(?i)(you\s+are\s+now|act\s+as|roleplay\s+as)\s+(?!a\s+helpful)", SeverityLevel.HIGH),
            (r"(?i)(new\s+instructions?|system\s+prompt|developer\s+mode)", SeverityLevel.HIGH),

            # Jailbreak attempts
            (r"(?i)(DAN|STAN|jailbreak|unrestricted\s+mode)", SeverityLevel.CRITICAL),
            (r"(?i)(bypass\s+(filter|safety|rules?))", SeverityLevel.CRITICAL),

            # Delimiter injection
            (r"(```|###|\"\"\"|''')(system|assistant|user)", SeverityLevel.HIGH),

            # Token manipulation
            (r"(?i)(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>)", SeverityLevel.HIGH),

            # Data exfiltration
            (r"(?i)(repeat\s+back|print\s+out|show\s+me)\s+(your\s+)?(instructions?|prompt|system)", SeverityLevel.MEDIUM),
        ]

    def _init_xss_patterns(self):
        """Initialize XSS patterns (8 patterns)"""
        self.xss_patterns = [
            # Script tags
            (r"<\s*script[^>]*>", SeverityLevel.CRITICAL),
            (r"<\s*/\s*script\s*>", SeverityLevel.CRITICAL),

            # Event handlers
            (r"(?i)on(load|error|click|mouse\w+|focus|blur)\s*=", SeverityLevel.HIGH),

            # JavaScript protocol
            (r"(?i)javascript\s*:", SeverityLevel.HIGH),
            (r"(?i)vbscript\s*:", SeverityLevel.HIGH),

            # Data URIs
            (r"(?i)data\s*:\s*text/html", SeverityLevel.HIGH),

            # Iframe injection
            (r"<\s*iframe[^>]*>", SeverityLevel.HIGH),

            # SVG with script
            (r"<\s*svg[^>]*>.*<\s*script", SeverityLevel.CRITICAL),
        ]

    def _init_path_traversal_patterns(self):
        """Initialize path traversal patterns (5 patterns)"""
        self.path_traversal_patterns = [
            # Directory traversal
            (r"\.\./", SeverityLevel.HIGH),
            (r"\.\.\\", SeverityLevel.HIGH),

            # Encoded traversal
            (r"%2e%2e[/\\]", SeverityLevel.HIGH),
            (r"\.\.%2f", SeverityLevel.HIGH),

            # Absolute paths to sensitive files
            (r"(?i)(/etc/passwd|/etc/shadow|C:\\Windows\\System32)", SeverityLevel.CRITICAL),
        ]

    def _init_command_injection_patterns(self):
        """Initialize command injection patterns (7 patterns)"""
        self.command_injection_patterns = [
            # Shell command separators
            (r"[;|&]\s*(cat|ls|dir|whoami|id|pwd|wget|curl|nc|netcat)", SeverityLevel.CRITICAL),

            # Command substitution
            (r"`[^`]+`", SeverityLevel.HIGH),
            (r"\$\([^\)]+\)", SeverityLevel.HIGH),

            # Pipe to shell
            (r"\|\s*(sh|bash|zsh|fish|cmd)", SeverityLevel.CRITICAL),

            # Redirection
            (r">\s*/\w+", SeverityLevel.MEDIUM),

            # Environment variable manipulation
            (r"\$\{?(PATH|LD_PRELOAD|LD_LIBRARY_PATH)", SeverityLevel.HIGH),

            # PowerShell
            (r"(?i)(Invoke-Expression|iex|powershell)", SeverityLevel.HIGH),
        ]

    def _init_ldap_patterns(self):
        """Initialize LDAP injection patterns (3 patterns)"""
        self.ldap_patterns = [
            # LDAP filter manipulation
            (r"\*\)\(", SeverityLevel.HIGH),
            (r"\(\|", SeverityLevel.HIGH),
            (r"\(&", SeverityLevel.HIGH),
        ]

    def _init_xml_patterns(self):
        """Initialize XML injection patterns (3 patterns)"""
        self.xml_patterns = [
            # XXE (XML External Entity)
            (r"<!ENTITY", SeverityLevel.CRITICAL),
            (r"<!DOCTYPE.*SYSTEM", SeverityLevel.CRITICAL),

            # CDATA injection
            (r"<!\[CDATA\[", SeverityLevel.MEDIUM),
        ]

    def validate_input(self, user_input: str) -> ValidationResult:
        """
        Validate input against all attack patterns.

        Args:
            user_input: String to validate

        Returns:
            ValidationResult with detection results
        """
        if not user_input or not isinstance(user_input, str):
            return ValidationResult(
                is_malicious=False,
                attack_type=AttackType.SAFE,
                severity=SeverityLevel.NONE,
                sanitized_input=user_input
            )

        # Check each attack category
        checks = [
            (self.detect_sql_injection, AttackType.SQL_INJECTION),
            (self.detect_prompt_injection, AttackType.PROMPT_INJECTION),
            (self.detect_xss, AttackType.XSS),
            (self.detect_path_traversal, AttackType.PATH_TRAVERSAL),
            (self.detect_command_injection, AttackType.COMMAND_INJECTION),
            (self.detect_ldap_injection, AttackType.LDAP_INJECTION),
            (self.detect_xml_injection, AttackType.XML_INJECTION),
        ]

        for check_func, attack_type in checks:
            is_attack, severity, pattern, confidence = check_func(user_input)
            if is_attack:
                return ValidationResult(
                    is_malicious=True,
                    attack_type=attack_type,
                    severity=severity,
                    matched_pattern=pattern,
                    confidence=confidence,
                    sanitized_input=self.sanitize_input(user_input)
                )

        # No attacks detected
        return ValidationResult(
            is_malicious=False,
            attack_type=AttackType.SAFE,
            severity=SeverityLevel.NONE,
            sanitized_input=user_input
        )

    def detect_sql_injection(self, user_input: str) -> Tuple[bool, SeverityLevel, Optional[str], float]:
        """Detect SQL injection patterns"""
        return self._check_patterns(user_input, self.sql_patterns)

    def detect_prompt_injection(self, user_input: str) -> Tuple[bool, SeverityLevel, Optional[str], float]:
        """Detect prompt injection patterns"""
        return self._check_patterns(user_input, self.prompt_patterns)

    def detect_xss(self, user_input: str) -> Tuple[bool, SeverityLevel, Optional[str], float]:
        """Detect XSS patterns"""
        return self._check_patterns(user_input, self.xss_patterns)

    def detect_path_traversal(self, user_input: str) -> Tuple[bool, SeverityLevel, Optional[str], float]:
        """Detect path traversal patterns"""
        return self._check_patterns(user_input, self.path_traversal_patterns)

    def detect_command_injection(self, user_input: str) -> Tuple[bool, SeverityLevel, Optional[str], float]:
        """Detect command injection patterns"""
        return self._check_patterns(user_input, self.command_injection_patterns)

    def detect_ldap_injection(self, user_input: str) -> Tuple[bool, SeverityLevel, Optional[str], float]:
        """Detect LDAP injection patterns"""
        return self._check_patterns(user_input, self.ldap_patterns)

    def detect_xml_injection(self, user_input: str) -> Tuple[bool, SeverityLevel, Optional[str], float]:
        """Detect XML injection patterns"""
        return self._check_patterns(user_input, self.xml_patterns)

    def _check_patterns(
        self,
        user_input: str,
        patterns: List[Tuple[str, SeverityLevel]]
    ) -> Tuple[bool, SeverityLevel, Optional[str], float]:
        """
        Check input against a list of patterns.

        Returns: (is_attack, severity, matched_pattern, confidence)
        """
        for pattern, severity in patterns:
            match = re.search(pattern, user_input)
            if match:
                # Calculate confidence based on match quality
                confidence = min(1.0, len(match.group(0)) / 10.0)
                confidence = max(0.5, confidence)  # Minimum 0.5 for any match

                return True, severity, pattern, confidence

        return False, SeverityLevel.NONE, None, 0.0

    def sanitize_input(self, user_input: str) -> str:
        """
        Sanitize input by removing/escaping dangerous characters.

        Args:
            user_input: Input to sanitize

        Returns:
            Sanitized string
        """
        if not user_input:
            return user_input

        # HTML escape
        sanitized = html.escape(user_input)

        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')

        # Remove control characters except newline and tab
        sanitized = ''.join(
            char for char in sanitized
            if char in '\n\t' or ord(char) >= 32
        )

        return sanitized

    def get_attack_statistics(self) -> Dict[str, int]:
        """Get count of patterns per attack type"""
        return {
            "sql_injection": len(self.sql_patterns),
            "prompt_injection": len(self.prompt_patterns),
            "xss": len(self.xss_patterns),
            "path_traversal": len(self.path_traversal_patterns),
            "command_injection": len(self.command_injection_patterns),
            "ldap_injection": len(self.ldap_patterns),
            "xml_injection": len(self.xml_patterns),
            "total": (
                len(self.sql_patterns) +
                len(self.prompt_patterns) +
                len(self.xss_patterns) +
                len(self.path_traversal_patterns) +
                len(self.command_injection_patterns) +
                len(self.ldap_patterns) +
                len(self.xml_patterns)
            )
        }


# Convenience functions
def validate_input(user_input: str) -> ValidationResult:
    """Quick validation using singleton validator"""
    validator = InputValidator()
    return validator.validate_input(user_input)


def is_safe_input(user_input: str) -> bool:
    """Quick check if input is safe"""
    result = validate_input(user_input)
    return not result.is_malicious
