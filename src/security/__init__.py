"""
Security Module - Week 9 Security Hardening

Components:
- input_validator: Attack pattern detection (SQL injection, XSS, etc.)
- output_filter: PII detection and redaction
- rate_limiter: Token bucket rate limiting
- security_middleware: Unified security wrapper with circuit breaker
- audit_logger: JSON structured audit logging
"""

from .input_validator import InputValidator, ValidationResult, AttackType, SeverityLevel
from .output_filter import OutputFilter, FilterResult, PIIType
from .rate_limiter import RateLimiter, RateLimitConfig, RateLimitExceeded
from .security_middleware import (
    SecurityMiddleware,
    security_wrapper,
    SecurityError,
    CircuitBreakerOpen
)
from .audit_logger import AuditLogger, get_audit_logger

__all__ = [
    # Input validation
    "InputValidator",
    "ValidationResult",
    "AttackType",
    "SeverityLevel",
    # Output filtering
    "OutputFilter",
    "FilterResult",
    "PIIType",
    # Rate limiting
    "RateLimiter",
    "RateLimitConfig",
    "RateLimitExceeded",
    # Security middleware
    "SecurityMiddleware",
    "security_wrapper",
    "SecurityError",
    "CircuitBreakerOpen",
    # Audit logging
    "AuditLogger",
    "get_audit_logger",
]
