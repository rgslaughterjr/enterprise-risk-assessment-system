"""Security Middleware - Input/Output Security Wrapper"""
from functools import wraps
from src.security.input_validator import InputValidator
from src.security.output_filter import OutputFilter
import logging

logger = logging.getLogger(__name__)

validator = InputValidator()
output_filter = OutputFilter()

def security_wrapper(func):
    """Decorator to wrap functions with security checks."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Validate inputs
        for arg in args:
            if isinstance(arg, str):
                threats = validator.detect_threats(arg)
                if any(t.should_block for t in threats):
                    logger.error(f"Blocked malicious input to {func.__name__}")
                    raise ValueError("Malicious input detected and blocked")

        # Execute function
        result = func(*args, **kwargs)

        # Filter output
        if isinstance(result, str):
            result = output_filter.redact_pii(result)

        return result
    return wrapper
