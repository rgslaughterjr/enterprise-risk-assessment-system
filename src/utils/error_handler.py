"""Error handling utilities with retry logic and exponential backoff.

This module provides decorators and utilities for handling API errors, rate limits,
and implementing retry logic with exponential backoff.
"""

import time
import logging
from functools import wraps
from typing import Callable, Optional, Tuple, Type
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# Custom Exceptions
# ============================================================================

class APIError(Exception):
    """Base exception for API errors."""

    pass


class RateLimitError(APIError):
    """Exception raised when API rate limit is exceeded."""

    pass


class AuthenticationError(APIError):
    """Exception raised for authentication failures."""

    pass


class NotFoundError(APIError):
    """Exception raised when resource is not found."""

    pass


class ValidationError(APIError):
    """Exception raised for validation errors."""

    pass


# ============================================================================
# Retry Decorators
# ============================================================================

def retry_on_rate_limit(max_attempts: int = 5, min_wait: int = 2, max_wait: int = 60):
    """Decorator for retrying on rate limit errors with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts
        min_wait: Minimum wait time in seconds
        max_wait: Maximum wait time in seconds

    Returns:
        Decorated function with retry logic
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type(RateLimitError),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )


def retry_on_api_error(max_attempts: int = 3, min_wait: int = 1, max_wait: int = 10):
    """Decorator for retrying on general API errors.

    Args:
        max_attempts: Maximum number of retry attempts
        min_wait: Minimum wait time in seconds
        max_wait: Maximum wait time in seconds

    Returns:
        Decorated function with retry logic
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type((APIError, requests.RequestException)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )


# ============================================================================
# Error Handling Functions
# ============================================================================

def handle_api_response(response: requests.Response, api_name: str = "API") -> dict:
    """Handle API response and raise appropriate exceptions.

    Args:
        response: HTTP response object
        api_name: Name of the API for error messages

    Returns:
        JSON response data

    Raises:
        AuthenticationError: For 401/403 errors
        NotFoundError: For 404 errors
        RateLimitError: For 429 errors
        APIError: For other error status codes
    """
    try:
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        status_code = response.status_code

        # Authentication errors
        if status_code in (401, 403):
            logger.error(f"{api_name} authentication failed: {e}")
            raise AuthenticationError(f"{api_name} authentication failed: {e}")

        # Not found errors
        elif status_code == 404:
            logger.warning(f"{api_name} resource not found: {e}")
            raise NotFoundError(f"{api_name} resource not found: {e}")

        # Rate limit errors
        elif status_code == 429:
            retry_after = response.headers.get("Retry-After", 60)
            logger.warning(f"{api_name} rate limit exceeded. Retry after {retry_after}s")
            raise RateLimitError(f"{api_name} rate limit exceeded. Retry after {retry_after}s")

        # Other errors
        else:
            logger.error(f"{api_name} error {status_code}: {e}")
            raise APIError(f"{api_name} error {status_code}: {e}")

    except requests.exceptions.JSONDecodeError as e:
        logger.error(f"{api_name} returned invalid JSON: {e}")
        raise APIError(f"{api_name} returned invalid JSON: {e}")


def safe_api_call(
    func: Callable,
    default_return: Optional[any] = None,
    log_errors: bool = True,
) -> Callable:
    """Decorator to safely execute API calls with error handling.

    Args:
        func: Function to decorate
        default_return: Default value to return on error
        log_errors: Whether to log errors

    Returns:
        Decorated function
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if log_errors:
                logger.error(f"Error in {func.__name__}: {e}")
            return default_return

    return wrapper


def validate_api_key(api_key: Optional[str], api_name: str) -> None:
    """Validate that API key is provided and non-empty.

    Args:
        api_key: API key to validate
        api_name: Name of the API for error messages

    Raises:
        ValidationError: If API key is missing or empty
    """
    if not api_key or api_key.strip() == "":
        raise ValidationError(f"{api_name} API key is required but not provided")


def parse_error_message(response: requests.Response) -> str:
    """Extract error message from API response.

    Args:
        response: HTTP response object

    Returns:
        Error message string
    """
    try:
        error_data = response.json()
        # Try common error message keys
        for key in ["error", "message", "detail", "error_description"]:
            if key in error_data:
                return str(error_data[key])
        return str(error_data)
    except:
        return response.text or f"HTTP {response.status_code}"


# ============================================================================
# Context Managers
# ============================================================================

class APIRateLimiter:
    """Context manager for rate limiting API calls.

    Ensures minimum time between API calls to avoid rate limits.
    """

    def __init__(self, calls_per_period: int, period_seconds: int):
        """Initialize rate limiter.

        Args:
            calls_per_period: Maximum number of calls allowed in period
            period_seconds: Time period in seconds
        """
        self.calls_per_period = calls_per_period
        self.period_seconds = period_seconds
        self.call_times = []

    def __enter__(self):
        """Wait if necessary before allowing API call."""
        now = time.time()

        # Remove calls outside the current period
        self.call_times = [t for t in self.call_times if now - t < self.period_seconds]

        # If at limit, wait until oldest call expires
        if len(self.call_times) >= self.calls_per_period:
            sleep_time = self.period_seconds - (now - self.call_times[0]) + 0.1
            if sleep_time > 0:
                logger.info(f"Rate limit reached. Waiting {sleep_time:.2f}s")
                time.sleep(sleep_time)
                now = time.time()
                self.call_times = [t for t in self.call_times if now - t < self.period_seconds]

        # Record this call
        self.call_times.append(now)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        pass


# ============================================================================
# Utility Functions
# ============================================================================

def log_api_call(api_name: str, endpoint: str, params: dict = None) -> None:
    """Log API call details.

    Args:
        api_name: Name of the API
        endpoint: API endpoint
        params: Query parameters (sensitive values will be masked)
    """
    # Mask sensitive parameters
    safe_params = {}
    if params:
        for key, value in params.items():
            if any(sensitive in key.lower() for sensitive in ["key", "token", "password", "secret"]):
                safe_params[key] = "***MASKED***"
            else:
                safe_params[key] = value

    logger.info(f"{api_name} API call: {endpoint} | Params: {safe_params}")


def calculate_backoff(attempt: int, base: int = 2, max_backoff: int = 60) -> int:
    """Calculate exponential backoff time.

    Args:
        attempt: Current attempt number (0-indexed)
        base: Base multiplier for exponential backoff
        max_backoff: Maximum backoff time in seconds

    Returns:
        Backoff time in seconds
    """
    backoff = min(base ** attempt, max_backoff)
    return backoff
