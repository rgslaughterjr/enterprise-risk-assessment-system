"""Unit tests for error handler utilities."""

import pytest
from unittest.mock import Mock, patch
import requests

from src.utils.error_handler import (
    APIError,
    RateLimitError,
    ValidationError,
    handle_api_response,
    validate_api_key,
    APIRateLimiter,
    log_api_call,
    retry_on_rate_limit,
    retry_on_api_error
)


class TestAPIError:
    def test_api_error_creation(self):
        error = APIError("Test error")
        assert str(error) == "Test error"

    def test_api_error_is_exception(self):
        assert issubclass(APIError, Exception)


class TestValidationError:
    def test_validation_error_creation(self):
        error = ValidationError("Validation failed")
        assert str(error) == "Validation failed"


class TestAPIKeyValidation:
    def test_validate_api_key_valid(self):
        # Should not raise
        validate_api_key("valid_key", "TestAPI")

    def test_validate_api_key_none(self):
        with pytest.raises(ValidationError):
            validate_api_key(None, "TestAPI")

    def test_validate_api_key_empty(self):
        with pytest.raises(ValidationError):
            validate_api_key("", "TestAPI")


class TestAPIResponseHandling:
    def test_handle_success_response(self):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {"data": "test"}

        result = handle_api_response(response, "TestAPI")
        assert result == {"data": "test"}

    def test_handle_rate_limit_response(self):
        """Test that 429 status raises RateLimitError."""
        response = Mock()
        response.status_code = 429
        response.text = "Rate limited"
        response.headers = {"Retry-After": "60"}
        response.raise_for_status = Mock(side_effect=requests.exceptions.HTTPError())

        with pytest.raises(RateLimitError):
            handle_api_response(response, "TestAPI")

    def test_handle_error_response(self):
        """Test that 500 status raises APIError."""
        response = Mock()
        response.status_code = 500
        response.text = "Server error"
        response.raise_for_status = Mock(side_effect=requests.exceptions.HTTPError())

        with pytest.raises(APIError):
            handle_api_response(response, "TestAPI")


class TestRateLimiter:
    def test_rate_limiter_initialization(self):
        limiter = APIRateLimiter(calls_per_period=5, period_seconds=60)
        assert limiter.calls_per_period == 5
        assert limiter.period_seconds == 60

    def test_rate_limiter_context_manager(self):
        limiter = APIRateLimiter(calls_per_period=10, period_seconds=1)
        with limiter:
            pass  # Should not raise


class TestLogging:
    @patch("src.utils.error_handler.logger")
    def test_log_api_call(self, mock_logger):
        """Test that API calls are logged."""
        log_api_call("TestAPI", "https://api.test.com", {"param": "value"})
        # Verify that info was called (log_api_call uses logger.info, not debug)
        assert mock_logger.info.call_count >= 1


class TestRetryDecorators:
    def test_retry_decorator_exists(self):
        assert callable(retry_on_rate_limit)
        assert callable(retry_on_api_error)

    def test_retry_on_rate_limit_decorator(self):
        @retry_on_rate_limit(max_attempts=2)
        def test_func():
            return "success"

        result = test_func()
        assert result == "success"

    def test_retry_on_api_error_decorator(self):
        @retry_on_api_error(max_attempts=2)
        def test_func():
            return "success"

        result = test_func()
        assert result == "success"
