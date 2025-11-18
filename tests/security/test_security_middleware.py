"""Tests for Security Middleware - Week 9"""

import pytest
import time
from src.security.security_middleware import (
    SecurityMiddleware, SecurityError, CircuitBreakerOpen,
    security_wrapper, CircuitBreaker, CircuitState
)


class TestCircuitBreaker:
    @pytest.fixture
    def circuit_breaker(self):
        from src.security.security_middleware import CircuitBreakerConfig
        config = CircuitBreakerConfig(attack_threshold=3, time_window_seconds=60)
        return CircuitBreaker(config)

    def test_circuit_initially_closed(self, circuit_breaker):
        assert circuit_breaker.check_circuit("user1")

    def test_circuit_opens_after_attacks(self, circuit_breaker):
        from src.security.input_validator import AttackType, SeverityLevel
        
        # Record 3 attacks
        for i in range(3):
            circuit_breaker.record_attack("user1", AttackType.SQL_INJECTION, SeverityLevel.HIGH)
        
        # Circuit should be open
        assert not circuit_breaker.check_circuit("user1")

    def test_circuit_different_users(self, circuit_breaker):
        from src.security.input_validator import AttackType, SeverityLevel
        
        # User1 triggers circuit breaker
        for i in range(3):
            circuit_breaker.record_attack("user1", AttackType.SQL_INJECTION, SeverityLevel.HIGH)
        
        # User2 should still work
        assert circuit_breaker.check_circuit("user2")

    def test_record_success_closes_circuit(self, circuit_breaker):
        circuit_breaker.circuit_states["user1"] = CircuitState.HALF_OPEN
        circuit_breaker.record_success("user1")
        assert circuit_breaker.get_state("user1") == CircuitState.CLOSED

    def test_reset_circuit(self, circuit_breaker):
        from src.security.input_validator import AttackType, SeverityLevel
        
        for i in range(3):
            circuit_breaker.record_attack("user1", AttackType.SQL_INJECTION, SeverityLevel.HIGH)
        
        circuit_breaker.reset_circuit("user1")
        assert circuit_breaker.check_circuit("user1")


class TestSecurityMiddleware:
    @pytest.fixture
    def middleware(self):
        return SecurityMiddleware(
            enable_input_validation=True,
            enable_output_filtering=True,
            enable_rate_limiting=False,  # Disable for simpler testing
            enable_circuit_breaker=True,
            enable_audit_logging=False  # Disable for simpler testing
        )

    def test_safe_function_call(self, middleware):
        def safe_func(msg):
            return f"Processed: {msg}"
        
        result = middleware.wrap_call(safe_func, "Hello world", user_id="user1")
        assert result == "Processed: Hello world"

    def test_malicious_input_blocked(self, middleware):
        def process_func(msg):
            return f"Processed: {msg}"
        
        with pytest.raises(SecurityError):
            middleware.wrap_call(process_func, "'; DROP TABLE users--", user_id="user1")

    def test_pii_filtered_in_output(self, middleware):
        def return_pii():
            return "User SSN is 123-45-6789"
        
        result = middleware.wrap_call(return_pii, user_id="user1")
        assert "<SSN>" in result
        assert "123-45-6789" not in result

    def test_circuit_breaker_blocks(self, middleware):
        def malicious_func(msg):
            return msg
        
        # Trigger circuit breaker with multiple attacks
        for i in range(5):
            try:
                middleware.wrap_call(malicious_func, "'; DROP TABLE users--", user_id="user2")
            except SecurityError:
                pass
        
        # Circuit should be open
        def safe_func(msg):
            return msg
        
        with pytest.raises(CircuitBreakerOpen):
            middleware.wrap_call(safe_func, "normal input", user_id="user2")

    def test_decorator_safe_call(self):
        @security_wrapper(user_id="user1", validate_input=True, filter_output=True)
        def decorated_func(msg):
            return f"Result: {msg}"
        
        result = decorated_func("test")
        assert "Result: test" in result

    def test_decorator_blocks_attack(self):
        @security_wrapper(user_id="user1", validate_input=True)
        def decorated_func(msg):
            return f"Result: {msg}"
        
        with pytest.raises(SecurityError):
            decorated_func("'; DROP TABLE users--")

    def test_skip_input_validation(self, middleware):
        def process_func(msg):
            return msg
        
        # Should not raise even with malicious input
        result = middleware.wrap_call(
            process_func,
            "'; DROP TABLE users--",
            user_id="user1",
            validate_input=False
        )
        assert result == "'; DROP TABLE users--"

    def test_skip_output_filtering(self, middleware):
        def return_pii():
            return "SSN: 123-45-6789"
        
        result = middleware.wrap_call(
            return_pii,
            user_id="user1",
            filter_output=False
        )
        assert "123-45-6789" in result

    def test_exception_propagation(self, middleware):
        def failing_func():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            middleware.wrap_call(failing_func, user_id="user1")
