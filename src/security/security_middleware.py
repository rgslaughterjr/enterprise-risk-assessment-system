"""
Security Middleware - Week 9 Security Hardening

Unified security wrapper for all agent calls:
- Input validation (SQL injection, XSS, prompt injection, etc.)
- Output filtering (PII redaction)
- Rate limiting (100 req/hour, 10 burst/min)
- Circuit breaker (block after 5 attacks in 10 min)
- Audit logging

Usage:
    @security_wrapper(user_id="user123", endpoint="/api/assess")
    def risky_function(user_input: str) -> str:
        # Process input
        return result

    # Or use directly
    middleware = SecurityMiddleware()
    result = middleware.wrap_call(func, user_input, user_id="user123")
"""

import functools
import time
from typing import Any, Callable, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading

from .input_validator import InputValidator, AttackType, SeverityLevel
from .output_filter import OutputFilter
from .rate_limiter import RateLimiter, RateLimitConfig, RateLimitExceeded
from .audit_logger import AuditLogger


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    # Attack threshold
    attack_threshold: int = 5  # Number of attacks before opening circuit
    time_window_seconds: int = 600  # 10 minutes

    # Circuit states
    cooldown_seconds: int = 300  # 5 minutes before trying half-open


class CircuitState:
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Blocking all requests
    HALF_OPEN = "half_open"  # Testing if attacks stopped


@dataclass
class AttackRecord:
    """Record of an attack attempt"""
    timestamp: float
    attack_type: AttackType
    severity: SeverityLevel
    user_id: str
    endpoint: Optional[str]
    input_sample: str  # First 100 chars


class CircuitBreaker:
    """
    Circuit breaker to block users after repeated attacks.

    States:
    - CLOSED: Normal operation, tracking attacks
    - OPEN: Blocking all requests after threshold exceeded
    - HALF_OPEN: Testing if attacks stopped after cooldown
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        """Initialize circuit breaker"""
        self.config = config or CircuitBreakerConfig()

        # Attack tracking: {user_id: deque of timestamps}
        self.attack_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Circuit states: {user_id: state}
        self.circuit_states: Dict[str, str] = defaultdict(lambda: CircuitState.CLOSED)

        # State transition times: {user_id: timestamp}
        self.state_transitions: Dict[str, float] = {}

        # Thread lock
        self.lock = threading.Lock()

    def record_attack(self, user_id: str, attack_type: AttackType, severity: SeverityLevel):
        """
        Record an attack and update circuit state.

        Args:
            user_id: User identifier
            attack_type: Type of attack detected
            severity: Severity level
        """
        with self.lock:
            now = time.time()

            # Add to attack history
            self.attack_history[user_id].append(now)

            # Clean old attacks outside time window
            cutoff = now - self.config.time_window_seconds
            while self.attack_history[user_id] and self.attack_history[user_id][0] < cutoff:
                self.attack_history[user_id].popleft()

            # Check if threshold exceeded
            recent_attacks = len(self.attack_history[user_id])
            if recent_attacks >= self.config.attack_threshold:
                # Open circuit
                self.circuit_states[user_id] = CircuitState.OPEN
                self.state_transitions[user_id] = now

    def check_circuit(self, user_id: str) -> bool:
        """
        Check if circuit allows request.

        Args:
            user_id: User identifier

        Returns:
            True if request allowed, False if blocked
        """
        with self.lock:
            state = self.circuit_states[user_id]
            now = time.time()

            if state == CircuitState.CLOSED:
                return True

            elif state == CircuitState.OPEN:
                # Check if cooldown period has passed
                transition_time = self.state_transitions.get(user_id, now)
                if now - transition_time >= self.config.cooldown_seconds:
                    # Try half-open
                    self.circuit_states[user_id] = CircuitState.HALF_OPEN
                    return True
                else:
                    return False

            elif state == CircuitState.HALF_OPEN:
                # Allow request to test if attacks stopped
                return True

            return False

    def record_success(self, user_id: str):
        """
        Record successful (non-attack) request.

        Args:
            user_id: User identifier
        """
        with self.lock:
            if self.circuit_states[user_id] == CircuitState.HALF_OPEN:
                # Close circuit after successful request in half-open state
                self.circuit_states[user_id] = CircuitState.CLOSED
                self.attack_history[user_id].clear()

    def get_state(self, user_id: str) -> str:
        """Get current circuit state for user"""
        with self.lock:
            return self.circuit_states[user_id]

    def reset_circuit(self, user_id: str):
        """Reset circuit for user"""
        with self.lock:
            self.circuit_states[user_id] = CircuitState.CLOSED
            self.attack_history[user_id].clear()
            if user_id in self.state_transitions:
                del self.state_transitions[user_id]


class SecurityMiddleware:
    """
    Unified security middleware for all agent calls.

    Features:
    - Input validation (40+ attack patterns)
    - Output filtering (15+ PII types)
    - Rate limiting (100 req/hour, 10 burst/min)
    - Circuit breaker (block after 5 attacks/10min)
    - Audit logging
    """

    def __init__(
        self,
        rate_limit_config: Optional[RateLimitConfig] = None,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
        enable_input_validation: bool = True,
        enable_output_filtering: bool = True,
        enable_rate_limiting: bool = True,
        enable_circuit_breaker: bool = True,
        enable_audit_logging: bool = True
    ):
        """
        Initialize security middleware.

        Args:
            rate_limit_config: Rate limiting configuration
            circuit_breaker_config: Circuit breaker configuration
            enable_*: Feature flags to enable/disable components
        """
        # Components
        self.input_validator = InputValidator() if enable_input_validation else None
        self.output_filter = OutputFilter() if enable_output_filtering else None
        self.rate_limiter = RateLimiter(rate_limit_config) if enable_rate_limiting else None
        self.circuit_breaker = CircuitBreaker(circuit_breaker_config) if enable_circuit_breaker else None
        self.audit_logger = AuditLogger() if enable_audit_logging else None

        # Feature flags
        self.enable_input_validation = enable_input_validation
        self.enable_output_filtering = enable_output_filtering
        self.enable_rate_limiting = enable_rate_limiting
        self.enable_circuit_breaker = enable_circuit_breaker
        self.enable_audit_logging = enable_audit_logging

    def wrap_call(
        self,
        func: Callable,
        *args,
        user_id: str = "anonymous",
        endpoint: Optional[str] = None,
        validate_input: bool = True,
        filter_output: bool = True,
        **kwargs
    ) -> Any:
        """
        Wrap a function call with security checks.

        Args:
            func: Function to wrap
            *args: Positional arguments for func
            user_id: User identifier for rate limiting
            endpoint: Endpoint identifier for rate limiting
            validate_input: Whether to validate input (default: True)
            filter_output: Whether to filter output (default: True)
            **kwargs: Keyword arguments for func

        Returns:
            Result from func (with output filtering if enabled)

        Raises:
            SecurityError: If malicious input detected
            RateLimitExceeded: If rate limit exceeded
            CircuitBreakerOpen: If circuit breaker is open
        """
        start_time = time.time()

        try:
            # 1. Check circuit breaker
            if self.enable_circuit_breaker and self.circuit_breaker:
                if not self.circuit_breaker.check_circuit(user_id):
                    error_msg = f"Circuit breaker OPEN for user {user_id}"
                    if self.enable_audit_logging and self.audit_logger:
                        self.audit_logger.log_security_event(
                            event_type="circuit_breaker_blocked",
                            user_id=user_id,
                            endpoint=endpoint,
                            severity="high",
                            details={"reason": "Circuit breaker open due to repeated attacks"}
                        )
                    raise CircuitBreakerOpen(error_msg)

            # 2. Check rate limit
            if self.enable_rate_limiting and self.rate_limiter:
                try:
                    self.rate_limiter.consume_tokens(user_id=user_id, endpoint=endpoint)
                except RateLimitExceeded as e:
                    if self.enable_audit_logging and self.audit_logger:
                        self.audit_logger.log_security_event(
                            event_type="rate_limit_exceeded",
                            user_id=user_id,
                            endpoint=endpoint,
                            severity="medium",
                            details={"retry_after": e.retry_after}
                        )
                    raise

            # 3. Validate input
            if self.enable_input_validation and self.input_validator and validate_input:
                # Get string inputs from args and kwargs
                string_inputs = [arg for arg in args if isinstance(arg, str)]
                string_inputs.extend([v for v in kwargs.values() if isinstance(v, str)])

                for input_str in string_inputs:
                    result = self.input_validator.validate_input(input_str)
                    if result.is_malicious:
                        # Record attack
                        if self.circuit_breaker:
                            self.circuit_breaker.record_attack(
                                user_id=user_id,
                                attack_type=result.attack_type,
                                severity=result.severity
                            )

                        # Log attack
                        if self.enable_audit_logging and self.audit_logger:
                            self.audit_logger.log_security_event(
                                event_type="attack_detected",
                                user_id=user_id,
                                endpoint=endpoint,
                                severity=result.severity.value,
                                details={
                                    "attack_type": result.attack_type.value,
                                    "confidence": result.confidence,
                                    "matched_pattern": result.matched_pattern,
                                    "input_sample": input_str[:100]
                                }
                            )

                        raise SecurityError(
                            f"{result.attack_type.value} detected (severity: {result.severity.value})"
                        )

            # 4. Call function
            output = func(*args, **kwargs)

            # 5. Filter output
            if self.enable_output_filtering and self.output_filter and filter_output:
                if isinstance(output, str):
                    filter_result = self.output_filter.filter_output(output)
                    if filter_result.contains_pii:
                        # Log PII detection
                        if self.enable_audit_logging and self.audit_logger:
                            self.audit_logger.log_security_event(
                                event_type="pii_detected",
                                user_id=user_id,
                                endpoint=endpoint,
                                severity="medium",
                                details={
                                    "pii_types": [match.pii_type.value for match in filter_result.pii_found],
                                    "pii_count": len(filter_result.pii_found)
                                }
                            )
                        output = filter_result.redacted_text

            # 6. Record success
            if self.circuit_breaker:
                self.circuit_breaker.record_success(user_id)

            # 7. Log successful request
            if self.enable_audit_logging and self.audit_logger:
                elapsed_ms = (time.time() - start_time) * 1000
                self.audit_logger.log_request(
                    user_id=user_id,
                    endpoint=endpoint or func.__name__,
                    duration_ms=elapsed_ms,
                    success=True
                )

            return output

        except Exception as e:
            # Log failed request
            if self.enable_audit_logging and self.audit_logger:
                elapsed_ms = (time.time() - start_time) * 1000
                self.audit_logger.log_request(
                    user_id=user_id,
                    endpoint=endpoint or func.__name__,
                    duration_ms=elapsed_ms,
                    success=False,
                    error=str(e)
                )
            raise


class SecurityError(Exception):
    """Raised when malicious input is detected"""
    pass


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open"""
    pass


# Global middleware instance
_global_middleware = SecurityMiddleware()


def security_wrapper(
    user_id: str = "anonymous",
    endpoint: Optional[str] = None,
    validate_input: bool = True,
    filter_output: bool = True
):
    """
    Decorator to wrap functions with security checks.

    Usage:
        @security_wrapper(user_id="user123", endpoint="/api/assess")
        def risky_function(user_input: str) -> str:
            return process(user_input)

    Args:
        user_id: User identifier
        endpoint: Endpoint identifier
        validate_input: Enable input validation
        filter_output: Enable output filtering

    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return _global_middleware.wrap_call(
                func,
                *args,
                user_id=user_id,
                endpoint=endpoint,
                validate_input=validate_input,
                filter_output=filter_output,
                **kwargs
            )
        return wrapper
    return decorator
