"""
Rate Limiter - Week 9 Security Hardening

Token bucket algorithm for rate limiting API requests.

Configuration:
- 100 requests/hour per user (base rate)
- 10 burst requests/minute (burst capacity)
- Configurable per endpoint/user

Usage:
    limiter = RateLimiter()

    if limiter.check_limit(user_id="user123", endpoint="/api/assess"):
        # Process request
        limiter.consume_tokens(user_id="user123", endpoint="/api/assess")
    else:
        # Rate limit exceeded
        raise RateLimitExceeded("Too many requests")
"""

import time
import threading
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.

    Algorithm:
    1. Bucket holds tokens (max = capacity)
    2. Tokens refill at constant rate
    3. Each request consumes tokens
    4. Request denied if insufficient tokens
    """
    capacity: int  # Maximum tokens
    tokens: float  # Current tokens
    refill_rate: float  # Tokens added per second
    last_refill: float = field(default_factory=time.time)

    def refill(self):
        """Refill tokens based on time elapsed"""
        now = time.time()
        time_elapsed = now - self.last_refill
        tokens_to_add = time_elapsed * self.refill_rate

        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens consumed, False if insufficient
        """
        self.refill()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def get_available_tokens(self) -> int:
        """Get number of available tokens"""
        self.refill()
        return int(self.tokens)

    def time_until_available(self, tokens: int = 1) -> float:
        """
        Get time (seconds) until N tokens available.

        Args:
            tokens: Number of tokens needed

        Returns:
            Seconds until tokens available (0 if already available)
        """
        self.refill()

        if self.tokens >= tokens:
            return 0.0

        tokens_needed = tokens - self.tokens
        return tokens_needed / self.refill_rate


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    # Hourly limit (base rate)
    requests_per_hour: int = 100

    # Burst limit (short-term)
    burst_requests: int = 10
    burst_window_seconds: int = 60  # 1 minute

    # Token cost per request
    tokens_per_request: int = 1


@dataclass
class RateLimitStatus:
    """Status of rate limit check"""
    allowed: bool
    remaining_requests: int
    reset_time: datetime
    retry_after_seconds: Optional[float] = None


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded"""
    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = retry_after


class RateLimiter:
    """
    Multi-level rate limiter with token bucket algorithm.

    Features:
    - Per-user rate limiting
    - Per-endpoint rate limiting
    - Burst protection
    - Thread-safe
    - Automatic token refill
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize rate limiter.

        Args:
            config: Rate limit configuration (uses defaults if None)
        """
        self.config = config or RateLimitConfig()

        # User buckets: {user_id: bucket}
        self.user_buckets: Dict[str, TokenBucket] = {}

        # Endpoint buckets: {(user_id, endpoint): bucket}
        self.endpoint_buckets: Dict[Tuple[str, str], TokenBucket] = {}

        # Burst buckets: {user_id: bucket}
        self.burst_buckets: Dict[str, TokenBucket] = {}

        # Request counters for statistics
        self.request_counts: Dict[str, int] = defaultdict(int)
        self.denied_counts: Dict[str, int] = defaultdict(int)

        # Thread lock for thread safety
        self.lock = threading.Lock()

    def check_limit(
        self,
        user_id: str,
        endpoint: Optional[str] = None,
        tokens: int = 1
    ) -> bool:
        """
        Check if request is within rate limit (without consuming tokens).

        Args:
            user_id: User identifier
            endpoint: Optional endpoint identifier
            tokens: Number of tokens required

        Returns:
            True if within limit, False if exceeded
        """
        with self.lock:
            # Check user-level hourly limit
            user_bucket = self._get_user_bucket(user_id)
            if user_bucket.get_available_tokens() < tokens:
                return False

            # Check burst limit
            burst_bucket = self._get_burst_bucket(user_id)
            if burst_bucket.get_available_tokens() < tokens:
                return False

            # Check endpoint-specific limit if applicable
            if endpoint:
                endpoint_bucket = self._get_endpoint_bucket(user_id, endpoint)
                if endpoint_bucket.get_available_tokens() < tokens:
                    return False

            return True

    def consume_tokens(
        self,
        user_id: str,
        endpoint: Optional[str] = None,
        tokens: int = 1
    ) -> RateLimitStatus:
        """
        Consume tokens for a request.

        Args:
            user_id: User identifier
            endpoint: Optional endpoint identifier
            tokens: Number of tokens to consume

        Returns:
            RateLimitStatus with current status

        Raises:
            RateLimitExceeded if rate limit exceeded
        """
        with self.lock:
            # Get all relevant buckets
            user_bucket = self._get_user_bucket(user_id)
            burst_bucket = self._get_burst_bucket(user_id)
            endpoint_bucket = self._get_endpoint_bucket(user_id, endpoint) if endpoint else None

            # Check all limits
            limits_ok = user_bucket.consume(tokens)
            limits_ok = limits_ok and burst_bucket.consume(tokens)
            if endpoint_bucket:
                limits_ok = limits_ok and endpoint_bucket.consume(tokens)

            if limits_ok:
                # Track successful request
                self.request_counts[user_id] += 1

                return RateLimitStatus(
                    allowed=True,
                    remaining_requests=user_bucket.get_available_tokens(),
                    reset_time=self._get_reset_time(user_bucket)
                )
            else:
                # Track denied request
                self.denied_counts[user_id] += 1

                # Calculate retry time
                retry_after = max(
                    user_bucket.time_until_available(tokens),
                    burst_bucket.time_until_available(tokens)
                )
                if endpoint_bucket:
                    retry_after = max(retry_after, endpoint_bucket.time_until_available(tokens))

                raise RateLimitExceeded(
                    f"Rate limit exceeded for user {user_id}",
                    retry_after=retry_after
                )

    def get_status(self, user_id: str, endpoint: Optional[str] = None) -> RateLimitStatus:
        """
        Get current rate limit status without consuming tokens.

        Args:
            user_id: User identifier
            endpoint: Optional endpoint identifier

        Returns:
            RateLimitStatus with current status
        """
        with self.lock:
            user_bucket = self._get_user_bucket(user_id)
            remaining = user_bucket.get_available_tokens()
            reset_time = self._get_reset_time(user_bucket)

            return RateLimitStatus(
                allowed=remaining > 0,
                remaining_requests=remaining,
                reset_time=reset_time
            )

    def reset_user(self, user_id: str):
        """
        Reset rate limits for a user.

        Args:
            user_id: User identifier
        """
        with self.lock:
            if user_id in self.user_buckets:
                del self.user_buckets[user_id]
            if user_id in self.burst_buckets:
                del self.burst_buckets[user_id]

            # Remove endpoint buckets
            keys_to_remove = [
                key for key in self.endpoint_buckets.keys()
                if key[0] == user_id
            ]
            for key in keys_to_remove:
                del self.endpoint_buckets[key]

    def get_statistics(self, user_id: Optional[str] = None) -> Dict:
        """
        Get rate limiting statistics.

        Args:
            user_id: Optional user to filter by

        Returns:
            Dictionary with statistics
        """
        with self.lock:
            if user_id:
                return {
                    "user_id": user_id,
                    "total_requests": self.request_counts.get(user_id, 0),
                    "denied_requests": self.denied_counts.get(user_id, 0),
                    "remaining_tokens": self._get_user_bucket(user_id).get_available_tokens(),
                    "denial_rate": (
                        self.denied_counts.get(user_id, 0) /
                        max(1, self.request_counts.get(user_id, 0) + self.denied_counts.get(user_id, 0))
                    )
                }
            else:
                total_requests = sum(self.request_counts.values())
                total_denied = sum(self.denied_counts.values())
                return {
                    "total_requests": total_requests,
                    "total_denied": total_denied,
                    "unique_users": len(self.user_buckets),
                    "denial_rate": total_denied / max(1, total_requests + total_denied)
                }

    def _get_user_bucket(self, user_id: str) -> TokenBucket:
        """Get or create user bucket (hourly limit)"""
        if user_id not in self.user_buckets:
            # Refill rate: requests_per_hour / 3600 seconds
            refill_rate = self.config.requests_per_hour / 3600.0

            self.user_buckets[user_id] = TokenBucket(
                capacity=self.config.requests_per_hour,
                tokens=self.config.requests_per_hour,  # Start full
                refill_rate=refill_rate
            )
        return self.user_buckets[user_id]

    def _get_burst_bucket(self, user_id: str) -> TokenBucket:
        """Get or create burst bucket (short-term limit)"""
        if user_id not in self.burst_buckets:
            # Refill rate: burst_requests / burst_window_seconds
            refill_rate = self.config.burst_requests / self.config.burst_window_seconds

            self.burst_buckets[user_id] = TokenBucket(
                capacity=self.config.burst_requests,
                tokens=self.config.burst_requests,
                refill_rate=refill_rate
            )
        return self.burst_buckets[user_id]

    def _get_endpoint_bucket(self, user_id: str, endpoint: str) -> TokenBucket:
        """Get or create endpoint-specific bucket"""
        key = (user_id, endpoint)
        if key not in self.endpoint_buckets:
            # Use same rate as user bucket for endpoint
            refill_rate = self.config.requests_per_hour / 3600.0

            self.endpoint_buckets[key] = TokenBucket(
                capacity=self.config.requests_per_hour,
                tokens=self.config.requests_per_hour,
                refill_rate=refill_rate
            )
        return self.endpoint_buckets[key]

    def _get_reset_time(self, bucket: TokenBucket) -> datetime:
        """Calculate when bucket will be full again"""
        if bucket.tokens >= bucket.capacity:
            return datetime.now()

        tokens_needed = bucket.capacity - bucket.tokens
        seconds_until_full = tokens_needed / bucket.refill_rate

        return datetime.now() + timedelta(seconds=seconds_until_full)
