"""Tests for Rate Limiter - Week 9"""

import pytest
import time
from src.security.rate_limiter import (
    RateLimiter, RateLimitConfig, RateLimitExceeded,
    TokenBucket
)


class TestTokenBucket:
    def test_token_bucket_creation(self):
        bucket = TokenBucket(capacity=100, tokens=100, refill_rate=10.0)
        assert bucket.capacity == 100
        assert bucket.tokens == 100

    def test_consume_tokens_success(self):
        bucket = TokenBucket(capacity=100, tokens=50, refill_rate=10.0)
        assert bucket.consume(10)
        assert bucket.tokens == 40

    def test_consume_tokens_insufficient(self):
        bucket = TokenBucket(capacity=100, tokens=5, refill_rate=10.0)
        assert not bucket.consume(10)

    def test_refill_tokens(self):
        bucket = TokenBucket(capacity=100, tokens=50, refill_rate=10.0)
        time.sleep(0.1)
        bucket.refill()
        assert bucket.tokens > 50


class TestRateLimiter:
    @pytest.fixture
    def limiter(self):
        config = RateLimitConfig(requests_per_hour=100, burst_requests=10)
        return RateLimiter(config)

    def test_initial_request_allowed(self, limiter):
        assert limiter.check_limit(user_id="user1")

    def test_consume_tokens_success(self, limiter):
        status = limiter.consume_tokens(user_id="user1")
        assert status.allowed
        assert status.remaining_requests > 0

    def test_burst_limit_exceeded(self, limiter):
        # Consume burst limit
        for i in range(10):
            limiter.consume_tokens(user_id="user2")
        
        # Next request should fail
        with pytest.raises(RateLimitExceeded):
            limiter.consume_tokens(user_id="user2")

    def test_different_users_independent(self, limiter):
        # User1 exhausts limit
        for i in range(10):
            limiter.consume_tokens(user_id="user1")
        
        # User2 should still work
        status = limiter.consume_tokens(user_id="user2")
        assert status.allowed

    def test_get_status(self, limiter):
        limiter.consume_tokens(user_id="user1")
        status = limiter.get_status(user_id="user1")
        assert status.remaining_requests < 100

    def test_reset_user(self, limiter):
        limiter.consume_tokens(user_id="user1")
        limiter.reset_user(user_id="user1")
        status = limiter.get_status(user_id="user1")
        assert status.remaining_requests == 100

    def test_statistics(self, limiter):
        limiter.consume_tokens(user_id="user1")
        stats = limiter.get_statistics(user_id="user1")
        assert stats["total_requests"] == 1
        assert stats["denied_requests"] == 0

    def test_denial_statistics(self, limiter):
        # Exhaust limit
        for i in range(10):
            limiter.consume_tokens(user_id="user1")
        
        # Try one more (should fail)
        try:
            limiter.consume_tokens(user_id="user1")
        except RateLimitExceeded:
            pass
        
        stats = limiter.get_statistics(user_id="user1")
        assert stats["denied_requests"] > 0

    def test_endpoint_specific_limits(self, limiter):
        # Different endpoints have independent limits
        limiter.consume_tokens(user_id="user1", endpoint="/api/assess")
        limiter.consume_tokens(user_id="user1", endpoint="/api/report")
        
        status = limiter.get_status(user_id="user1")
        assert status.allowed

    def test_retry_after_calculation(self, limiter):
        # Exhaust burst limit
        for i in range(10):
            limiter.consume_tokens(user_id="user1")
        
        try:
            limiter.consume_tokens(user_id="user1")
        except RateLimitExceeded as e:
            assert e.retry_after > 0

    def test_concurrent_access(self, limiter):
        # Basic thread safety test
        import threading
        
        def consume():
            try:
                limiter.consume_tokens(user_id="user1")
            except RateLimitExceeded:
                pass
        
        threads = [threading.Thread(target=consume) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def test_custom_token_cost(self, limiter):
        # Consume multiple tokens at once
        status = limiter.consume_tokens(user_id="user1", tokens=5)
        assert status.allowed
