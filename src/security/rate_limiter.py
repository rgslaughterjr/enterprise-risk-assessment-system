"""Rate Limiter - Token Bucket Algorithm"""
import time
from collections import defaultdict
from threading import Lock
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, requests_per_hour: int = 100, burst: int = 10):
        self.rate = requests_per_hour / 3600.0  # tokens per second
        self.burst = burst
        self.buckets = defaultdict(lambda: {'tokens': burst, 'last_update': time.time()})
        self.lock = Lock()

    def consume_tokens(self, user_id: str, cost: int = 1) -> bool:
        """Try to consume tokens for request."""
        with self.lock:
            bucket = self.buckets[user_id]
            now = time.time()

            # Refill tokens
            elapsed = now - bucket['last_update']
            bucket['tokens'] = min(self.burst, bucket['tokens'] + elapsed * self.rate)
            bucket['last_update'] = now

            # Try to consume
            if bucket['tokens'] >= cost:
                bucket['tokens'] -= cost
                return True
            return False
