"""
Observer - Week 9 Monitoring

Request tracking and metrics collection with Prometheus export.

Features:
- Request latency tracking (p50, p95, p99)
- Success/failure rates
- Request counts by endpoint/user
- Prometheus metrics export
- Thread-safe metrics collection

Usage:
    observer = Observer()

    # Track request
    with observer.track_request(endpoint="/api/assess", user_id="user123"):
        # Process request
        result = process()

    # Get metrics
    metrics = observer.get_metrics()
    print(f"p95 latency: {metrics.p95_latency_ms}ms")

    # Export Prometheus metrics
    prometheus_text = observer.export_prometheus()
"""

import time
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from contextlib import contextmanager
from collections import defaultdict
import statistics

try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


@dataclass
class RequestMetrics:
    """Aggregated request metrics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    success_rate: float = 0.0

    # Latency percentiles (milliseconds)
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    mean_latency_ms: float = 0.0
    max_latency_ms: float = 0.0

    # By endpoint
    requests_by_endpoint: Dict[str, int] = field(default_factory=dict)

    # By user
    requests_by_user: Dict[str, int] = field(default_factory=dict)


@dataclass
class RequestRecord:
    """Individual request record"""
    endpoint: str
    user_id: str
    start_time: float
    end_time: float
    duration_ms: float
    success: bool
    error: Optional[str] = None


class Observer:
    """
    Request observer with metrics tracking and Prometheus export.

    Features:
    - Latency tracking with percentiles
    - Success/failure tracking
    - Per-endpoint metrics
    - Per-user metrics
    - Prometheus integration
    - Thread-safe
    """

    def __init__(self, enable_prometheus: bool = True):
        """
        Initialize observer.

        Args:
            enable_prometheus: Enable Prometheus metrics (requires prometheus_client)
        """
        # Request history
        self.request_history: List[RequestRecord] = []
        self.max_history_size = 10000  # Keep last 10K requests

        # Metrics by endpoint
        self.endpoint_counts: Dict[str, int] = defaultdict(int)
        self.endpoint_successes: Dict[str, int] = defaultdict(int)
        self.endpoint_failures: Dict[str, int] = defaultdict(int)
        self.endpoint_latencies: Dict[str, List[float]] = defaultdict(list)

        # Metrics by user
        self.user_counts: Dict[str, int] = defaultdict(int)

        # Thread lock
        self.lock = threading.Lock()

        # Prometheus metrics
        self.enable_prometheus = enable_prometheus and PROMETHEUS_AVAILABLE
        if self.enable_prometheus:
            self._init_prometheus_metrics()

    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics"""
        # Request counter
        self.prom_request_counter = Counter(
            'risk_assessment_requests_total',
            'Total number of requests',
            ['endpoint', 'status']
        )

        # Request duration histogram
        self.prom_request_duration = Histogram(
            'risk_assessment_request_duration_seconds',
            'Request duration in seconds',
            ['endpoint'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
        )

        # Active requests gauge
        self.prom_active_requests = Gauge(
            'risk_assessment_active_requests',
            'Number of requests currently being processed',
            ['endpoint']
        )

        # Success rate gauge
        self.prom_success_rate = Gauge(
            'risk_assessment_success_rate',
            'Success rate (0.0 to 1.0)',
            ['endpoint']
        )

    @contextmanager
    def track_request(
        self,
        endpoint: str,
        user_id: str = "anonymous"
    ):
        """
        Context manager to track a request.

        Usage:
            with observer.track_request(endpoint="/api/assess", user_id="user123"):
                result = process()

        Args:
            endpoint: Endpoint identifier
            user_id: User identifier

        Yields:
            None
        """
        start_time = time.time()

        # Increment active requests
        if self.enable_prometheus:
            self.prom_active_requests.labels(endpoint=endpoint).inc()

        try:
            yield
            # Request succeeded
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000

            self._record_request(
                endpoint=endpoint,
                user_id=user_id,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                success=True
            )

        except Exception as e:
            # Request failed
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000

            self._record_request(
                endpoint=endpoint,
                user_id=user_id,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                success=False,
                error=str(e)
            )
            raise

        finally:
            # Decrement active requests
            if self.enable_prometheus:
                self.prom_active_requests.labels(endpoint=endpoint).dec()

    def record_request(
        self,
        endpoint: str,
        user_id: str,
        duration_ms: float,
        success: bool,
        error: Optional[str] = None
    ):
        """
        Manually record a request (alternative to context manager).

        Args:
            endpoint: Endpoint identifier
            user_id: User identifier
            duration_ms: Request duration in milliseconds
            success: Whether request succeeded
            error: Error message if failed
        """
        now = time.time()
        self._record_request(
            endpoint=endpoint,
            user_id=user_id,
            start_time=now - (duration_ms / 1000),
            end_time=now,
            duration_ms=duration_ms,
            success=success,
            error=error
        )

    def _record_request(
        self,
        endpoint: str,
        user_id: str,
        start_time: float,
        end_time: float,
        duration_ms: float,
        success: bool,
        error: Optional[str] = None
    ):
        """Internal method to record request"""
        with self.lock:
            # Create record
            record = RequestRecord(
                endpoint=endpoint,
                user_id=user_id,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                success=success,
                error=error
            )

            # Add to history (limit size)
            self.request_history.append(record)
            if len(self.request_history) > self.max_history_size:
                self.request_history = self.request_history[-self.max_history_size:]

            # Update endpoint metrics
            self.endpoint_counts[endpoint] += 1
            if success:
                self.endpoint_successes[endpoint] += 1
            else:
                self.endpoint_failures[endpoint] += 1

            self.endpoint_latencies[endpoint].append(duration_ms)
            # Limit latency history per endpoint
            if len(self.endpoint_latencies[endpoint]) > 1000:
                self.endpoint_latencies[endpoint] = self.endpoint_latencies[endpoint][-1000:]

            # Update user metrics
            self.user_counts[user_id] += 1

            # Update Prometheus metrics
            if self.enable_prometheus:
                status = "success" if success else "failure"
                self.prom_request_counter.labels(endpoint=endpoint, status=status).inc()
                self.prom_request_duration.labels(endpoint=endpoint).observe(duration_ms / 1000)

                # Update success rate
                total = self.endpoint_counts[endpoint]
                success_count = self.endpoint_successes[endpoint]
                success_rate = success_count / total if total > 0 else 0.0
                self.prom_success_rate.labels(endpoint=endpoint).set(success_rate)

    def get_metrics(
        self,
        endpoint: Optional[str] = None,
        last_n_requests: Optional[int] = None
    ) -> RequestMetrics:
        """
        Get aggregated metrics.

        Args:
            endpoint: Optional endpoint to filter by
            last_n_requests: Optional limit to last N requests

        Returns:
            RequestMetrics with aggregated data
        """
        with self.lock:
            # Filter requests
            requests = self.request_history
            if endpoint:
                requests = [r for r in requests if r.endpoint == endpoint]
            if last_n_requests:
                requests = requests[-last_n_requests:]

            if not requests:
                return RequestMetrics()

            # Calculate metrics
            total = len(requests)
            successful = sum(1 for r in requests if r.success)
            failed = total - successful

            # Latencies
            latencies = [r.duration_ms for r in requests]
            latencies.sort()

            metrics = RequestMetrics(
                total_requests=total,
                successful_requests=successful,
                failed_requests=failed,
                success_rate=successful / total if total > 0 else 0.0,
                p50_latency_ms=self._percentile(latencies, 0.50),
                p95_latency_ms=self._percentile(latencies, 0.95),
                p99_latency_ms=self._percentile(latencies, 0.99),
                mean_latency_ms=statistics.mean(latencies) if latencies else 0.0,
                max_latency_ms=max(latencies) if latencies else 0.0,
                requests_by_endpoint=dict(self.endpoint_counts),
                requests_by_user=dict(self.user_counts)
            )

            return metrics

    def get_endpoint_metrics(self, endpoint: str) -> Dict:
        """
        Get detailed metrics for a specific endpoint.

        Args:
            endpoint: Endpoint identifier

        Returns:
            Dictionary with endpoint metrics
        """
        with self.lock:
            total = self.endpoint_counts.get(endpoint, 0)
            successes = self.endpoint_successes.get(endpoint, 0)
            failures = self.endpoint_failures.get(endpoint, 0)
            latencies = self.endpoint_latencies.get(endpoint, [])

            if not latencies:
                return {
                    "endpoint": endpoint,
                    "total_requests": total,
                    "successful_requests": successes,
                    "failed_requests": failures,
                    "success_rate": successes / total if total > 0 else 0.0,
                    "p50_latency_ms": 0.0,
                    "p95_latency_ms": 0.0,
                    "p99_latency_ms": 0.0,
                }

            sorted_latencies = sorted(latencies)

            return {
                "endpoint": endpoint,
                "total_requests": total,
                "successful_requests": successes,
                "failed_requests": failures,
                "success_rate": successes / total if total > 0 else 0.0,
                "p50_latency_ms": self._percentile(sorted_latencies, 0.50),
                "p95_latency_ms": self._percentile(sorted_latencies, 0.95),
                "p99_latency_ms": self._percentile(sorted_latencies, 0.99),
                "mean_latency_ms": statistics.mean(sorted_latencies),
                "max_latency_ms": max(sorted_latencies),
            }

    def _percentile(self, sorted_data: List[float], percentile: float) -> float:
        """Calculate percentile from sorted data"""
        if not sorted_data:
            return 0.0

        k = (len(sorted_data) - 1) * percentile
        f = int(k)
        c = int(k) + 1 if k < len(sorted_data) - 1 else f

        if f == c:
            return sorted_data[f]

        d0 = sorted_data[f] * (c - k)
        d1 = sorted_data[c] * (k - f)
        return d0 + d1

    def export_prometheus(self) -> str:
        """
        Export metrics in Prometheus format.

        Returns:
            Prometheus metrics as text
        """
        if not self.enable_prometheus:
            return "# Prometheus metrics not enabled"

        return generate_latest(REGISTRY).decode('utf-8')

    def reset_metrics(self):
        """Reset all metrics"""
        with self.lock:
            self.request_history.clear()
            self.endpoint_counts.clear()
            self.endpoint_successes.clear()
            self.endpoint_failures.clear()
            self.endpoint_latencies.clear()
            self.user_counts.clear()


# Singleton instance
_global_observer = None


def get_observer() -> Observer:
    """Get global observer instance"""
    global _global_observer
    if _global_observer is None:
        _global_observer = Observer()
    return _global_observer
