"""Tests for Observer - Week 9 Monitoring"""

import pytest
import time
from src.monitoring.observer import Observer, RequestMetrics


class TestObserver:
    @pytest.fixture
    def observer(self):
        return Observer(enable_prometheus=False)

    def test_track_request_success(self, observer):
        with observer.track_request(endpoint="/api/test", user_id="user1"):
            time.sleep(0.01)  # Simulate work

        metrics = observer.get_metrics()
        assert metrics.total_requests == 1
        assert metrics.successful_requests == 1

    def test_track_request_failure(self, observer):
        try:
            with observer.track_request(endpoint="/api/test", user_id="user1"):
                raise ValueError("Test error")
        except ValueError:
            pass

        metrics = observer.get_metrics()
        assert metrics.total_requests == 1
        assert metrics.failed_requests == 1

    def test_latency_tracking(self, observer):
        with observer.track_request(endpoint="/api/test", user_id="user1"):
            time.sleep(0.05)

        metrics = observer.get_metrics()
        assert metrics.mean_latency_ms > 40  # Should be ~50ms

    def test_percentile_calculation(self, observer):
        # Record requests with varying latencies
        for i in range(100):
            observer.record_request(
                endpoint="/api/test",
                user_id="user1",
                duration_ms=i,
                success=True
            )

        metrics = observer.get_metrics()
        assert metrics.p50_latency_ms > 45
        assert metrics.p50_latency_ms < 55
        assert metrics.p95_latency_ms > 90

    def test_success_rate(self, observer):
        # 7 successes, 3 failures
        for i in range(7):
            observer.record_request("/api/test", "user1", 100, True)
        for i in range(3):
            observer.record_request("/api/test", "user1", 100, False)

        metrics = observer.get_metrics()
        assert metrics.success_rate == 0.7

    def test_endpoint_metrics(self, observer):
        observer.record_request("/api/test1", "user1", 100, True)
        observer.record_request("/api/test2", "user1", 200, True)

        metrics = observer.get_metrics()
        assert "/api/test1" in metrics.requests_by_endpoint
        assert "/api/test2" in metrics.requests_by_endpoint

    def test_user_metrics(self, observer):
        observer.record_request("/api/test", "user1", 100, True)
        observer.record_request("/api/test", "user2", 100, True)

        metrics = observer.get_metrics()
        assert "user1" in metrics.requests_by_user
        assert "user2" in metrics.requests_by_user

    def test_get_endpoint_metrics(self, observer):
        for i in range(5):
            observer.record_request("/api/test", "user1", 100, True)

        endpoint_metrics = observer.get_endpoint_metrics("/api/test")
        assert endpoint_metrics["total_requests"] == 5
        assert endpoint_metrics["success_rate"] == 1.0

    def test_filter_by_endpoint(self, observer):
        observer.record_request("/api/test1", "user1", 100, True)
        observer.record_request("/api/test2", "user1", 100, True)

        metrics = observer.get_metrics(endpoint="/api/test1")
        assert metrics.total_requests == 1

    def test_last_n_requests(self, observer):
        for i in range(20):
            observer.record_request("/api/test", "user1", 100, True)

        metrics = observer.get_metrics(last_n_requests=10)
        assert metrics.total_requests == 10

    def test_reset_metrics(self, observer):
        observer.record_request("/api/test", "user1", 100, True)
        observer.reset_metrics()

        metrics = observer.get_metrics()
        assert metrics.total_requests == 0

    def test_max_latency(self, observer):
        observer.record_request("/api/test", "user1", 100, True)
        observer.record_request("/api/test", "user1", 500, True)
        observer.record_request("/api/test", "user1", 200, True)

        metrics = observer.get_metrics()
        assert metrics.max_latency_ms == 500

    def test_history_limit(self, observer):
        # Record more than max_history_size
        for i in range(11000):
            observer.record_request("/api/test", "user1", 100, True)

        # Should only keep last 10,000
        assert len(observer.request_history) == 10000

    def test_concurrent_tracking(self, observer):
        import threading

        def track():
            with observer.track_request(endpoint="/api/test", user_id="user1"):
                time.sleep(0.01)

        threads = [threading.Thread(target=track) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        metrics = observer.get_metrics()
        assert metrics.total_requests == 10
