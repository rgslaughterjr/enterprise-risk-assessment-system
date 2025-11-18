"""Tests for Cost Tracker - Week 9 Monitoring"""

import pytest
import tempfile
import csv
from datetime import date
from src.monitoring.cost_tracker import CostTracker, APICallRecord


class TestCostTracker:
    @pytest.fixture
    def temp_data_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def tracker(self, temp_data_dir):
        return CostTracker(data_dir=temp_data_dir)

    def test_log_anthropic_call(self, tracker):
        record = tracker.log_api_call(
            service="anthropic",
            endpoint="messages",
            tokens_input=1000,
            tokens_output=500,
            model="sonnet"
        )

        assert record.cost_total > 0
        assert record.tokens_total == 1500

    def test_cost_calculation_sonnet(self, tracker):
        record = tracker.log_api_call(
            service="anthropic",
            endpoint="messages",
            tokens_input=1_000_000,  # 1M tokens
            tokens_output=1_000_000,
            model="sonnet"
        )

        # $3/MTok input + $15/MTok output = $18
        assert record.cost_total == 18.0

    def test_cost_calculation_haiku(self, tracker):
        record = tracker.log_api_call(
            service="anthropic",
            endpoint="messages",
            tokens_input=1_000_000,
            tokens_output=1_000_000,
            model="haiku"
        )

        # $0.25/MTok input + $1.25/MTok output = $1.50
        assert record.cost_total == 1.50

    def test_free_service_cost(self, tracker):
        record = tracker.log_api_call(
            service="nvd",
            endpoint="/cves",
            duration_ms=100
        )

        assert record.cost_total == 0.0

    def test_get_total_cost(self, tracker):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")

        total = tracker.get_total_cost()
        assert total > 0

    def test_get_daily_cost(self, tracker):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")

        today_cost = tracker.get_daily_cost()
        assert today_cost > 0

    def test_get_cost_by_service(self, tracker):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")
        tracker.log_api_call("nvd", "/cves", duration_ms=100)

        costs = tracker.get_cost_by_service()
        assert "anthropic" in costs
        assert "nvd" in costs

    def test_get_cost_by_agent(self, tracker):
        tracker.log_api_call("anthropic", "messages", agent="vulnerability_agent", tokens_input=1000, tokens_output=500, model="sonnet")
        tracker.log_api_call("anthropic", "messages", agent="threat_agent", tokens_input=1000, tokens_output=500, model="sonnet")

        costs = tracker.get_cost_by_agent()
        assert "vulnerability_agent" in costs
        assert "threat_agent" in costs

    def test_token_usage_tracking(self, tracker):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")

        usage = tracker.get_token_usage()
        assert usage["input"] == 1000
        assert usage["output"] == 500
        assert usage["total"] == 1500

    def test_token_usage_by_service(self, tracker):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")

        usage = tracker.get_token_usage(service="anthropic")
        assert usage["total"] == 1500

    def test_call_statistics(self, tracker):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, success=True, model="sonnet")
        tracker.log_api_call("nvd", "/cves", success=False, error="Timeout")

        stats = tracker.get_call_statistics()
        assert stats["total_calls"] == 2
        assert stats["successful_calls"] == 1
        assert stats["failed_calls"] == 1

    def test_export_to_csv(self, tracker, temp_data_dir):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")

        tracker.export_to_csv("test_export.csv")

        # Verify CSV created
        csv_path = tracker.data_dir / "test_export.csv"
        assert csv_path.exists()

        # Verify content
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["service"] == "anthropic"

    def test_export_daily_summary_csv(self, tracker, temp_data_dir):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")

        tracker.export_daily_summary_csv("daily_summary.csv")

        csv_path = tracker.data_dir / "daily_summary.csv"
        assert csv_path.exists()

    def test_export_service_summary_csv(self, tracker, temp_data_dir):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")
        tracker.log_api_call("nvd", "/cves", duration_ms=100)

        tracker.export_service_summary_csv("service_summary.csv")

        csv_path = tracker.data_dir / "service_summary.csv"
        assert csv_path.exists()

    def test_reset_metrics(self, tracker):
        tracker.log_api_call("anthropic", "messages", tokens_input=1000, tokens_output=500, model="sonnet")
        tracker.reset_metrics()

        assert tracker.get_total_cost() == 0.0
        assert len(tracker.call_history) == 0
