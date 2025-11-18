"""Tests for Audit Logger - Week 9"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from src.security.audit_logger import AuditLogger


class TestAuditLogger:
    @pytest.fixture
    def temp_log_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def logger(self, temp_log_dir):
        return AuditLogger(log_dir=temp_log_dir, log_file="test_audit.log")

    def test_log_security_event(self, logger):
        logger.log_security_event(
            event_type="attack_detected",
            user_id="user1",
            severity="high",
            details={"attack_type": "sql_injection"}
        )
        
        # Verify log file created
        assert logger.log_path.exists()

    def test_log_request(self, logger):
        logger.log_request(
            user_id="user1",
            endpoint="/api/assess",
            duration_ms=123.45,
            success=True
        )
        
        assert logger.log_path.exists()

    def test_log_api_call(self, logger):
        logger.log_api_call(
            service="anthropic",
            endpoint="messages",
            duration_ms=456.78,
            status_code=200,
            tokens_used=1000,
            cost=0.05
        )
        
        assert logger.log_path.exists()

    def test_log_format_is_json(self, logger):
        logger.log_security_event(
            event_type="test_event",
            user_id="user1",
            severity="low"
        )
        
        # Read log file
        with open(logger.log_path, 'r') as f:
            line = f.readline()
            event = json.loads(line)
            assert event["event_type"] == "security_event"
            assert event["user_id"] == "user1"

    def test_input_hashing(self, logger):
        logger.log_security_event(
            event_type="attack_detected",
            user_id="user1",
            severity="high",
            details={"input_sample": "malicious input"}
        )
        
        with open(logger.log_path, 'r') as f:
            event = json.loads(f.readline())
            assert "input_hash" in event["details"]
            assert len(event["details"]["input_hash"]) == 64  # SHA-256

    def test_query_logs(self, logger):
        logger.log_security_event(
            event_type="attack_detected",
            user_id="user1",
            severity="high"
        )
        
        results = logger.query_logs(event_type="security_event")
        assert len(results) == 1

    def test_query_by_user(self, logger):
        logger.log_security_event("event1", "user1", "high")
        logger.log_security_event("event2", "user2", "low")
        
        results = logger.query_logs(user_id="user1")
        assert len(results) == 1

    def test_query_by_severity(self, logger):
        logger.log_security_event("event1", "user1", "high")
        logger.log_security_event("event2", "user2", "low")
        
        results = logger.query_logs(severity="high")
        assert len(results) == 1

    def test_query_with_limit(self, logger):
        for i in range(10):
            logger.log_security_event(f"event{i}", "user1", "low")
        
        results = logger.query_logs(limit=5)
        assert len(results) == 5

    def test_security_summary(self, logger):
        logger.log_security_event("attack_detected", "user1", "critical")
        logger.log_security_event("pii_detected", "user2", "medium")
        
        summary = logger.get_security_summary(hours=24)
        assert summary["total_events"] == 2
        assert "critical" in summary["by_severity"]

    def test_timestamp_format(self, logger):
        logger.log_request("user1", "/api/test", 100, True)
        
        with open(logger.log_path, 'r') as f:
            event = json.loads(f.readline())
            # Should be ISO 8601 format
            timestamp = datetime.fromisoformat(event["timestamp"].rstrip("Z"))
            assert isinstance(timestamp, datetime)

    def test_circuit_breaker_event(self, logger):
        logger.log_circuit_breaker_event(
            user_id="user1",
            state="open",
            reason="Too many attacks",
            attack_count=5
        )
        
        results = logger.query_logs(event_type="circuit_breaker")
        assert len(results) == 1

    def test_agent_action_logging(self, logger):
        logger.log_agent_action(
            agent_name="vulnerability_agent",
            action="analyze_cve",
            duration_ms=567.89,
            success=True
        )
        
        results = logger.query_logs(event_type="agent_action")
        assert len(results) == 1
