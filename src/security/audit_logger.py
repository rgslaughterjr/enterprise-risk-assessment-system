"""
Audit Logger - Week 9 Security Hardening

JSON structured logging for security events and requests.

Features:
- Security event logging (attacks, PII, rate limits)
- Request logging (latency, success/failure)
- SHA-256 input hashing for forensics
- Rotating file handler (10MB files, 10 backups)
- Queryable JSON format

Log location: logs/audit.log

Usage:
    logger = AuditLogger()

    # Log security event
    logger.log_security_event(
        event_type="attack_detected",
        user_id="user123",
        severity="high",
        details={"attack_type": "sql_injection"}
    )

    # Log request
    logger.log_request(
        user_id="user123",
        endpoint="/api/assess",
        duration_ms=234.5,
        success=True
    )
"""

import json
import logging
import hashlib
import os
from typing import Any, Dict, Optional
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path


class AuditLogger:
    """
    JSON structured audit logger for security events.

    Features:
    - JSON formatted logs for easy parsing
    - Rotating file handler (10MB × 10 files)
    - SHA-256 input hashing
    - Severity levels
    - Timestamp with milliseconds
    """

    def __init__(
        self,
        log_dir: str = "logs",
        log_file: str = "audit.log",
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 10
    ):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for log files
            log_file: Log file name
            max_bytes: Maximum log file size before rotation
            backup_count: Number of backup files to keep
        """
        # Create log directory
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

        self.log_path = self.log_dir / log_file

        # Create logger
        self.logger = logging.getLogger("audit_logger")
        self.logger.setLevel(logging.INFO)

        # Prevent duplicate handlers
        if not self.logger.handlers:
            # Rotating file handler
            file_handler = RotatingFileHandler(
                self.log_path,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setLevel(logging.INFO)

            # No formatting - we'll write JSON directly
            file_handler.setFormatter(logging.Formatter('%(message)s'))

            self.logger.addHandler(file_handler)

            # Also add console handler for development
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.WARNING)  # Only warnings/errors to console
            console_handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(console_handler)

    def log_security_event(
        self,
        event_type: str,
        user_id: str,
        severity: str,
        endpoint: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log a security event.

        Args:
            event_type: Type of event (attack_detected, pii_detected, etc.)
            user_id: User identifier
            severity: Severity level (critical, high, medium, low)
            endpoint: Optional endpoint identifier
            details: Additional event details
        """
        event = {
            "timestamp": self._get_timestamp(),
            "event_type": "security_event",
            "security_event_type": event_type,
            "user_id": user_id,
            "severity": severity,
            "endpoint": endpoint,
            "details": details or {}
        }

        # Hash any input samples for privacy
        if "input_sample" in event["details"]:
            event["details"]["input_hash"] = self._hash_input(event["details"]["input_sample"])
            # Keep only first 50 chars of sample
            event["details"]["input_sample"] = event["details"]["input_sample"][:50]

        self._write_log(event)

    def log_request(
        self,
        user_id: str,
        endpoint: str,
        duration_ms: float,
        success: bool,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log a request.

        Args:
            user_id: User identifier
            endpoint: Endpoint identifier
            duration_ms: Request duration in milliseconds
            success: Whether request succeeded
            error: Error message if failed
            metadata: Additional request metadata
        """
        event = {
            "timestamp": self._get_timestamp(),
            "event_type": "request",
            "user_id": user_id,
            "endpoint": endpoint,
            "duration_ms": round(duration_ms, 2),
            "success": success,
            "error": error,
            "metadata": metadata or {}
        }

        self._write_log(event)

    def log_api_call(
        self,
        service: str,
        endpoint: str,
        duration_ms: float,
        status_code: Optional[int] = None,
        tokens_used: Optional[int] = None,
        cost: Optional[float] = None,
        error: Optional[str] = None
    ):
        """
        Log an external API call.

        Args:
            service: Service name (nvd, virustotal, anthropic, etc.)
            endpoint: API endpoint
            duration_ms: Call duration in milliseconds
            status_code: HTTP status code
            tokens_used: Tokens consumed (for LLM calls)
            cost: Estimated cost in USD
            error: Error message if failed
        """
        event = {
            "timestamp": self._get_timestamp(),
            "event_type": "api_call",
            "service": service,
            "endpoint": endpoint,
            "duration_ms": round(duration_ms, 2),
            "status_code": status_code,
            "tokens_used": tokens_used,
            "cost_usd": cost,
            "success": status_code is not None and 200 <= status_code < 300,
            "error": error
        }

        self._write_log(event)

    def log_agent_action(
        self,
        agent_name: str,
        action: str,
        duration_ms: float,
        success: bool,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log an agent action.

        Args:
            agent_name: Name of agent (servicenow, vulnerability, etc.)
            action: Action performed
            duration_ms: Action duration in milliseconds
            success: Whether action succeeded
            metadata: Additional metadata
        """
        event = {
            "timestamp": self._get_timestamp(),
            "event_type": "agent_action",
            "agent_name": agent_name,
            "action": action,
            "duration_ms": round(duration_ms, 2),
            "success": success,
            "metadata": metadata or {}
        }

        self._write_log(event)

    def log_circuit_breaker_event(
        self,
        user_id: str,
        state: str,
        reason: str,
        attack_count: int
    ):
        """
        Log circuit breaker state change.

        Args:
            user_id: User identifier
            state: New state (open, closed, half_open)
            reason: Reason for state change
            attack_count: Number of attacks in time window
        """
        event = {
            "timestamp": self._get_timestamp(),
            "event_type": "circuit_breaker",
            "user_id": user_id,
            "state": state,
            "reason": reason,
            "attack_count": attack_count
        }

        self._write_log(event)

    def _write_log(self, event: Dict[str, Any]):
        """Write event to log file"""
        log_line = json.dumps(event, default=str)
        self.logger.info(log_line)

    def _get_timestamp(self) -> str:
        """Get ISO 8601 timestamp with milliseconds"""
        return datetime.utcnow().isoformat() + "Z"

    def _hash_input(self, input_str: str) -> str:
        """
        Hash input string with SHA-256 for forensic correlation.

        Args:
            input_str: Input to hash

        Returns:
            Hex digest of SHA-256 hash
        """
        return hashlib.sha256(input_str.encode('utf-8')).hexdigest()

    def query_logs(
        self,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> list:
        """
        Query audit logs (simple file-based search).

        Args:
            event_type: Filter by event type
            user_id: Filter by user ID
            severity: Filter by severity
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum number of results

        Returns:
            List of matching log entries
        """
        results = []

        try:
            with open(self.log_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())

                        # Apply filters
                        if event_type and event.get("event_type") != event_type:
                            continue
                        if user_id and event.get("user_id") != user_id:
                            continue
                        if severity and event.get("severity") != severity:
                            continue

                        # Time filters
                        if start_time or end_time:
                            event_time = datetime.fromisoformat(event["timestamp"].rstrip("Z"))
                            if start_time and event_time < start_time:
                                continue
                            if end_time and event_time > end_time:
                                continue

                        results.append(event)

                        if len(results) >= limit:
                            break

                    except json.JSONDecodeError:
                        continue

        except FileNotFoundError:
            pass

        return results

    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get summary of security events in last N hours.

        Args:
            hours: Number of hours to look back

        Returns:
            Dictionary with summary statistics
        """
        start_time = datetime.utcnow() - timedelta(hours=hours)
        events = self.query_logs(
            event_type="security_event",
            start_time=start_time,
            limit=10000
        )

        summary = {
            "total_events": len(events),
            "by_type": {},
            "by_severity": {},
            "by_user": {},
            "critical_events": []
        }

        for event in events:
            # Count by type
            event_subtype = event.get("security_event_type", "unknown")
            summary["by_type"][event_subtype] = summary["by_type"].get(event_subtype, 0) + 1

            # Count by severity
            severity = event.get("severity", "unknown")
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

            # Count by user
            user_id = event.get("user_id", "unknown")
            summary["by_user"][user_id] = summary["by_user"].get(user_id, 0) + 1

            # Collect critical events
            if severity == "critical":
                summary["critical_events"].append(event)

        return summary


# Singleton instance
_global_logger = None


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = AuditLogger()
    return _global_logger


# Import for convenience
from datetime import timedelta
