"""Audit Logger - Security Event Logging"""
import json
import logging
from datetime import datetime
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)

class AuditLogger:
    """Structured audit logging for security events."""

    def __init__(self, log_path: str = "logs/audit.log"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Initialized AuditLogger: {log_path}")

    def log_security_event(self, event_type: str, details: dict):
        """Log security event in JSON format."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user": details.get("user", "system"),
            "input_hash": self._hash_input(details.get("input", "")),
            "threat_detected": details.get("threat_detected", False),
            "action_taken": details.get("action_taken", "none"),
            "details": details
        }

        with open(self.log_path, 'a') as f:
            f.write(json.dumps(event) + '\n')

    def _hash_input(self, text: str) -> str:
        """Hash input for privacy."""
        return hashlib.sha256(text.encode()).hexdigest()[:16]
