"""Monitoring Observer - Request Metrics Tracking"""
import time
from collections import defaultdict
from typing import Dict
import numpy as np
import logging

logger = logging.getLogger(__name__)

class Observer:
    """Track request metrics for monitoring."""

    def __init__(self):
        self.metrics = defaultdict(lambda: {'durations': [], 'tokens': [], 'costs': []})
        logger.info("Initialized Observer")

    def track_request(self, agent_name: str, duration: float, tokens: int = 0, cost: float = 0.0):
        """Track a request."""
        self.metrics[agent_name]['durations'].append(duration)
        self.metrics[agent_name]['tokens'].append(tokens)
        self.metrics[agent_name]['costs'].append(cost)

    def get_metrics(self, agent_name: str) -> Dict:
        """Get metrics for agent."""
        data = self.metrics.get(agent_name, {'durations': [], 'tokens': [], 'costs': []})
        durations = data['durations']

        if not durations:
            return {'count': 0}

        return {
            'count': len(durations),
            'p50_latency_ms': float(np.percentile(durations, 50) * 1000),
            'p95_latency_ms': float(np.percentile(durations, 95) * 1000),
            'p99_latency_ms': float(np.percentile(durations, 99) * 1000),
            'avg_tokens': float(np.mean(data['tokens'])) if data['tokens'] else 0,
            'total_cost': float(np.sum(data['costs']))
        }
