"""Cost Tracker - API Usage Cost Tracking"""
from datetime import datetime, date
from collections import defaultdict
from typing import Dict
import csv
import logging

logger = logging.getLogger(__name__)

class CostTracker:
    """Track API costs."""

    # Pricing (example rates)
    MODEL_PRICING = {
        'claude-sonnet-4': {'input': 0.003, 'output': 0.015},  # per 1K tokens
        'claude-opus-4': {'input': 0.015, 'output': 0.075},
        'claude-haiku-4': {'input': 0.00025, 'output': 0.00125}
    }

    def __init__(self):
        self.daily_costs = defaultdict(lambda: defaultdict(float))
        self.agent_costs = defaultdict(float)
        logger.info("Initialized CostTracker")

    def log_api_call(self, agent: str, model: str, input_tokens: int, output_tokens: int):
        """Log API call and calculate cost."""
        pricing = self.MODEL_PRICING.get(model, {'input': 0.003, 'output': 0.015})
        cost = (input_tokens / 1000 * pricing['input'] +
                output_tokens / 1000 * pricing['output'])

        today = date.today().isoformat()
        self.daily_costs[today][agent] += cost
        self.agent_costs[agent] += cost

        return cost

    def get_daily_cost(self, day: str = None) -> float:
        """Get total cost for a day."""
        day = day or date.today().isoformat()
        return sum(self.daily_costs[day].values())

    def get_agent_costs(self) -> Dict[str, float]:
        """Get costs by agent."""
        return dict(self.agent_costs)

    def export_to_csv(self, filepath: str):
        """Export costs to CSV."""
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Agent', 'Total Cost'])
            for agent, cost in self.agent_costs.items():
                writer.writerow([agent, f'${cost:.4f}'])
