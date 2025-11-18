"""
Cost Tracker - Week 9 Monitoring

API cost tracking with CSV export and per-agent breakdown.

Features:
- Track API calls per service (Anthropic, NVD, VirusTotal, etc.)
- Token usage tracking for LLM calls
- Cost estimation in USD
- Daily/monthly cost aggregation
- CSV export for analysis
- Per-agent cost breakdown

Pricing (as of 2024):
- Claude Sonnet: $3/MTok input, $15/MTok output
- NVD API: Free
- VirusTotal: Free (limited), $490/month (Premium)
- AlienVault OTX: Free

Usage:
    tracker = CostTracker()

    # Log API call
    tracker.log_api_call(
        service="anthropic",
        endpoint="messages",
        tokens_input=1000,
        tokens_output=500
    )

    # Get daily cost
    cost = tracker.get_daily_cost()
    print(f"Today's cost: ${cost:.2f}")

    # Export to CSV
    tracker.export_to_csv("costs_2024.csv")
"""

import csv
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, date, timedelta
from collections import defaultdict
from pathlib import Path


@dataclass
class APICallRecord:
    """Record of an API call with cost"""
    timestamp: str
    service: str  # anthropic, nvd, virustotal, otx, cisa, mitre
    endpoint: str
    agent: Optional[str] = None  # Which agent made the call

    # Token usage (for LLM calls)
    tokens_input: int = 0
    tokens_output: int = 0
    tokens_total: int = 0

    # Cost (USD)
    cost_input: float = 0.0
    cost_output: float = 0.0
    cost_total: float = 0.0

    # Metadata
    duration_ms: float = 0.0
    success: bool = True
    error: Optional[str] = None


class CostTracker:
    """
    API cost tracker with CSV export.

    Features:
    - Per-service cost tracking
    - Per-agent cost breakdown
    - Token usage tracking
    - Daily/monthly aggregation
    - CSV export
    - Thread-safe
    """

    # Pricing (USD per 1M tokens)
    PRICING = {
        "anthropic_sonnet_input": 3.00,  # $3/MTok
        "anthropic_sonnet_output": 15.00,  # $15/MTok
        "anthropic_haiku_input": 0.25,  # $0.25/MTok
        "anthropic_haiku_output": 1.25,  # $1.25/MTok
        # Other services are free (with API limits)
        "nvd": 0.0,
        "virustotal": 0.0,  # Assuming free tier
        "otx": 0.0,
        "cisa": 0.0,
        "mitre": 0.0,
    }

    def __init__(self, data_dir: str = "data"):
        """
        Initialize cost tracker.

        Args:
            data_dir: Directory for cost data files
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        # Call history
        self.call_history: List[APICallRecord] = []

        # Aggregated metrics
        self.total_cost = 0.0
        self.cost_by_service: Dict[str, float] = defaultdict(float)
        self.cost_by_agent: Dict[str, float] = defaultdict(float)
        self.cost_by_date: Dict[date, float] = defaultdict(float)

        # Token usage
        self.tokens_by_service: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"input": 0, "output": 0, "total": 0}
        )

        # Call counts
        self.calls_by_service: Dict[str, int] = defaultdict(int)

        # Thread lock
        self.lock = threading.Lock()

    def log_api_call(
        self,
        service: str,
        endpoint: str,
        agent: Optional[str] = None,
        tokens_input: int = 0,
        tokens_output: int = 0,
        duration_ms: float = 0.0,
        success: bool = True,
        error: Optional[str] = None,
        model: str = "sonnet"  # sonnet or haiku
    ) -> APICallRecord:
        """
        Log an API call and calculate cost.

        Args:
            service: Service name (anthropic, nvd, virustotal, etc.)
            endpoint: API endpoint
            agent: Agent that made the call
            tokens_input: Input tokens (for LLM calls)
            tokens_output: Output tokens (for LLM calls)
            duration_ms: Call duration in milliseconds
            success: Whether call succeeded
            error: Error message if failed
            model: LLM model (sonnet or haiku)

        Returns:
            APICallRecord with cost calculation
        """
        with self.lock:
            # Calculate tokens
            tokens_total = tokens_input + tokens_output

            # Calculate cost
            cost_input = 0.0
            cost_output = 0.0

            if service == "anthropic":
                if model == "sonnet":
                    cost_input = (tokens_input / 1_000_000) * self.PRICING["anthropic_sonnet_input"]
                    cost_output = (tokens_output / 1_000_000) * self.PRICING["anthropic_sonnet_output"]
                elif model == "haiku":
                    cost_input = (tokens_input / 1_000_000) * self.PRICING["anthropic_haiku_input"]
                    cost_output = (tokens_output / 1_000_000) * self.PRICING["anthropic_haiku_output"]
            else:
                # Other services are free (or assumed free tier)
                cost_input = 0.0
                cost_output = 0.0

            cost_total = cost_input + cost_output

            # Create record
            record = APICallRecord(
                timestamp=datetime.utcnow().isoformat() + "Z",
                service=service,
                endpoint=endpoint,
                agent=agent,
                tokens_input=tokens_input,
                tokens_output=tokens_output,
                tokens_total=tokens_total,
                cost_input=cost_input,
                cost_output=cost_output,
                cost_total=cost_total,
                duration_ms=duration_ms,
                success=success,
                error=error
            )

            # Add to history
            self.call_history.append(record)

            # Update aggregates
            self.total_cost += cost_total
            self.cost_by_service[service] += cost_total
            if agent:
                self.cost_by_agent[agent] += cost_total

            today = datetime.utcnow().date()
            self.cost_by_date[today] += cost_total

            # Update token counts
            if tokens_total > 0:
                self.tokens_by_service[service]["input"] += tokens_input
                self.tokens_by_service[service]["output"] += tokens_output
                self.tokens_by_service[service]["total"] += tokens_total

            # Update call counts
            self.calls_by_service[service] += 1

            return record

    def get_total_cost(self) -> float:
        """Get total cost across all services"""
        with self.lock:
            return self.total_cost

    def get_daily_cost(self, target_date: Optional[date] = None) -> float:
        """
        Get cost for a specific day.

        Args:
            target_date: Date to query (defaults to today)

        Returns:
            Cost in USD
        """
        if target_date is None:
            target_date = datetime.utcnow().date()

        with self.lock:
            return self.cost_by_date.get(target_date, 0.0)

    def get_monthly_cost(self, year: int, month: int) -> float:
        """
        Get cost for a specific month.

        Args:
            year: Year
            month: Month (1-12)

        Returns:
            Cost in USD
        """
        with self.lock:
            total = 0.0
            for target_date, cost in self.cost_by_date.items():
                if target_date.year == year and target_date.month == month:
                    total += cost
            return total

    def get_cost_by_service(self) -> Dict[str, float]:
        """Get cost breakdown by service"""
        with self.lock:
            return dict(self.cost_by_service)

    def get_cost_by_agent(self) -> Dict[str, float]:
        """Get cost breakdown by agent"""
        with self.lock:
            return dict(self.cost_by_agent)

    def get_token_usage(self, service: Optional[str] = None) -> Dict:
        """
        Get token usage statistics.

        Args:
            service: Optional service to filter by

        Returns:
            Dictionary with token usage
        """
        with self.lock:
            if service:
                return dict(self.tokens_by_service.get(service, {}))
            else:
                # Aggregate across all services
                total_input = sum(
                    tokens["input"]
                    for tokens in self.tokens_by_service.values()
                )
                total_output = sum(
                    tokens["output"]
                    for tokens in self.tokens_by_service.values()
                )
                return {
                    "input": total_input,
                    "output": total_output,
                    "total": total_input + total_output,
                    "by_service": {
                        service: dict(tokens)
                        for service, tokens in self.tokens_by_service.items()
                    }
                }

    def get_call_statistics(self) -> Dict:
        """Get call statistics"""
        with self.lock:
            total_calls = len(self.call_history)
            successful_calls = sum(1 for record in self.call_history if record.success)
            failed_calls = total_calls - successful_calls

            return {
                "total_calls": total_calls,
                "successful_calls": successful_calls,
                "failed_calls": failed_calls,
                "success_rate": successful_calls / total_calls if total_calls > 0 else 0.0,
                "calls_by_service": dict(self.calls_by_service),
                "total_cost": self.total_cost,
                "cost_by_service": dict(self.cost_by_service),
                "cost_by_agent": dict(self.cost_by_agent)
            }

    def export_to_csv(self, filename: str, start_date: Optional[date] = None, end_date: Optional[date] = None):
        """
        Export call history to CSV.

        Args:
            filename: Output CSV filename
            start_date: Optional start date filter
            end_date: Optional end date filter
        """
        filepath = self.data_dir / filename

        with self.lock:
            # Filter records
            records = self.call_history
            if start_date or end_date:
                filtered_records = []
                for record in records:
                    record_date = datetime.fromisoformat(record.timestamp.rstrip("Z")).date()
                    if start_date and record_date < start_date:
                        continue
                    if end_date and record_date > end_date:
                        continue
                    filtered_records.append(record)
                records = filtered_records

            # Write CSV
            if records:
                with open(filepath, 'w', newline='') as f:
                    fieldnames = [
                        'timestamp', 'service', 'endpoint', 'agent',
                        'tokens_input', 'tokens_output', 'tokens_total',
                        'cost_input', 'cost_output', 'cost_total',
                        'duration_ms', 'success', 'error'
                    ]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()

                    for record in records:
                        writer.writerow(asdict(record))

    def export_daily_summary_csv(self, filename: str):
        """
        Export daily cost summary to CSV.

        Args:
            filename: Output CSV filename
        """
        filepath = self.data_dir / filename

        with self.lock:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['date', 'cost_usd', 'calls'])

                # Group by date
                calls_by_date: Dict[date, int] = defaultdict(int)
                for record in self.call_history:
                    record_date = datetime.fromisoformat(record.timestamp.rstrip("Z")).date()
                    calls_by_date[record_date] += 1

                # Write sorted by date
                for target_date in sorted(self.cost_by_date.keys()):
                    cost = self.cost_by_date[target_date]
                    calls = calls_by_date[target_date]
                    writer.writerow([target_date.isoformat(), f"{cost:.4f}", calls])

    def export_service_summary_csv(self, filename: str):
        """
        Export per-service cost summary to CSV.

        Args:
            filename: Output CSV filename
        """
        filepath = self.data_dir / filename

        with self.lock:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['service', 'calls', 'cost_usd', 'tokens_total'])

                for service in sorted(self.cost_by_service.keys()):
                    calls = self.calls_by_service[service]
                    cost = self.cost_by_service[service]
                    tokens = self.tokens_by_service[service]["total"]
                    writer.writerow([service, calls, f"{cost:.4f}", tokens])

    def reset_metrics(self):
        """Reset all metrics"""
        with self.lock:
            self.call_history.clear()
            self.total_cost = 0.0
            self.cost_by_service.clear()
            self.cost_by_agent.clear()
            self.cost_by_date.clear()
            self.tokens_by_service.clear()
            self.calls_by_service.clear()


# Singleton instance
_global_cost_tracker = None


def get_cost_tracker() -> CostTracker:
    """Get global cost tracker instance"""
    global _global_cost_tracker
    if _global_cost_tracker is None:
        _global_cost_tracker = CostTracker()
    return _global_cost_tracker
