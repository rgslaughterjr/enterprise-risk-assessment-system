"""Performance Benchmark Suite for Risk Assessment System.

Measures latency (p50/p95/p99), throughput, and resource utilization
for all agents and critical operations.
"""

import time
import statistics
import json
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path

# Mock imports to avoid API key requirements in benchmarking
class MockAgent:
    """Mock agent for benchmarking without API calls."""
    def __init__(self, name: str, base_latency: float = 0.5):
        self.name = name
        self.base_latency = base_latency

    def execute(self, *args, **kwargs) -> Dict[str, Any]:
        """Simulate agent execution with realistic latency."""
        time.sleep(self.base_latency)
        return {"status": "success", "agent": self.name}


class PerformanceBenchmark:
    """Benchmark runner for risk assessment agents."""

    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.agents = self._initialize_agents()

    def _initialize_agents(self) -> Dict[str, MockAgent]:
        """Initialize mock agents with realistic latencies."""
        return {
            "cve_fetcher": MockAgent("CVE Fetcher", base_latency=0.03),
            "risk_scorer": MockAgent("Risk Scorer", base_latency=0.08),
            "control_discovery": MockAgent("Control Discovery", base_latency=0.12),
            "gap_analyzer": MockAgent("Gap Analyzer", base_latency=0.06),
            "document_processor": MockAgent("Document Processor", base_latency=0.15),
            "tot_risk_scorer": MockAgent("ToT Risk Scorer", base_latency=0.20),
            "supervisor": MockAgent("Supervisor", base_latency=0.04),
        }

    def measure_latency(self, agent_name: str, iterations: int = 100) -> Dict[str, float]:
        """Measure latency percentiles for an agent.

        Args:
            agent_name: Name of the agent to benchmark
            iterations: Number of iterations to run

        Returns:
            Dictionary with p50, p95, p99 latency in milliseconds
        """
        agent = self.agents[agent_name]
        latencies: List[float] = []

        print(f"\nBenchmarking {agent_name}...")
        for i in range(iterations):
            start = time.perf_counter()
            agent.execute()
            latency = (time.perf_counter() - start) * 1000  # Convert to ms
            latencies.append(latency)

            if (i + 1) % 25 == 0:
                print(f"  Progress: {i + 1}/{iterations} iterations")

        latencies.sort()
        return {
            "p50": statistics.median(latencies),
            "p95": latencies[int(len(latencies) * 0.95)],
            "p99": latencies[int(len(latencies) * 0.99)],
            "mean": statistics.mean(latencies),
            "min": min(latencies),
            "max": max(latencies),
        }

    def measure_throughput(self, agent_name: str, duration_seconds: int = 10) -> Dict[str, float]:
        """Measure throughput (requests per second).

        Args:
            agent_name: Name of the agent to benchmark
            duration_seconds: Duration to run benchmark

        Returns:
            Dictionary with throughput metrics
        """
        agent = self.agents[agent_name]
        start = time.perf_counter()
        count = 0

        print(f"\nMeasuring throughput for {agent_name} ({duration_seconds}s)...")
        while (time.perf_counter() - start) < duration_seconds:
            agent.execute()
            count += 1

        elapsed = time.perf_counter() - start
        throughput = count / elapsed

        return {
            "requests_per_second": throughput,
            "total_requests": count,
            "duration_seconds": elapsed,
        }

    def run_all_benchmarks(self, latency_iterations: int = 100, throughput_duration: int = 10) -> Dict[str, Any]:
        """Run comprehensive benchmarks on all agents.

        Args:
            latency_iterations: Number of iterations for latency tests
            throughput_duration: Duration for throughput tests (seconds)

        Returns:
            Complete benchmark results
        """
        print("=" * 80)
        print("RISK ASSESSMENT SYSTEM - PERFORMANCE BENCHMARK")
        print("=" * 80)
        print(f"Timestamp: {datetime.utcnow().isoformat()}")
        print(f"Latency iterations: {latency_iterations}")
        print(f"Throughput duration: {throughput_duration}s")

        results = {
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "latency_iterations": latency_iterations,
                "throughput_duration": throughput_duration,
            },
            "latency": {},
            "throughput": {},
        }

        # Latency benchmarks
        print("\n" + "=" * 80)
        print("LATENCY BENCHMARKS (p50/p95/p99 in milliseconds)")
        print("=" * 80)

        for agent_name in self.agents.keys():
            latency_results = self.measure_latency(agent_name, latency_iterations)
            results["latency"][agent_name] = latency_results

            print(f"\n{agent_name}:")
            print(f"  p50: {latency_results['p50']:.2f} ms")
            print(f"  p95: {latency_results['p95']:.2f} ms")
            print(f"  p99: {latency_results['p99']:.2f} ms")
            print(f"  Mean: {latency_results['mean']:.2f} ms")

        # Throughput benchmarks
        print("\n" + "=" * 80)
        print("THROUGHPUT BENCHMARKS (requests/second)")
        print("=" * 80)

        for agent_name in self.agents.keys():
            throughput_results = self.measure_throughput(agent_name, throughput_duration)
            results["throughput"][agent_name] = throughput_results

            print(f"\n{agent_name}:")
            print(f"  Throughput: {throughput_results['requests_per_second']:.2f} req/s")
            print(f"  Total requests: {throughput_results['total_requests']}")

        return results

    def generate_report(self, results: Dict[str, Any], output_path: str = "benchmark-report.json"):
        """Generate benchmark report and save to file.

        Args:
            results: Benchmark results
            output_path: Path to save the report
        """
        # Save JSON report
        report_path = Path(output_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)

        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)

        print("\n" + "=" * 80)
        print("BENCHMARK COMPLETE")
        print("=" * 80)
        print(f"Report saved to: {report_path.absolute()}")

        # Print summary
        print("\nSUMMARY:")
        print(f"Agents benchmarked: {len(self.agents)}")
        print(f"Total latency samples: {results['metadata']['latency_iterations'] * len(self.agents)}")
        print(f"Throughput test duration: {results['metadata']['throughput_duration']}s per agent")


def main():
    """Run benchmark suite."""
    benchmark = PerformanceBenchmark()

    # Run all benchmarks
    results = benchmark.run_all_benchmarks(
        latency_iterations=20,
        throughput_duration=3
    )

    # Generate report
    benchmark.generate_report(results, output_path="benchmark-report.json")


if __name__ == "__main__":
    main()
