"""Threat Scenario Agent"""
from typing import List, Dict
from src.reasoning.markov_threat_modeler import MarkovThreatModeler
import logging

logger = logging.getLogger(__name__)

class ThreatScenarioAgent:
    """Generate threat scenarios for CVEs."""

    def __init__(self):
        self.modeler = MarkovThreatModeler()
        logger.info("Initialized ThreatScenarioAgent")

    def generate_scenarios(self, cve: Dict, num_scenarios: int = 10) -> List[Dict]:
        """Generate attack scenarios for a CVE."""
        scenarios = []

        for i in range(num_scenarios):
            technique_sequence = self.modeler.generate_attack_scenario("T1190", steps=8)

            scenarios.append({
                "scenario_id": i + 1,
                "cve_id": cve.get("cve_id"),
                "technique_sequence": technique_sequence,
                "probability": 0.7 - (i * 0.05),  # Mock probability
                "impact": "High" if i < 3 else "Medium",
                "description": f"Attack path via {' -> '.join(technique_sequence[:3])}"
            })

        return scenarios
