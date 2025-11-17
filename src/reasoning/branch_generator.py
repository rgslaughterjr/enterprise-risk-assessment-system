"""Tree of Thought - Branch Generator"""
from typing import List, Dict
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class Branch:
    """A reasoning branch in Tree of Thought."""
    branch_id: int
    strategy: str
    description: str
    risk_score: float
    confidence: float
    reasoning: str

class BranchGenerator:
    """Generate multiple evaluation branches for ToT reasoning."""

    STRATEGIES = [
        "conservative_scoring", "aggressive_scoring", "contextual_adjustment",
        "historical_pattern", "threat_intelligence_based"
    ]

    def __init__(self, num_branches: int = 5):
        self.num_branches = num_branches
        logger.info(f"Initialized BranchGenerator ({num_branches} branches)")

    def generate_branches(self, risk: Dict) -> List[Branch]:
        """Generate evaluation branches for a risk."""
        branches = []
        for i in range(min(self.num_branches, len(self.STRATEGIES))):
            strategy = self.STRATEGIES[i]
            branch = Branch(
                branch_id=i,
                strategy=strategy,
                description=f"Evaluate using {strategy.replace('_', ' ')}",
                risk_score=self._mock_score(risk, strategy),
                confidence=0.7 + (i * 0.05),
                reasoning=f"Applied {strategy} to {risk.get('cve_id', 'risk')}"
            )
            branches.append(branch)
        return branches

    def _mock_score(self, risk: Dict, strategy: str) -> float:
        """Mock scoring (placeholder for real implementation)."""
        base_score = risk.get('cvss_score', 5.0)
        adjustments = {
            "conservative_scoring": -1.0,
            "aggressive_scoring": +1.5,
            "contextual_adjustment": +0.5,
            "historical_pattern": -0.5,
            "threat_intelligence_based": +1.0
        }
        return max(0, min(10, base_score + adjustments.get(strategy, 0)))
