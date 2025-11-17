"""Tree of Thought Risk Scorer Agent"""
from typing import Dict, List
from src.reasoning.branch_generator import BranchGenerator
from src.reasoning.branch_evaluator import BranchEvaluator
from src.frameworks.nist_ai_rmf_adapter import NISTAIRMFAdapter
from src.frameworks.octave_adapter import OctaveAdapter
import logging

logger = logging.getLogger(__name__)

class ToTRiskScorer:
    """Risk scoring agent using Tree of Thought reasoning."""

    def __init__(self, num_branches: int = 5):
        self.generator = BranchGenerator(num_branches)
        self.evaluator = BranchEvaluator()
        self.nist_ai = NISTAIRMFAdapter()
        self.octave = OctaveAdapter()
        logger.info("Initialized ToTRiskScorer")

    def score_risk(self, cve: Dict, asset: Dict, context: Dict) -> Dict:
        """Score risk using ToT approach."""
        # Generate branches
        branches = self.generator.generate_branches(cve)

        # Evaluate and prune
        viable_branches = self.evaluator.prune_branches(branches)

        # Select best
        best_branch = self.evaluator.select_best(viable_branches)

        # Compare frameworks
        nist_score = self.nist_ai.score_risk_nist_ai(cve, asset, context)
        octave_score = self.octave.score_risk_octave(cve, asset, context)

        return {
            "tot_selected_branch": best_branch.strategy,
            "tot_risk_score": best_branch.risk_score,
            "nist_ai_score": nist_score["overall_score"],
            "octave_score": octave_score["overall_risk_score"],
            "consensus_score": (best_branch.risk_score + nist_score["overall_score"] +
                               octave_score["overall_risk_score"]) / 3,
            "branches_evaluated": len(branches),
            "branches_pruned": len(branches) - len(viable_branches)
        }
