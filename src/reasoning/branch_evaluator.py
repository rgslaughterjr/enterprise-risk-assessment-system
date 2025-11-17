"""Tree of Thought - Branch Evaluator"""
from typing import List, Dict
from src.reasoning.branch_generator import Branch
import logging

logger = logging.getLogger(__name__)

class BranchEvaluator:
    """Evaluate and prune ToT branches."""

    def __init__(self, quality_threshold: float = 0.6):
        self.quality_threshold = quality_threshold
        logger.info(f"Initialized BranchEvaluator (threshold={quality_threshold})")

    def evaluate_branch(self, branch: Branch) -> float:
        """Evaluate branch quality (0-1)."""
        # Quality based on confidence and reasoning consistency
        quality = branch.confidence * 0.7 + 0.3  # Mock quality
        return quality

    def prune_branches(self, branches: List[Branch]) -> List[Branch]:
        """Remove low-quality branches."""
        evaluated = [(b, self.evaluate_branch(b)) for b in branches]
        pruned = [b for b, quality in evaluated if quality >= self.quality_threshold]
        logger.info(f"Pruned {len(branches) - len(pruned)} branches")
        return pruned

    def select_best(self, branches: List[Branch]) -> Branch:
        """Select highest quality branch."""
        if not branches:
            raise ValueError("No branches to select from")
        return max(branches, key=lambda b: self.evaluate_branch(b))
