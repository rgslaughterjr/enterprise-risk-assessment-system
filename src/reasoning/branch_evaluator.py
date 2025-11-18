"""Branch Evaluator for Tree of Thought (ToT) risk assessment.

This module evaluates multiple risk assessment branches, prunes low-quality
evaluations, and synthesizes consensus scores from high-quality branches.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import statistics

logger = logging.getLogger(__name__)


class BranchEvaluator:
    """Evaluates and synthesizes results from multiple assessment branches.

    Implements quality scoring, pruning, and weighted consensus mechanisms
    for multi-branch Tree of Thought risk assessment.
    """

    DEFAULT_QUALITY_THRESHOLD = 0.6
    MIN_BRANCHES_FOR_CONSENSUS = 2

    def __init__(
        self,
        quality_threshold: float = DEFAULT_QUALITY_THRESHOLD,
        enable_pruning: bool = True,
    ):
        """Initialize branch evaluator.

        Args:
            quality_threshold: Minimum quality score for branch inclusion (0-1)
            enable_pruning: If True, prune low-quality branches
        """
        self.quality_threshold = quality_threshold
        self.enable_pruning = enable_pruning

        logger.info(
            f"Branch evaluator initialized "
            f"(threshold={quality_threshold}, pruning={enable_pruning})"
        )

    def evaluate_branch(self, branch: Dict[str, Any]) -> float:
        """Evaluate quality of a single assessment branch.

        Args:
            branch: Branch dictionary with evaluation results

        Returns:
            Quality score (0.0 to 1.0)

        Example:
            >>> evaluator = BranchEvaluator()
            >>> branch = {"evaluation": {"score": 8.5, "confidence": 0.9}}
            >>> quality = evaluator.evaluate_branch(branch)
            >>> 0.0 <= quality <= 1.0
            True
        """
        if not branch.get("evaluation"):
            logger.warning(f"Branch {branch.get('branch_id')} has no evaluation")
            return 0.0

        evaluation = branch["evaluation"]

        # Quality factors
        factors = []

        # Factor 1: Confidence score (if provided)
        if "confidence" in evaluation:
            confidence = float(evaluation["confidence"])
            factors.append(confidence)

        # Factor 2: Completeness (all required fields present)
        required_fields = ["score", "risk_level", "justification"]
        completeness = sum(1 for f in required_fields if f in evaluation) / len(required_fields)
        factors.append(completeness)

        # Factor 3: Justification quality (length and detail)
        justification = evaluation.get("justification", "")
        if justification:
            # Longer, more detailed justifications = higher quality
            justification_score = min(len(justification) / 200.0, 1.0)
            factors.append(justification_score)

        # Factor 4: Score consistency (reasonable score range)
        score = evaluation.get("score")
        if score is not None:
            try:
                score_val = float(score)
                # Scores should be in reasonable range (0-10 or 0-100)
                if 0 <= score_val <= 10:
                    consistency = 1.0
                elif 0 <= score_val <= 100:
                    consistency = 1.0
                else:
                    consistency = 0.5  # Out of normal range
                factors.append(consistency)
            except (ValueError, TypeError):
                factors.append(0.3)  # Invalid score format

        # Calculate average quality score
        if factors:
            quality_score = sum(factors) / len(factors)
        else:
            quality_score = 0.0

        logger.debug(f"Branch {branch.get('branch_id')} quality: {quality_score:.2f}")
        return quality_score

    def prune_low_quality(
        self,
        branches: List[Dict[str, Any]],
        threshold: Optional[float] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Prune branches below quality threshold.

        Args:
            branches: List of evaluated branches
            threshold: Quality threshold (uses instance default if None)

        Returns:
            Tuple of (high_quality_branches, pruned_branches)

        Example:
            >>> evaluator = BranchEvaluator(quality_threshold=0.6)
            >>> branches = [...]  # List of branches
            >>> high_quality, pruned = evaluator.prune_low_quality(branches)
        """
        if threshold is None:
            threshold = self.quality_threshold

        if not self.enable_pruning:
            logger.info("Pruning disabled, returning all branches")
            return branches, []

        logger.info(f"Pruning branches with quality < {threshold}")

        high_quality = []
        pruned = []

        for branch in branches:
            quality = branch.get("quality_score")

            if quality is None:
                # Evaluate if not already done
                quality = self.evaluate_branch(branch)
                branch["quality_score"] = quality

            if quality >= threshold:
                high_quality.append(branch)
            else:
                pruned.append(branch)

        logger.info(
            f"Pruned {len(pruned)} branches, "
            f"retained {len(high_quality)} high-quality branches"
        )

        return high_quality, pruned

    def consensus_scoring(
        self,
        branches: List[Dict[str, Any]],
        method: str = "weighted_average",
    ) -> Dict[str, Any]:
        """Calculate consensus score from multiple branches.

        Args:
            branches: List of evaluated branches
            method: Consensus method ('weighted_average', 'median', 'majority_vote')

        Returns:
            Consensus score dictionary with score, confidence, and metadata

        Example:
            >>> evaluator = BranchEvaluator()
            >>> branches = [...]  # List of evaluated branches
            >>> consensus = evaluator.consensus_scoring(branches)
            >>> consensus['final_score']
            7.5
        """
        logger.info(f"Calculating consensus from {len(branches)} branches using {method}")

        if not branches:
            logger.warning("No branches provided for consensus")
            return {
                "final_score": 0.0,
                "confidence": 0.0,
                "method": method,
                "num_branches": 0,
                "error": "No branches available",
            }

        if len(branches) < self.MIN_BRANCHES_FOR_CONSENSUS:
            logger.warning(
                f"Fewer than {self.MIN_BRANCHES_FOR_CONSENSUS} branches available"
            )

        # Extract scores and weights
        scores = []
        weights = []
        quality_scores = []

        for branch in branches:
            evaluation = branch.get("evaluation")
            if not evaluation:
                continue

            try:
                score = float(evaluation.get("score", 0))
                scores.append(score)

                # Weight = quality score or branch weight
                weight = branch.get("weight") or branch.get("quality_score", 1.0)
                weights.append(weight)

                quality = branch.get("quality_score", 0.0)
                quality_scores.append(quality)

            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid score in branch: {e}")
                continue

        if not scores:
            return {
                "final_score": 0.0,
                "confidence": 0.0,
                "method": method,
                "num_branches": len(branches),
                "error": "No valid scores found",
            }

        # Calculate consensus based on method
        if method == "weighted_average":
            final_score = self._weighted_average(scores, weights)

        elif method == "median":
            final_score = statistics.median(scores)

        elif method == "majority_vote":
            final_score = self._majority_vote(scores)

        else:
            logger.warning(f"Unknown method {method}, using weighted_average")
            final_score = self._weighted_average(scores, weights)

        # Calculate confidence
        confidence = self._calculate_confidence(scores, quality_scores)

        # Calculate variance for uncertainty measure
        variance = statistics.variance(scores) if len(scores) > 1 else 0.0

        consensus = {
            "final_score": round(final_score, 2),
            "confidence": round(confidence, 2),
            "method": method,
            "num_branches": len(branches),
            "score_range": (min(scores), max(scores)),
            "score_variance": round(variance, 2),
            "average_quality": round(statistics.mean(quality_scores), 2) if quality_scores else 0.0,
            "calculated_at": datetime.utcnow().isoformat(),
        }

        logger.info(
            f"Consensus score: {final_score:.2f} "
            f"(confidence: {confidence:.2f}, variance: {variance:.2f})"
        )

        return consensus

    def _weighted_average(
        self,
        scores: List[float],
        weights: List[float],
    ) -> float:
        """Calculate weighted average of scores.

        Args:
            scores: List of scores
            weights: List of weights

        Returns:
            Weighted average score
        """
        if len(scores) != len(weights):
            logger.warning("Score and weight counts mismatch, using equal weights")
            weights = [1.0] * len(scores)

        # Normalize weights
        total_weight = sum(weights)
        if total_weight == 0:
            return statistics.mean(scores)

        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        return weighted_sum / total_weight

    def _majority_vote(self, scores: List[float]) -> float:
        """Calculate majority vote consensus (most common score range).

        Args:
            scores: List of scores

        Returns:
            Representative score from majority range
        """
        # Group scores into ranges
        ranges = {
            "low": [],      # 0-3
            "medium": [],   # 4-6
            "high": [],     # 7-10
        }

        for score in scores:
            if score <= 3:
                ranges["low"].append(score)
            elif score <= 6:
                ranges["medium"].append(score)
            else:
                ranges["high"].append(score)

        # Find range with most votes
        majority_range = max(ranges.items(), key=lambda x: len(x[1]))

        if majority_range[1]:
            return statistics.mean(majority_range[1])
        else:
            return statistics.mean(scores)

    def _calculate_confidence(
        self,
        scores: List[float],
        quality_scores: List[float],
    ) -> float:
        """Calculate confidence in consensus score.

        Args:
            scores: List of risk scores
            quality_scores: List of branch quality scores

        Returns:
            Confidence value (0-1)
        """
        factors = []

        # Factor 1: Score agreement (low variance = high confidence)
        if len(scores) > 1:
            variance = statistics.variance(scores)
            max_variance = (max(scores) - min(scores)) ** 2 / 4
            if max_variance > 0:
                agreement = 1.0 - min(variance / max_variance, 1.0)
            else:
                agreement = 1.0
            factors.append(agreement)

        # Factor 2: Average quality of branches
        if quality_scores:
            avg_quality = statistics.mean(quality_scores)
            factors.append(avg_quality)

        # Factor 3: Number of branches (more = higher confidence)
        num_branches_factor = min(len(scores) / 5.0, 1.0)
        factors.append(num_branches_factor)

        if factors:
            return sum(factors) / len(factors)
        else:
            return 0.5  # Default moderate confidence

    def evaluate_all_branches(
        self,
        branches: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Evaluate quality of all branches and add quality scores.

        Args:
            branches: List of branches to evaluate

        Returns:
            Branches with quality_score field added
        """
        logger.info(f"Evaluating {len(branches)} branches")

        for branch in branches:
            if "quality_score" not in branch:
                quality = self.evaluate_branch(branch)
                branch["quality_score"] = quality

        return branches

    def get_evaluation_summary(
        self,
        branches: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Get summary statistics for branch evaluations.

        Args:
            branches: List of evaluated branches

        Returns:
            Summary dictionary with statistics
        """
        if not branches:
            return {"error": "No branches provided"}

        quality_scores = [b.get("quality_score", 0.0) for b in branches]
        risk_scores = []

        for b in branches:
            eval_data = b.get("evaluation", {})
            if "score" in eval_data:
                try:
                    risk_scores.append(float(eval_data["score"]))
                except (ValueError, TypeError):
                    continue

        summary = {
            "total_branches": len(branches),
            "avg_quality": round(statistics.mean(quality_scores), 2) if quality_scores else 0.0,
            "min_quality": round(min(quality_scores), 2) if quality_scores else 0.0,
            "max_quality": round(max(quality_scores), 2) if quality_scores else 0.0,
            "high_quality_count": sum(1 for q in quality_scores if q >= self.quality_threshold),
            "low_quality_count": sum(1 for q in quality_scores if q < self.quality_threshold),
        }

        if risk_scores:
            summary["avg_risk_score"] = round(statistics.mean(risk_scores), 2)
            summary["risk_score_range"] = (round(min(risk_scores), 2), round(max(risk_scores), 2))

        return summary
