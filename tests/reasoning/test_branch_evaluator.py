"""Tests for Tree of Thought Branch Evaluator."""

import pytest
from src.reasoning.branch_evaluator import BranchEvaluator


class TestBranchEvaluator:
    """Test suite for BranchEvaluator."""

    @pytest.fixture
    def evaluator(self):
        """Create branch evaluator instance."""
        return BranchEvaluator()

    @pytest.fixture
    def sample_branch_high_quality(self):
        """Create high-quality sample branch."""
        return {
            "branch_id": "RISK-001_nist_ai_rmf_0",
            "risk_id": "RISK-001",
            "strategy": "nist_ai_rmf",
            "evaluation": {
                "score": 7.5,
                "risk_level": "High",
                "confidence": 0.9,
                "justification": "This is a detailed justification explaining why this risk is scored as high. It includes multiple factors including the CVSS score, asset criticality, and threat landscape analysis with specific evidence.",
            },
        }

    @pytest.fixture
    def sample_branch_low_quality(self):
        """Create low-quality sample branch."""
        return {
            "branch_id": "RISK-001_fair_1",
            "risk_id": "RISK-001",
            "strategy": "fair",
            "evaluation": {
                "score": 5.0,
                "justification": "Short",  # Too short
            },
        }

    @pytest.fixture
    def sample_branches_mixed(
        self, sample_branch_high_quality, sample_branch_low_quality
    ):
        """Create mixed quality branches."""
        return [
            sample_branch_high_quality,
            {
                "branch_id": "RISK-001_octave_1",
                "evaluation": {
                    "score": 8.0,
                    "risk_level": "High",
                    "confidence": 0.85,
                    "justification": "Comprehensive OCTAVE analysis shows high organizational risk due to critical asset exposure and multiple threat vectors.",
                },
            },
            sample_branch_low_quality,
        ]

    def test_init_default(self):
        """Test evaluator initialization with defaults."""
        evaluator = BranchEvaluator()

        assert evaluator.quality_threshold == 0.6
        assert evaluator.enable_pruning is True

    def test_init_custom_threshold(self):
        """Test evaluator initialization with custom threshold."""
        evaluator = BranchEvaluator(quality_threshold=0.75)

        assert evaluator.quality_threshold == 0.75

    def test_init_pruning_disabled(self):
        """Test evaluator initialization with pruning disabled."""
        evaluator = BranchEvaluator(enable_pruning=False)

        assert evaluator.enable_pruning is False

    def test_evaluate_branch_high_quality(
        self, evaluator, sample_branch_high_quality
    ):
        """Test evaluating a high-quality branch."""
        quality = evaluator.evaluate_branch(sample_branch_high_quality)

        assert isinstance(quality, float)
        assert 0.0 <= quality <= 1.0
        assert quality >= 0.7  # Should be high quality

    def test_evaluate_branch_low_quality(self, evaluator, sample_branch_low_quality):
        """Test evaluating a low-quality branch."""
        quality = evaluator.evaluate_branch(sample_branch_low_quality)

        assert isinstance(quality, float)
        assert 0.0 <= quality <= 1.0
        assert quality < 0.7  # Should be lower quality

    def test_evaluate_branch_no_evaluation(self, evaluator):
        """Test evaluating a branch with no evaluation."""
        branch = {"branch_id": "TEST", "evaluation": None}
        quality = evaluator.evaluate_branch(branch)

        assert quality == 0.0

    def test_evaluate_branch_empty_evaluation(self, evaluator):
        """Test evaluating a branch with empty evaluation."""
        branch = {"branch_id": "TEST", "evaluation": {}}
        quality = evaluator.evaluate_branch(branch)

        assert quality < 0.5  # Should be low quality

    def test_evaluate_branch_confidence_factor(self, evaluator):
        """Test that confidence affects quality score."""
        branch_high_conf = {
            "evaluation": {
                "score": 7.0,
                "risk_level": "High",
                "confidence": 0.95,
                "justification": "Detailed analysis with high confidence",
            }
        }

        branch_low_conf = {
            "evaluation": {
                "score": 7.0,
                "risk_level": "High",
                "confidence": 0.50,
                "justification": "Detailed analysis with low confidence",
            }
        }

        quality_high = evaluator.evaluate_branch(branch_high_conf)
        quality_low = evaluator.evaluate_branch(branch_low_conf)

        assert quality_high > quality_low

    def test_evaluate_branch_completeness_factor(self, evaluator):
        """Test that completeness affects quality score."""
        branch_complete = {
            "evaluation": {
                "score": 7.0,
                "risk_level": "High",
                "justification": "Complete evaluation",
            }
        }

        branch_incomplete = {
            "evaluation": {
                "score": 7.0,
                # Missing risk_level and justification
            }
        }

        quality_complete = evaluator.evaluate_branch(branch_complete)
        quality_incomplete = evaluator.evaluate_branch(branch_incomplete)

        assert quality_complete > quality_incomplete

    def test_evaluate_branch_justification_length(self, evaluator):
        """Test that justification length affects quality."""
        branch_long = {
            "evaluation": {
                "score": 7.0,
                "risk_level": "High",
                "justification": "This is a very detailed and comprehensive justification that explains all the factors considered in the risk assessment including vulnerabilities, assets, threats, and controls. " * 3,
            }
        }

        branch_short = {
            "evaluation": {
                "score": 7.0,
                "risk_level": "High",
                "justification": "Short",
            }
        }

        quality_long = evaluator.evaluate_branch(branch_long)
        quality_short = evaluator.evaluate_branch(branch_short)

        assert quality_long > quality_short

    def test_evaluate_branch_score_consistency(self, evaluator):
        """Test that score consistency is validated."""
        branch_valid = {"evaluation": {"score": 7.5}}
        branch_invalid = {"evaluation": {"score": 150}}  # Out of range

        quality_valid = evaluator.evaluate_branch(branch_valid)
        quality_invalid = evaluator.evaluate_branch(branch_invalid)

        assert quality_valid > quality_invalid

    def test_prune_low_quality_default_threshold(
        self, evaluator, sample_branches_mixed
    ):
        """Test pruning with default threshold."""
        # Add quality scores
        for branch in sample_branches_mixed:
            branch["quality_score"] = evaluator.evaluate_branch(branch)

        high_quality, pruned = evaluator.prune_low_quality(sample_branches_mixed)

        assert len(high_quality) + len(pruned) == len(sample_branches_mixed)
        assert all(b["quality_score"] >= 0.6 for b in high_quality)
        assert all(b["quality_score"] < 0.6 for b in pruned)

    def test_prune_low_quality_custom_threshold(self, evaluator, sample_branches_mixed):
        """Test pruning with custom threshold."""
        for branch in sample_branches_mixed:
            branch["quality_score"] = evaluator.evaluate_branch(branch)

        high_quality, pruned = evaluator.prune_low_quality(
            sample_branches_mixed, threshold=0.8
        )

        assert all(b["quality_score"] >= 0.8 for b in high_quality)
        assert all(b["quality_score"] < 0.8 for b in pruned)

    def test_prune_low_quality_evaluates_if_needed(self, evaluator):
        """Test that pruning evaluates quality if not already done."""
        branches = [
            {
                "branch_id": "TEST1",
                "evaluation": {
                    "score": 8.0,
                    "risk_level": "High",
                    "confidence": 0.9,
                    "justification": "Detailed analysis",
                },
            }
        ]

        high_quality, pruned = evaluator.prune_low_quality(branches)

        assert "quality_score" in high_quality[0]
        assert isinstance(high_quality[0]["quality_score"], float)

    def test_prune_low_quality_pruning_disabled(self, sample_branches_mixed):
        """Test that pruning can be disabled."""
        evaluator = BranchEvaluator(enable_pruning=False)

        high_quality, pruned = evaluator.prune_low_quality(sample_branches_mixed)

        assert len(high_quality) == len(sample_branches_mixed)
        assert len(pruned) == 0

    def test_consensus_scoring_weighted_average(self, evaluator):
        """Test consensus scoring with weighted average."""
        branches = [
            {
                "evaluation": {"score": 7.0},
                "quality_score": 0.8,
            },
            {
                "evaluation": {"score": 8.0},
                "quality_score": 0.9,
            },
            {
                "evaluation": {"score": 6.0},
                "quality_score": 0.7,
            },
        ]

        consensus = evaluator.consensus_scoring(branches, method="weighted_average")

        assert "final_score" in consensus
        assert "confidence" in consensus
        assert "method" in consensus
        assert consensus["method"] == "weighted_average"
        assert 6.0 <= consensus["final_score"] <= 8.0

    def test_consensus_scoring_median(self, evaluator):
        """Test consensus scoring with median."""
        branches = [
            {"evaluation": {"score": 7.0}, "quality_score": 0.8},
            {"evaluation": {"score": 8.0}, "quality_score": 0.9},
            {"evaluation": {"score": 6.0}, "quality_score": 0.7},
        ]

        consensus = evaluator.consensus_scoring(branches, method="median")

        assert consensus["method"] == "median"
        assert consensus["final_score"] == 7.0  # Median of [6, 7, 8]

    def test_consensus_scoring_majority_vote(self, evaluator):
        """Test consensus scoring with majority vote."""
        branches = [
            {"evaluation": {"score": 7.5}, "quality_score": 0.8},
            {"evaluation": {"score": 8.0}, "quality_score": 0.9},
            {"evaluation": {"score": 7.2}, "quality_score": 0.7},
            {"evaluation": {"score": 3.0}, "quality_score": 0.6},
        ]

        consensus = evaluator.consensus_scoring(branches, method="majority_vote")

        assert consensus["method"] == "majority_vote"
        assert isinstance(consensus["final_score"], float)

    def test_consensus_scoring_empty_branches(self, evaluator):
        """Test consensus scoring with no branches."""
        consensus = evaluator.consensus_scoring([], method="weighted_average")

        assert consensus["final_score"] == 0.0
        assert consensus["confidence"] == 0.0
        assert "error" in consensus

    def test_consensus_scoring_invalid_scores(self, evaluator):
        """Test consensus scoring with invalid scores."""
        branches = [
            {"evaluation": {"score": "invalid"}, "quality_score": 0.8},
        ]

        consensus = evaluator.consensus_scoring(branches)

        assert "error" in consensus or consensus["final_score"] == 0.0

    def test_consensus_scoring_metadata(self, evaluator):
        """Test that consensus includes metadata."""
        branches = [
            {"evaluation": {"score": 7.0}, "quality_score": 0.8},
            {"evaluation": {"score": 8.0}, "quality_score": 0.9},
        ]

        consensus = evaluator.consensus_scoring(branches)

        assert "num_branches" in consensus
        assert "score_range" in consensus
        assert "score_variance" in consensus
        assert "average_quality" in consensus
        assert "calculated_at" in consensus

    def test_consensus_scoring_score_range(self, evaluator):
        """Test that score range is calculated correctly."""
        branches = [
            {"evaluation": {"score": 5.0}, "quality_score": 0.7},
            {"evaluation": {"score": 9.0}, "quality_score": 0.9},
        ]

        consensus = evaluator.consensus_scoring(branches)

        assert consensus["score_range"] == (5.0, 9.0)

    def test_consensus_scoring_variance(self, evaluator):
        """Test that variance is calculated."""
        branches = [
            {"evaluation": {"score": 7.0}, "quality_score": 0.8},
            {"evaluation": {"score": 7.0}, "quality_score": 0.9},
        ]

        consensus = evaluator.consensus_scoring(branches)

        assert consensus["score_variance"] == 0.0  # Identical scores

    def test_evaluate_all_branches(self, evaluator, sample_branches_mixed):
        """Test evaluating all branches at once."""
        evaluated = evaluator.evaluate_all_branches(sample_branches_mixed)

        assert len(evaluated) == len(sample_branches_mixed)
        assert all("quality_score" in b for b in evaluated)
        assert all(isinstance(b["quality_score"], float) for b in evaluated)

    def test_evaluate_all_branches_preserves_existing(self, evaluator):
        """Test that existing quality scores are preserved."""
        branches = [
            {
                "evaluation": {"score": 7.0},
                "quality_score": 0.95,  # Pre-existing
            }
        ]

        evaluated = evaluator.evaluate_all_branches(branches)

        assert evaluated[0]["quality_score"] == 0.95  # Should be preserved

    def test_get_evaluation_summary_basic(self, evaluator, sample_branches_mixed):
        """Test getting evaluation summary."""
        for branch in sample_branches_mixed:
            branch["quality_score"] = evaluator.evaluate_branch(branch)

        summary = evaluator.get_evaluation_summary(sample_branches_mixed)

        assert "total_branches" in summary
        assert "avg_quality" in summary
        assert "min_quality" in summary
        assert "max_quality" in summary
        assert "high_quality_count" in summary
        assert "low_quality_count" in summary

    def test_get_evaluation_summary_empty(self, evaluator):
        """Test getting summary for empty list."""
        summary = evaluator.get_evaluation_summary([])

        assert "error" in summary

    def test_get_evaluation_summary_counts(self, evaluator):
        """Test that summary counts are correct."""
        branches = [
            {"evaluation": {"score": 7.0}, "quality_score": 0.8},
            {"evaluation": {"score": 8.0}, "quality_score": 0.9},
            {"evaluation": {"score": 5.0}, "quality_score": 0.5},
        ]

        summary = evaluator.get_evaluation_summary(branches)

        assert summary["total_branches"] == 3
        assert summary["high_quality_count"] == 2
        assert summary["low_quality_count"] == 1

    def test_get_evaluation_summary_risk_scores(self, evaluator):
        """Test that summary includes risk score statistics."""
        branches = [
            {"evaluation": {"score": 7.0}, "quality_score": 0.8},
            {"evaluation": {"score": 8.0}, "quality_score": 0.9},
        ]

        summary = evaluator.get_evaluation_summary(branches)

        assert "avg_risk_score" in summary
        assert "risk_score_range" in summary
        assert summary["avg_risk_score"] == 7.5
        assert summary["risk_score_range"] == (7.0, 8.0)

    def test_weighted_average_calculation(self, evaluator):
        """Test weighted average calculation."""
        scores = [7.0, 8.0, 9.0]
        weights = [0.5, 0.3, 0.2]

        result = evaluator._weighted_average(scores, weights)

        expected = (7.0 * 0.5 + 8.0 * 0.3 + 9.0 * 0.2)
        assert abs(result - expected) < 0.01

    def test_weighted_average_equal_weights(self, evaluator):
        """Test weighted average with equal weights."""
        scores = [6.0, 8.0, 10.0]
        weights = [1.0, 1.0, 1.0]

        result = evaluator._weighted_average(scores, weights)

        assert result == 8.0  # Simple average

    def test_weighted_average_mismatched_lengths(self, evaluator):
        """Test weighted average with mismatched lengths."""
        scores = [7.0, 8.0]
        weights = [0.5]

        result = evaluator._weighted_average(scores, weights)

        # Should fall back to simple average
        assert result == 7.5

    def test_majority_vote_calculation(self, evaluator):
        """Test majority vote calculation."""
        scores = [7.5, 8.0, 7.2, 7.8]  # All in high range

        result = evaluator._majority_vote(scores)

        assert 7.0 <= result <= 10.0

    def test_calculate_confidence_high_agreement(self, evaluator):
        """Test confidence calculation with high score agreement."""
        scores = [7.0, 7.1, 7.2]
        quality_scores = [0.9, 0.9, 0.9]

        confidence = evaluator._calculate_confidence(scores, quality_scores)

        assert 0.0 <= confidence <= 1.0  # Valid confidence range
        assert confidence > 0.4  # High agreement with few branches = moderate confidence

    def test_calculate_confidence_low_agreement(self, evaluator):
        """Test confidence calculation with low score agreement."""
        scores = [2.0, 5.0, 9.0]
        quality_scores = [0.6, 0.6, 0.6]

        confidence = evaluator._calculate_confidence(scores, quality_scores)

        assert confidence < 0.7  # Low agreement = lower confidence

    def test_calculate_confidence_single_score(self, evaluator):
        """Test confidence with single score."""
        scores = [7.0]
        quality_scores = [0.9]

        confidence = evaluator._calculate_confidence(scores, quality_scores)

        assert 0.0 <= confidence <= 1.0

    def test_min_branches_warning(self, evaluator):
        """Test warning for too few branches."""
        branches = [{"evaluation": {"score": 7.0}, "quality_score": 0.8}]

        consensus = evaluator.consensus_scoring(branches)

        # Should still work but with low confidence
        assert consensus["num_branches"] == 1
        assert consensus["confidence"] < 0.8
