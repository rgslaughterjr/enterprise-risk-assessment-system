"""Tests for Tree of Thought Branch Generator."""

import pytest
from src.reasoning.branch_generator import (
    BranchGenerator,
    EvaluationStrategy,
)


class TestBranchGenerator:
    """Test suite for BranchGenerator."""

    @pytest.fixture
    def generator(self):
        """Create branch generator instance."""
        return BranchGenerator()

    @pytest.fixture
    def sample_risk(self):
        """Create sample risk for testing."""
        return {
            "id": "RISK-001",
            "title": "SQL Injection Vulnerability",
            "description": "SQL injection in login form",
            "risk_level": "High",
            "cve_ids": ["CVE-2024-1234"],
            "affected_assets": ["Web Application"],
        }

    def test_init_default(self):
        """Test generator initialization with defaults."""
        gen = BranchGenerator()

        assert len(gen.default_strategies) == 5
        assert EvaluationStrategy.NIST_AI_RMF.value in gen.default_strategies
        assert EvaluationStrategy.OCTAVE.value in gen.default_strategies
        assert gen.enable_randomization is False

    def test_init_custom_strategies(self):
        """Test generator initialization with custom strategies."""
        strategies = ["nist_ai_rmf", "octave"]
        gen = BranchGenerator(default_strategies=strategies)

        assert len(gen.default_strategies) == 2
        assert gen.default_strategies == strategies

    def test_init_with_randomization(self):
        """Test generator initialization with randomization enabled."""
        gen = BranchGenerator(enable_randomization=True)

        assert gen.enable_randomization is True

    def test_generate_branches_default_count(self, generator, sample_risk):
        """Test generating default number of branches."""
        branches = generator.generate_branches(sample_risk)

        assert len(branches) == 5
        assert all(isinstance(b, dict) for b in branches)

    def test_generate_branches_custom_count(self, generator, sample_risk):
        """Test generating custom number of branches."""
        branches = generator.generate_branches(sample_risk, num_branches=3)

        assert len(branches) == 3

    def test_generate_branches_more_than_strategies(self, generator, sample_risk):
        """Test generating more branches than available strategies."""
        branches = generator.generate_branches(sample_risk, num_branches=8)

        assert len(branches) == 8
        # Should duplicate some strategies

    def test_branch_structure(self, generator, sample_risk):
        """Test that generated branches have correct structure."""
        branches = generator.generate_branches(sample_risk, num_branches=1)
        branch = branches[0]

        assert "branch_id" in branch
        assert "risk_id" in branch
        assert "risk_title" in branch
        assert "risk_description" in branch
        assert "strategy" in branch
        assert "branch_index" in branch
        assert "created_at" in branch
        assert "parameters" in branch
        assert "status" in branch
        assert "evaluation" in branch
        assert "quality_score" in branch

    def test_branch_ids_unique(self, generator, sample_risk):
        """Test that branch IDs are unique."""
        branches = generator.generate_branches(sample_risk, num_branches=5)
        branch_ids = [b["branch_id"] for b in branches]

        assert len(branch_ids) == len(set(branch_ids))

    def test_branch_risk_metadata(self, generator, sample_risk):
        """Test that branches contain risk metadata."""
        branches = generator.generate_branches(sample_risk, num_branches=1)
        branch = branches[0]

        assert branch["risk_id"] == sample_risk["id"]
        assert branch["risk_title"] == sample_risk["title"]
        assert branch["risk_description"] == sample_risk["description"]

    def test_branch_initial_status(self, generator, sample_risk):
        """Test that branches have correct initial status."""
        branches = generator.generate_branches(sample_risk)

        for branch in branches:
            assert branch["status"] == "pending"
            assert branch["evaluation"] is None
            assert branch["quality_score"] is None

    def test_nist_ai_rmf_parameters(self, generator, sample_risk):
        """Test NIST AI RMF strategy parameters."""
        strategies = [EvaluationStrategy.NIST_AI_RMF.value]
        branches = generator.generate_branches(
            sample_risk, strategies=strategies, num_branches=1
        )
        branch = branches[0]
        params = branch["parameters"]

        assert branch["strategy"] == EvaluationStrategy.NIST_AI_RMF.value
        assert "functions" in params
        assert params["functions"] == ["GOVERN", "MAP", "MEASURE", "MANAGE"]
        assert params["consider_ai_context"] is True

    def test_octave_parameters(self, generator, sample_risk):
        """Test OCTAVE strategy parameters."""
        strategies = [EvaluationStrategy.OCTAVE.value]
        branches = generator.generate_branches(
            sample_risk, strategies=strategies, num_branches=1
        )
        branch = branches[0]
        params = branch["parameters"]

        assert branch["strategy"] == EvaluationStrategy.OCTAVE.value
        assert "phases" in params
        assert params["organizational_impact"] is True
        assert "asset_criticality" in params

    def test_iso31000_parameters(self, generator, sample_risk):
        """Test ISO 31000 strategy parameters."""
        strategies = [EvaluationStrategy.ISO_31000.value]
        branches = generator.generate_branches(
            sample_risk, strategies=strategies, num_branches=1
        )
        branch = branches[0]
        params = branch["parameters"]

        assert branch["strategy"] == EvaluationStrategy.ISO_31000.value
        assert params["likelihood_scale"] == 5
        assert params["consequence_scale"] == 5
        assert params["risk_matrix"] == "5x5"

    def test_fair_parameters(self, generator, sample_risk):
        """Test FAIR strategy parameters."""
        strategies = [EvaluationStrategy.FAIR.value]
        branches = generator.generate_branches(
            sample_risk, strategies=strategies, num_branches=1
        )
        branch = branches[0]
        params = branch["parameters"]

        assert branch["strategy"] == EvaluationStrategy.FAIR.value
        assert params["loss_magnitude"] is True
        assert params["threat_event_frequency"] is True

    def test_quantitative_parameters(self, generator, sample_risk):
        """Test Quantitative strategy parameters."""
        strategies = [EvaluationStrategy.QUANTITATIVE.value]
        branches = generator.generate_branches(
            sample_risk, strategies=strategies, num_branches=1
        )
        branch = branches[0]
        params = branch["parameters"]

        assert branch["strategy"] == EvaluationStrategy.QUANTITATIVE.value
        assert "probability_distribution" in params
        assert "impact_range" in params

    def test_base_parameters_in_all_strategies(self, generator, sample_risk):
        """Test that all strategies include base parameters."""
        branches = generator.generate_branches(sample_risk, num_branches=5)

        for branch in branches:
            params = branch["parameters"]
            assert "risk_level" in params
            assert "cve_ids" in params
            assert "affected_assets" in params

    def test_randomization_disabled_by_default(self, generator, sample_risk):
        """Test that randomization is disabled by default."""
        branches = generator.generate_branches(sample_risk, num_branches=1)
        params = branches[0]["parameters"]

        assert "random_seed" not in params
        assert "sampling_variance" not in params

    def test_randomization_enabled(self, sample_risk):
        """Test randomization when enabled."""
        gen = BranchGenerator(enable_randomization=True)
        branches = gen.generate_branches(sample_risk, num_branches=1)
        params = branches[0]["parameters"]

        assert "random_seed" in params
        assert "sampling_variance" in params
        assert isinstance(params["random_seed"], int)
        assert isinstance(params["sampling_variance"], float)

    def test_generate_comparative_branches(self, generator, sample_risk):
        """Test generating comparative branches with baseline."""
        baseline_score = 7.5
        branches = generator.generate_comparative_branches(
            sample_risk, baseline_score=baseline_score
        )

        assert len(branches) == 5
        for branch in branches:
            assert branch["baseline_score"] == baseline_score
            assert branch["comparison_enabled"] is True

    def test_generate_comparative_branches_no_baseline(self, generator, sample_risk):
        """Test generating comparative branches without baseline."""
        branches = generator.generate_comparative_branches(sample_risk)

        for branch in branches:
            assert branch["baseline_score"] is None
            assert branch["comparison_enabled"] is False

    def test_generate_weighted_branches_default(self, generator, sample_risk):
        """Test generating weighted branches with default weights."""
        branches = generator.generate_weighted_branches(sample_risk)

        assert len(branches) > 0
        total_weight = sum(b["weight"] for b in branches)
        assert abs(total_weight - 1.0) < 0.01  # Should sum to 1

    def test_generate_weighted_branches_custom(self, generator, sample_risk):
        """Test generating weighted branches with custom weights."""
        weights = {
            "nist_ai_rmf": 0.4,
            "octave": 0.3,
            "iso31000": 0.3,
        }
        branches = generator.generate_weighted_branches(sample_risk, weights)

        assert len(branches) == 3

        # Check normalized weights
        total_weight = sum(b["weight"] for b in branches)
        assert abs(total_weight - 1.0) < 0.01

    def test_get_strategy_info_nist(self, generator):
        """Test getting NIST AI RMF strategy info."""
        info = generator.get_strategy_info(EvaluationStrategy.NIST_AI_RMF.value)

        assert info["name"] == "NIST AI Risk Management Framework"
        assert info["version"] == "1.0"
        assert info["focus"] == "AI-specific risks and governance"
        assert info["functions"] == 4

    def test_get_strategy_info_octave(self, generator):
        """Test getting OCTAVE strategy info."""
        info = generator.get_strategy_info(EvaluationStrategy.OCTAVE.value)

        assert info["name"] == "OCTAVE Allegro"
        assert info["phases"] == 3

    def test_get_strategy_info_unknown(self, generator):
        """Test getting info for unknown strategy."""
        info = generator.get_strategy_info("unknown_strategy")

        assert info["name"] == "Unknown"
        assert info["version"] == "N/A"

    def test_get_supported_strategies(self, generator):
        """Test getting list of supported strategies."""
        strategies = generator.get_supported_strategies()

        assert len(strategies) == 5
        assert EvaluationStrategy.NIST_AI_RMF.value in strategies
        assert EvaluationStrategy.OCTAVE.value in strategies
        assert EvaluationStrategy.ISO_31000.value in strategies
        assert EvaluationStrategy.FAIR.value in strategies
        assert EvaluationStrategy.QUANTITATIVE.value in strategies

    def test_expand_strategies(self, generator):
        """Test strategy expansion for more branches."""
        original = ["nist_ai_rmf", "octave"]
        expanded = generator._expand_strategies(original, target_count=5)

        assert len(expanded) == 5
        # Should contain duplicates
        assert expanded.count("nist_ai_rmf") >= 2

    def test_branch_index_sequential(self, generator, sample_risk):
        """Test that branch indices are sequential."""
        branches = generator.generate_branches(sample_risk, num_branches=5)
        indices = [b["branch_index"] for b in branches]

        assert indices == list(range(5))

    def test_ai_system_category_propagation(self, generator):
        """Test that AI system category is propagated to parameters."""
        risk = {
            "id": "RISK-AI-001",
            "title": "AI Model Bias",
            "ai_system_category": "high_risk",
        }

        strategies = [EvaluationStrategy.NIST_AI_RMF.value]
        branches = generator.generate_branches(risk, strategies=strategies, num_branches=1)
        params = branches[0]["parameters"]

        assert params.get("ai_system_category") == "high_risk"
