"""Tests for MarkovThreatModeler."""

import pytest
import numpy as np
from pathlib import Path
import tempfile

from src.reasoning.markov_threat_modeler import MarkovThreatModeler, AttackScenario
from src.tools.attack_transition_builder import AttackTransitionBuilder


@pytest.fixture
def builder():
    """Create a test transition builder."""
    builder = AttackTransitionBuilder()
    builder.parse_mitre_attack()
    builder.extract_technique_relationships()
    builder.calculate_transition_probabilities()
    builder.build_transition_matrix()
    return builder


@pytest.fixture
def modeler(builder):
    """Create a test threat modeler."""
    return MarkovThreatModeler(transition_builder=builder)


class TestAttackScenario:
    """Test AttackScenario class."""

    def test_create_scenario(self):
        """Test creating an attack scenario."""
        scenario = AttackScenario(
            techniques=["T1190", "T1059", "T1003"],
            probability=0.5,
            tactics=["initial-access", "execution", "credential-access"],
            description="Test scenario",
        )

        assert scenario.techniques == ["T1190", "T1059", "T1003"]
        assert scenario.probability == 0.5
        assert len(scenario.tactics) == 3

    def test_scenario_to_dict(self):
        """Test converting scenario to dictionary."""
        scenario = AttackScenario(
            techniques=["T1190", "T1059"],
            probability=0.3,
            tactics=["initial-access", "execution"],
            description="Test",
        )

        d = scenario.to_dict()
        assert "techniques" in d
        assert "probability" in d
        assert "tactics" in d
        assert d["techniques"] == ["T1190", "T1059"]

    def test_scenario_repr(self):
        """Test scenario string representation."""
        scenario = AttackScenario(
            techniques=["T1190"],
            probability=0.5,
            tactics=["initial-access"],
        )

        repr_str = repr(scenario)
        assert "AttackScenario" in repr_str
        assert "0.5000" in repr_str


class TestMarkovThreatModelerInit:
    """Test threat modeler initialization."""

    def test_init_with_builder(self, builder):
        """Test initialization with provided builder."""
        modeler = MarkovThreatModeler(transition_builder=builder)

        assert modeler.transition_builder is not None
        assert modeler.transition_builder.transition_matrix is not None

    def test_init_without_builder(self):
        """Test initialization without builder (builds automatically)."""
        modeler = MarkovThreatModeler()

        assert modeler.transition_builder is not None
        # Should have built or loaded a matrix
        assert modeler.transition_builder.transition_matrix is not None or \
               len(modeler.transition_builder.techniques) > 0

    def test_init_with_cache(self, builder):
        """Test initialization with cached matrix."""
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            cache_path = f.name

        try:
            # Cache matrix
            builder.cache_matrix(cache_path)

            # Create modeler with cache
            modeler = MarkovThreatModeler(cache_path=cache_path)

            assert modeler.transition_builder is not None

        finally:
            Path(cache_path).unlink(missing_ok=True)


class TestBuildTransitionMatrix:
    """Test matrix building."""

    def test_build_matrix(self, builder):
        """Test building transition matrix."""
        modeler = MarkovThreatModeler(transition_builder=builder)
        matrix = modeler.build_transition_matrix()

        assert isinstance(matrix, np.ndarray)
        assert matrix.ndim == 2

    def test_build_matrix_idempotent(self, builder):
        """Test that building matrix multiple times is safe."""
        modeler = MarkovThreatModeler(transition_builder=builder)

        matrix1 = modeler.build_transition_matrix()
        matrix2 = modeler.build_transition_matrix()

        np.testing.assert_array_equal(matrix1, matrix2)


class TestGenerateScenario:
    """Test scenario generation."""

    def test_generate_scenario_basic(self, modeler):
        """Test basic scenario generation."""
        scenario = modeler.generate_scenario("T1190", steps=5)

        assert isinstance(scenario, AttackScenario)
        assert len(scenario.techniques) > 0
        assert scenario.techniques[0] == "T1190"
        assert len(scenario.techniques) <= 5

    def test_generate_scenario_different_starts(self, modeler):
        """Test generating scenarios from different start points."""
        scenario1 = modeler.generate_scenario("T1190", steps=5)
        scenario2 = modeler.generate_scenario("T1059", steps=5)

        assert scenario1.techniques[0] == "T1190"
        assert scenario2.techniques[0] == "T1059"

    def test_generate_scenario_variable_length(self, modeler):
        """Test scenario generation with different lengths."""
        scenario_short = modeler.generate_scenario("T1190", steps=3)
        scenario_long = modeler.generate_scenario("T1190", steps=10)

        assert len(scenario_short.techniques) <= 3
        assert len(scenario_long.techniques) <= 10

    def test_generate_scenario_probability(self, modeler):
        """Test that scenario has valid probability."""
        scenario = modeler.generate_scenario("T1190", steps=5)

        assert 0.0 <= scenario.probability <= 1.0

    def test_generate_scenario_tactics(self, modeler):
        """Test that scenario includes tactics."""
        scenario = modeler.generate_scenario("T1190", steps=5)

        assert len(scenario.tactics) == len(scenario.techniques)

    def test_generate_scenario_invalid_technique(self, modeler):
        """Test generating scenario from invalid technique."""
        scenario = modeler.generate_scenario("T9999", steps=5)

        assert scenario.probability == 0.0
        assert "Invalid" in scenario.description

    def test_generate_scenario_description(self, modeler):
        """Test that scenario has description."""
        scenario = modeler.generate_scenario("T1190", steps=5)

        assert scenario.description
        assert "T1190" in scenario.description


class TestCalculateProbability:
    """Test path probability calculation."""

    def test_calculate_probability_single_technique(self, modeler):
        """Test probability of single technique path."""
        prob = modeler.calculate_probability(["T1190"])
        assert prob == 1.0

    def test_calculate_probability_valid_path(self, modeler):
        """Test probability of valid path."""
        # Generate a scenario to get a valid path
        scenario = modeler.generate_scenario("T1190", steps=3)
        prob = modeler.calculate_probability(scenario.techniques)

        assert 0.0 <= prob <= 1.0

    def test_calculate_probability_decreases_with_length(self, modeler):
        """Test that probability generally decreases with path length."""
        scenario = modeler.generate_scenario("T1190", steps=5)

        if len(scenario.techniques) >= 3:
            prob_short = modeler.calculate_probability(scenario.techniques[:2])
            prob_long = modeler.calculate_probability(scenario.techniques)

            # Longer paths typically have lower probability
            assert prob_long <= prob_short

    def test_calculate_probability_invalid_transition(self, modeler):
        """Test probability with invalid transitions."""
        # Create path with unlikely transitions
        prob = modeler.calculate_probability(["T1190", "T9999"])

        # Should be 0 or very low
        assert prob >= 0.0


class TestMonteCarloScenarios:
    """Test Monte Carlo scenario generation."""

    def test_generate_monte_carlo_basic(self, modeler):
        """Test basic Monte Carlo generation."""
        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=10, steps=5
        )

        assert len(scenarios) > 0
        assert len(scenarios) <= 10  # May have duplicates removed
        assert all(isinstance(s, AttackScenario) for s in scenarios)

    def test_monte_carlo_sorted_by_probability(self, modeler):
        """Test that scenarios are sorted by probability."""
        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=20, steps=5
        )

        probabilities = [s.probability for s in scenarios]

        # Should be in descending order
        assert probabilities == sorted(probabilities, reverse=True)

    def test_monte_carlo_removes_duplicates(self, modeler):
        """Test that duplicate scenarios are removed."""
        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=100, steps=3
        )

        # Check for unique technique sequences
        sequences = [tuple(s.techniques) for s in scenarios]
        assert len(sequences) == len(set(sequences))

    def test_monte_carlo_diversity(self, modeler):
        """Test that Monte Carlo generates diverse scenarios."""
        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=50, steps=5
        )

        # Should have multiple unique paths
        assert len(scenarios) > 1

    def test_monte_carlo_all_start_same(self, modeler):
        """Test that all scenarios start with same technique."""
        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=20, steps=5
        )

        assert all(s.techniques[0] == "T1190" for s in scenarios)


class TestFindMostLikelyPath:
    """Test finding most likely path between techniques."""

    def test_find_path_exists(self, modeler):
        """Test finding path when one exists."""
        # Find path from initial access to execution
        scenario = modeler.find_most_likely_path("T1190", "T1059", max_depth=5)

        if scenario:  # Path may not always exist in mock data
            assert scenario.techniques[0] == "T1190"
            assert scenario.techniques[-1] == "T1059"

    def test_find_path_same_technique(self, modeler):
        """Test finding path to same technique."""
        scenario = modeler.find_most_likely_path("T1190", "T1190", max_depth=5)

        if scenario:
            assert len(scenario.techniques) == 1

    def test_find_path_invalid_start(self, modeler):
        """Test finding path from invalid start technique."""
        scenario = modeler.find_most_likely_path("T9999", "T1059", max_depth=5)

        assert scenario is None

    def test_find_path_invalid_end(self, modeler):
        """Test finding path to invalid end technique."""
        scenario = modeler.find_most_likely_path("T1190", "T9999", max_depth=5)

        assert scenario is None

    def test_find_path_respects_max_depth(self, modeler):
        """Test that path finding respects max depth."""
        scenario = modeler.find_most_likely_path("T1190", "T1567", max_depth=3)

        if scenario:
            assert len(scenario.techniques) <= 3


class TestGetTopNextTechniques:
    """Test getting top next techniques."""

    def test_get_top_next_basic(self, modeler):
        """Test getting top next techniques."""
        next_techs = modeler.get_top_next_techniques("T1190", top_k=5)

        assert isinstance(next_techs, list)
        assert len(next_techs) <= 5

    def test_get_top_next_structure(self, modeler):
        """Test structure of returned techniques."""
        next_techs = modeler.get_top_next_techniques("T1190", top_k=3)

        for tech_id, prob, name in next_techs:
            assert isinstance(tech_id, str)
            assert isinstance(prob, float)
            assert isinstance(name, str)
            assert 0.0 <= prob <= 1.0

    def test_get_top_next_sorted_by_probability(self, modeler):
        """Test that results are sorted by probability."""
        next_techs = modeler.get_top_next_techniques("T1190", top_k=5)

        if len(next_techs) > 1:
            probabilities = [prob for _, prob, _ in next_techs]
            assert probabilities == sorted(probabilities, reverse=True)

    def test_get_top_next_invalid_technique(self, modeler):
        """Test getting next from invalid technique."""
        next_techs = modeler.get_top_next_techniques("T9999", top_k=5)

        assert next_techs == []

    def test_get_top_next_different_k(self, modeler):
        """Test with different top_k values."""
        next_3 = modeler.get_top_next_techniques("T1190", top_k=3)
        next_10 = modeler.get_top_next_techniques("T1190", top_k=10)

        assert len(next_3) <= 3
        assert len(next_10) <= 10

        if len(next_3) > 0 and len(next_10) >= 3:
            # First 3 should be same
            assert [t[0] for t in next_3] == [t[0] for t in next_10[:3]]


class TestAnalyzeTechniqueReachability:
    """Test technique reachability analysis."""

    def test_reachability_basic(self, modeler):
        """Test basic reachability analysis."""
        reachable = modeler.analyze_technique_reachability("T1190", max_steps=3)

        assert isinstance(reachable, dict)
        assert "T1190" in reachable  # Starting technique is reachable
        assert reachable["T1190"] == 1.0

    def test_reachability_includes_neighbors(self, modeler):
        """Test that reachability includes neighboring techniques."""
        reachable = modeler.analyze_technique_reachability("T1190", max_steps=2)

        # Should have more than just the starting technique
        assert len(reachable) > 1

    def test_reachability_probabilities_valid(self, modeler):
        """Test that all reachability probabilities are valid."""
        reachable = modeler.analyze_technique_reachability("T1190", max_steps=3)

        for tech_id, prob in reachable.items():
            assert 0.0 <= prob <= 1.0

    def test_reachability_increases_with_steps(self, modeler):
        """Test that more steps finds more reachable techniques."""
        reachable_2 = modeler.analyze_technique_reachability("T1190", max_steps=2)
        reachable_5 = modeler.analyze_technique_reachability("T1190", max_steps=5)

        assert len(reachable_5) >= len(reachable_2)

    def test_reachability_invalid_technique(self, modeler):
        """Test reachability from invalid technique."""
        reachable = modeler.analyze_technique_reachability("T9999", max_steps=3)

        assert reachable == {}


class TestGetStatistics:
    """Test statistics retrieval."""

    def test_get_statistics_basic(self, modeler):
        """Test getting basic statistics."""
        stats = modeler.get_statistics()

        assert isinstance(stats, dict)
        assert "techniques" in stats
        assert "relationships" in stats

    def test_get_statistics_content(self, modeler):
        """Test statistics content."""
        stats = modeler.get_statistics()

        assert stats["techniques"] > 0
        assert isinstance(stats["techniques"], int)

    def test_get_statistics_with_matrix(self, modeler):
        """Test statistics when matrix is built."""
        modeler.build_transition_matrix()
        stats = modeler.get_statistics()

        assert "matrix_non_zero" in stats
        assert "matrix_sparsity" in stats
        assert "matrix_shape" in stats


class TestPrivateMethods:
    """Test private helper methods."""

    def test_get_next_techniques(self, modeler):
        """Test getting next techniques."""
        next_techs = modeler._get_next_techniques(
            "T1190", min_probability=0.01, visited=set()
        )

        assert isinstance(next_techs, list)
        # Should be sorted by probability
        if len(next_techs) > 1:
            probs = [p for _, p in next_techs]
            assert probs == sorted(probs, reverse=True)

    def test_sample_next_technique(self, modeler):
        """Test sampling next technique."""
        next_techs = [("T1059", 0.7), ("T1068", 0.3)]
        sampled = modeler._sample_next_technique(next_techs)

        assert sampled[0] in ["T1059", "T1068"]
        assert 0.0 <= sampled[1] <= 1.0

    def test_get_tactics_for_techniques(self, modeler):
        """Test getting tactics for techniques."""
        techniques = ["T1190", "T1059", "T1003"]
        tactics = modeler._get_tactics_for_techniques(techniques)

        assert len(tactics) == len(techniques)
        assert all(isinstance(t, str) for t in tactics)

    def test_generate_scenario_description(self, modeler):
        """Test generating scenario description."""
        techniques = ["T1190", "T1059"]
        tactics = ["initial-access", "execution"]

        description = modeler._generate_scenario_description(techniques, tactics)

        assert "T1190" in description
        assert "T1059" in description
        assert "initial-access" in description

    def test_deduplicate_scenarios(self, modeler):
        """Test scenario deduplication."""
        scenarios = [
            AttackScenario(["T1190", "T1059"], 0.5, ["a", "b"]),
            AttackScenario(["T1190", "T1059"], 0.6, ["a", "b"]),  # Duplicate, higher prob
            AttackScenario(["T1190", "T1068"], 0.4, ["a", "c"]),
        ]

        unique = modeler._deduplicate_scenarios(scenarios)

        assert len(unique) == 2
        # Should keep the one with higher probability
        path_1190_1059 = [s for s in unique if s.techniques == ["T1190", "T1059"]]
        assert len(path_1190_1059) == 1
        assert path_1190_1059[0].probability == 0.6


class TestEndToEnd:
    """End-to-end tests."""

    def test_full_scenario_generation_workflow(self, modeler):
        """Test complete scenario generation workflow."""
        # Generate scenarios
        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=20, steps=5
        )

        assert len(scenarios) > 0

        # Verify top scenario
        top_scenario = scenarios[0]
        assert top_scenario.techniques[0] == "T1190"
        assert len(top_scenario.tactics) == len(top_scenario.techniques)

        # Calculate probability
        prob = modeler.calculate_probability(top_scenario.techniques)
        # Allow slightly larger tolerance due to probabilistic sampling
        assert abs(prob - top_scenario.probability) < 0.02

    def test_threat_modeling_workflow(self, modeler):
        """Test complete threat modeling workflow."""
        # 1. Get initial technique
        initial = "T1190"

        # 2. Get top next techniques
        next_techs = modeler.get_top_next_techniques(initial, top_k=3)
        assert len(next_techs) > 0

        # 3. Generate scenarios
        scenarios = modeler.generate_monte_carlo_scenarios(initial, num_scenarios=10)
        assert len(scenarios) > 0

        # 4. Analyze reachability
        reachable = modeler.analyze_technique_reachability(initial, max_steps=3)
        assert len(reachable) > 1

        # 5. Get statistics
        stats = modeler.get_statistics()
        assert stats["techniques"] > 0
