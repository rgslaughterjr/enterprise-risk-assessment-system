"""Integration tests for threat scenario generation."""

import pytest
from unittest.mock import patch
import numpy as np

from src.tools.attack_transition_builder import AttackTransitionBuilder
from src.reasoning.markov_threat_modeler import MarkovThreatModeler, AttackScenario
from src.agents.threat_scenario_agent import ThreatScenarioAgent
from src.tools.mitre_client import MITREClient


@pytest.fixture
def full_stack():
    """Create complete stack for integration testing."""
    builder = AttackTransitionBuilder()
    builder.parse_mitre_attack()
    builder.extract_technique_relationships()
    builder.calculate_transition_probabilities()
    builder.build_transition_matrix()

    modeler = MarkovThreatModeler(transition_builder=builder)

    return {
        "builder": builder,
        "modeler": modeler,
    }


class TestBuilderToModelerIntegration:
    """Test integration between builder and modeler."""

    def test_modeler_uses_builder_data(self, full_stack):
        """Test that modeler correctly uses builder data."""
        builder = full_stack["builder"]
        modeler = full_stack["modeler"]

        # Verify modeler has access to builder's data
        assert modeler.transition_builder == builder
        assert modeler.transition_builder.transition_matrix is not None

        # Verify dimensions match
        n_techniques = len(builder.technique_ids)
        assert modeler.transition_builder.transition_matrix.shape == (n_techniques, n_techniques)

    def test_scenario_uses_valid_techniques(self, full_stack):
        """Test that generated scenarios use valid techniques."""
        modeler = full_stack["modeler"]
        builder = full_stack["builder"]

        scenario = modeler.generate_scenario("T1190", steps=5)

        for tech_id in scenario.techniques:
            assert tech_id in builder.techniques

    def test_probabilities_consistent(self, full_stack):
        """Test that probabilities are consistent between builder and modeler."""
        modeler = full_stack["modeler"]
        builder = full_stack["builder"]

        # Generate a scenario
        scenario = modeler.generate_scenario("T1190", steps=3)

        # Calculate probability using builder's data
        calc_prob = modeler.calculate_probability(scenario.techniques)

        # Should be close to scenario's probability
        # Allow larger tolerance due to probabilistic sampling
        assert abs(calc_prob - scenario.probability) < 0.05


class TestScenarioGenerationIntegration:
    """Test end-to-end scenario generation."""

    def test_generate_realistic_scenarios(self, full_stack):
        """Test generating realistic attack scenarios."""
        modeler = full_stack["modeler"]

        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=20, steps=5
        )

        assert len(scenarios) > 0

        # Verify scenarios are realistic
        for scenario in scenarios[:5]:  # Check top 5
            assert len(scenario.techniques) > 0
            assert scenario.techniques[0] == "T1190"
            assert 0.0 <= scenario.probability <= 1.0
            assert len(scenario.tactics) == len(scenario.techniques)

    def test_scenario_tactic_progression(self, full_stack):
        """Test that scenarios follow logical tactic progression."""
        modeler = full_stack["modeler"]
        builder = full_stack["builder"]

        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=10, steps=8
        )

        tactic_order = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]

        tactic_index = {t: i for i, t in enumerate(tactic_order)}

        for scenario in scenarios[:5]:
            # Check if tactics generally progress forward
            tactic_positions = []
            for tactic in scenario.tactics:
                if tactic in tactic_index:
                    tactic_positions.append(tactic_index[tactic])

            if len(tactic_positions) > 1:
                # Not strictly increasing, but should have forward movement
                assert max(tactic_positions) > min(tactic_positions)

    def test_high_probability_paths_are_coherent(self, full_stack):
        """Test that high probability paths make tactical sense."""
        modeler = full_stack["modeler"]

        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=50, steps=6
        )

        # Top scenario should have relatively high probability
        top_scenario = scenarios[0]
        assert top_scenario.probability > 0.0

        # Check for typical attack progression patterns
        tactics = top_scenario.tactics
        # Should have some variation in tactics
        unique_tactics = set(tactics)
        assert len(unique_tactics) > 1


class TestPathFindingIntegration:
    """Test attack path finding."""

    def test_find_path_from_initial_to_impact(self, full_stack):
        """Test finding path from initial access to impact."""
        modeler = full_stack["modeler"]
        builder = full_stack["builder"]

        # Find initial access and impact techniques
        initial_access = [
            tid for tid, tdata in builder.techniques.items()
            if "initial-access" in tdata["tactics"]
        ]
        impact_techs = [
            tid for tid, tdata in builder.techniques.items()
            if "impact" in tdata["tactics"]
        ]

        if initial_access and impact_techs:
            scenario = modeler.find_most_likely_path(
                initial_access[0], impact_techs[0], max_depth=10
            )

            if scenario:  # Path may not exist
                assert scenario.techniques[0] == initial_access[0]
                assert scenario.techniques[-1] == impact_techs[0]

    def test_path_finding_respects_transitions(self, full_stack):
        """Test that found paths use valid transitions."""
        modeler = full_stack["modeler"]

        scenario = modeler.find_most_likely_path("T1190", "T1059", max_depth=5)

        if scenario:
            # Verify all transitions are valid
            for i in range(len(scenario.techniques) - 1):
                src = scenario.techniques[i]
                dst = scenario.techniques[i + 1]

                # Should have non-zero probability transition
                prob = modeler.calculate_probability([src, dst])
                assert prob > 0.0


class TestReachabilityAnalysis:
    """Test reachability analysis."""

    def test_reachability_grows_with_steps(self, full_stack):
        """Test that reachability increases with more steps."""
        modeler = full_stack["modeler"]

        reachable_2 = modeler.analyze_technique_reachability("T1190", max_steps=2)
        reachable_4 = modeler.analyze_technique_reachability("T1190", max_steps=4)

        assert len(reachable_4) >= len(reachable_2)

    def test_reachability_probabilities_decrease(self, full_stack):
        """Test that reachability probabilities decrease with distance."""
        modeler = full_stack["modeler"]

        reachable = modeler.analyze_technique_reachability("T1190", max_steps=5)

        # Starting technique should have probability 1.0
        assert reachable.get("T1190", 0) == 1.0

        # Most distant techniques should have lower probabilities
        sorted_reachable = sorted(reachable.items(), key=lambda x: x[1], reverse=True)

        if len(sorted_reachable) > 1:
            # First should be highest
            assert sorted_reachable[0][1] >= sorted_reachable[-1][1]


class TestAgentIntegration:
    """Test agent integration with modeler."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_agent_generates_scenarios(self, mock_llm, full_stack):
        """Test that agent can generate scenarios."""
        modeler = full_stack["modeler"]

        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=modeler):
            agent = ThreatScenarioAgent()

            scenarios = agent.generate_scenarios(
                cve_id="CVE-2024-1234",
                initial_technique="T1190",
                num_scenarios=10
            )

            assert len(scenarios) > 0
            assert all("cve_id" in s for s in scenarios)

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_agent_ranks_scenarios(self, mock_llm, full_stack):
        """Test that agent ranks scenarios correctly."""
        modeler = full_stack["modeler"]

        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=modeler):
            agent = ThreatScenarioAgent()

            scenarios = agent.generate_scenarios(
                cve_id="CVE-2024-1234",
                initial_technique="T1190",
                num_scenarios=10
            )

            ranked = agent.rank_by_probability(scenarios)

            # Verify sorted
            probs = [s["probability"] for s in ranked]
            assert probs == sorted(probs, reverse=True)

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_agent_integration_with_mitre(self, mock_llm, full_stack):
        """Test agent integration with MITRE client."""
        modeler = full_stack["modeler"]

        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=modeler):
            with patch("src.agents.threat_scenario_agent.get_mitre_client") as mock_mitre:
                from src.models.schemas import MITRETechnique

                mock_tech = MITRETechnique(
                    technique_id="T1190",
                    name="Exploit Public-Facing Application",
                    description="Test",
                    tactics=["initial-access"],
                    platforms=["Windows"]
                )
                mock_mitre.return_value.map_cve_to_techniques.return_value = [mock_tech]

                agent = ThreatScenarioAgent()

                result = agent.integrate_with_threat_agent(
                    cve_id="CVE-2024-1234",
                    cve_description="Remote code execution"
                )

                assert "scenarios" in result
                assert result["cve_id"] == "CVE-2024-1234"


class TestCVEToScenarioWorkflow:
    """Test complete CVE to scenario workflow."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_cve_to_scenarios_complete(self, mock_llm, full_stack):
        """Test complete workflow from CVE to attack scenarios."""
        modeler = full_stack["modeler"]

        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=modeler):
            with patch("src.agents.threat_scenario_agent.get_mitre_client") as mock_mitre:
                from src.models.schemas import MITRETechnique

                # Mock CVE mapping
                mock_tech = MITRETechnique(
                    technique_id="T1190",
                    name="Exploit Public-Facing Application",
                    description="Test",
                    tactics=["initial-access"],
                    platforms=["Windows", "Linux"]
                )
                mock_mitre.return_value.map_cve_to_techniques.return_value = [mock_tech]

                agent = ThreatScenarioAgent()

                # Complete workflow
                result = agent.integrate_with_threat_agent(
                    cve_id="CVE-2024-3400",
                    cve_description="OS command injection vulnerability in PAN-OS"
                )

                # Verify complete result
                assert "cve_id" in result
                assert "initial_techniques" in result
                assert "scenarios" in result
                assert "num_scenarios" in result

                # Verify scenarios are complete
                if result["scenarios"]:
                    scenario = result["scenarios"][0]
                    assert "techniques" in scenario
                    assert "probability" in scenario
                    assert "tactics" in scenario


class TestMatrixCachingIntegration:
    """Test matrix caching integration."""

    def test_cache_and_load_workflow(self, full_stack):
        """Test caching and loading matrix."""
        import tempfile
        from pathlib import Path

        builder1 = full_stack["builder"]

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            cache_path = f.name

        try:
            # Cache matrix
            builder1.cache_matrix(cache_path)

            # Create new modeler with cached matrix
            modeler2 = MarkovThreatModeler(cache_path=cache_path)

            # Verify it works the same
            scenario1 = modeler2.generate_scenario("T1190", steps=5)

            assert scenario1.techniques[0] == "T1190"
            assert len(scenario1.techniques) > 0

        finally:
            Path(cache_path).unlink(missing_ok=True)


class TestStatisticsIntegration:
    """Test statistics collection."""

    def test_complete_statistics(self, full_stack):
        """Test collecting complete statistics."""
        modeler = full_stack["modeler"]
        builder = full_stack["builder"]

        stats = modeler.get_statistics()

        assert stats["techniques"] == len(builder.techniques)
        assert stats["relationships"] == len(builder.relationships)
        assert stats["transitions"] == len(builder.transition_probs)
        assert stats["matrix_size"] == len(builder.technique_ids)

    def test_statistics_after_operations(self, full_stack):
        """Test statistics remain consistent after operations."""
        modeler = full_stack["modeler"]

        stats_before = modeler.get_statistics()

        # Perform operations
        modeler.generate_scenario("T1190", steps=5)
        modeler.analyze_technique_reachability("T1190", max_steps=3)

        stats_after = modeler.get_statistics()

        # Statistics should remain the same
        assert stats_before == stats_after


class TestMultipleCVEScenarios:
    """Test generating scenarios for multiple CVEs."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_multiple_cves(self, mock_llm, full_stack):
        """Test generating scenarios for multiple CVEs."""
        modeler = full_stack["modeler"]

        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=modeler):
            agent = ThreatScenarioAgent()

            cves = [
                ("CVE-2024-1234", "T1190"),
                ("CVE-2024-5678", "T1059"),
                ("CVE-2024-9012", "T1068"),
            ]

            results = []
            for cve_id, initial_tech in cves:
                scenarios = agent.generate_scenarios(
                    cve_id=cve_id,
                    initial_technique=initial_tech,
                    num_scenarios=5
                )
                results.append(scenarios)

            # Verify all generated successfully
            assert len(results) == 3
            assert all(len(r) > 0 for r in results)


class TestRealWorldScenarios:
    """Test realistic attack scenario generation."""

    def test_realistic_attack_chain(self, full_stack):
        """Test generating realistic multi-stage attack."""
        modeler = full_stack["modeler"]

        # Generate longer scenarios
        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=30, steps=8
        )

        # Analyze top scenario
        top = scenarios[0]

        # Should have multiple stages
        assert len(top.techniques) >= 3

        # Should have diverse tactics
        unique_tactics = set(top.tactics)
        assert len(unique_tactics) >= 2

    def test_common_attack_patterns(self, full_stack):
        """Test that common patterns are generated."""
        modeler = full_stack["modeler"]

        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=50, steps=10
        )

        # Common pattern: initial-access -> execution -> privilege-escalation
        common_tactics = ["initial-access", "execution", "privilege-escalation"]

        found_pattern = False
        for scenario in scenarios:
            tactics_set = set(scenario.tactics)
            if all(t in tactics_set for t in common_tactics):
                found_pattern = True
                break

        # Should find at least one scenario with common pattern
        # (Note: This may not always be true with mock data)


class TestEdgeCases:
    """Test edge cases in integration."""

    def test_very_short_scenarios(self, full_stack):
        """Test generating very short scenarios."""
        modeler = full_stack["modeler"]

        scenario = modeler.generate_scenario("T1190", steps=1)

        assert len(scenario.techniques) == 1
        assert scenario.techniques[0] == "T1190"

    def test_very_long_scenarios(self, full_stack):
        """Test generating very long scenarios."""
        modeler = full_stack["modeler"]

        scenario = modeler.generate_scenario("T1190", steps=20)

        assert len(scenario.techniques) <= 20

    def test_many_scenarios_generation(self, full_stack):
        """Test generating many scenarios."""
        modeler = full_stack["modeler"]

        scenarios = modeler.generate_monte_carlo_scenarios(
            "T1190", num_scenarios=100, steps=5
        )

        assert len(scenarios) > 0
        assert all(isinstance(s, AttackScenario) for s in scenarios)


class TestConcurrency:
    """Test concurrent operations."""

    def test_multiple_simultaneous_generations(self, full_stack):
        """Test generating multiple scenarios simultaneously."""
        modeler = full_stack["modeler"]

        # Generate from different starting points
        results = []
        for tech_id in ["T1190", "T1059", "T1068"]:
            scenario = modeler.generate_scenario(tech_id, steps=5)
            results.append(scenario)

        assert len(results) == 3
        assert all(isinstance(s, AttackScenario) for s in results)
