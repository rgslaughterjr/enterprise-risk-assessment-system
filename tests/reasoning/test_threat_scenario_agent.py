"""Tests for ThreatScenarioAgent."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from src.agents.threat_scenario_agent import (
    ThreatScenarioAgent,
    generate_attack_scenario,
    generate_multiple_scenarios,
    find_attack_path,
    get_next_likely_techniques,
    analyze_technique_reachability,
    calculate_path_probability,
    get_modeler_statistics,
    _assess_probability,
)


@pytest.fixture
def mock_modeler():
    """Create a mock threat modeler."""
    from src.reasoning.markov_threat_modeler import MarkovThreatModeler, AttackScenario
    from src.tools.attack_transition_builder import AttackTransitionBuilder

    builder = AttackTransitionBuilder()
    builder.parse_mitre_attack()
    builder.extract_technique_relationships()
    builder.calculate_transition_probabilities()
    builder.build_transition_matrix()

    return MarkovThreatModeler(transition_builder=builder)


class TestToolFunctions:
    """Test individual tool functions."""

    def test_generate_attack_scenario_tool(self, mock_modeler):
        """Test generate_attack_scenario tool."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = generate_attack_scenario.invoke(
                {"initial_technique": "T1190", "steps": 5}
            )

            assert "techniques" in result
            assert "probability" in result
            assert "tactics" in result
            assert result["techniques"][0] == "T1190"

    def test_generate_attack_scenario_invalid_technique(self, mock_modeler):
        """Test generating scenario with invalid technique."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = generate_attack_scenario.invoke(
                {"initial_technique": "T9999", "steps": 5}
            )

            assert result["probability"] == 0.0

    def test_generate_multiple_scenarios_tool(self, mock_modeler):
        """Test generate_multiple_scenarios tool."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = generate_multiple_scenarios.invoke(
                {"initial_technique": "T1190", "num_scenarios": 10, "steps": 5}
            )

            assert "num_generated" in result
            assert "top_scenarios" in result
            assert "summary" in result
            assert isinstance(result["top_scenarios"], list)

    def test_find_attack_path_tool(self, mock_modeler):
        """Test find_attack_path tool."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = find_attack_path.invoke(
                {"start_technique": "T1190", "end_technique": "T1059", "max_steps": 5}
            )

            assert "found" in result
            if result["found"]:
                assert "techniques" in result
                assert result["techniques"][0] == "T1190"
                assert result["techniques"][-1] == "T1059"

    def test_find_attack_path_not_found(self, mock_modeler):
        """Test finding path when none exists."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = find_attack_path.invoke(
                {"start_technique": "T1190", "end_technique": "T9999", "max_steps": 5}
            )

            assert result["found"] is False

    def test_get_next_likely_techniques_tool(self, mock_modeler):
        """Test get_next_likely_techniques tool."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = get_next_likely_techniques.invoke(
                {"current_technique": "T1190", "top_k": 5}
            )

            assert isinstance(result, list)
            if len(result) > 0:
                assert "technique_id" in result[0]
                assert "probability" in result[0]
                assert "name" in result[0]

    def test_analyze_technique_reachability_tool(self, mock_modeler):
        """Test analyze_technique_reachability tool."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = analyze_technique_reachability.invoke(
                {"technique": "T1190", "max_steps": 5}
            )

            assert "total_reachable" in result
            assert "high_probability" in result
            assert "top_10_reachable" in result

    def test_calculate_path_probability_tool(self, mock_modeler):
        """Test calculate_path_probability tool."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = calculate_path_probability.invoke(
                {"techniques": ["T1190", "T1059"]}
            )

            assert "path" in result
            assert "probability" in result
            assert "assessment" in result
            assert result["num_steps"] == 2

    def test_get_modeler_statistics_tool(self, mock_modeler):
        """Test get_modeler_statistics tool."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            result = get_modeler_statistics.invoke({})

            assert "techniques" in result
            assert isinstance(result["techniques"], int)


class TestAssessProbability:
    """Test probability assessment function."""

    def test_assess_very_likely(self):
        """Test very likely assessment."""
        assessment = _assess_probability(0.2)
        assert "Very likely" in assessment

    def test_assess_likely(self):
        """Test likely assessment."""
        assessment = _assess_probability(0.05)
        assert "Likely" in assessment

    def test_assess_possible(self):
        """Test possible assessment."""
        assessment = _assess_probability(0.005)
        assert "Possible" in assessment

    def test_assess_unlikely(self):
        """Test unlikely assessment."""
        assessment = _assess_probability(0.0001)
        assert "Unlikely" in assessment


class TestThreatScenarioAgentInit:
    """Test agent initialization."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_init_basic(self, mock_llm):
        """Test basic agent initialization."""
        agent = ThreatScenarioAgent()

        assert agent is not None
        assert len(agent.tools) == 7
        assert agent.model_name == "claude-3-5-sonnet-20241022"
        assert agent.temperature == 0

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_init_custom_model(self, mock_llm):
        """Test initialization with custom model."""
        agent = ThreatScenarioAgent(
            model="claude-3-opus-20240229",
            temperature=0.5
        )

        assert agent.model_name == "claude-3-opus-20240229"
        assert agent.temperature == 0.5

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_init_creates_executor(self, mock_llm):
        """Test that initialization creates executor."""
        agent = ThreatScenarioAgent()

        assert agent.executor is not None
        assert agent.agent is not None


class TestGenerateScenarios:
    """Test scenario generation methods."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_generate_scenarios_basic(self, mock_llm, mock_modeler):
        """Test basic scenario generation."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            agent = ThreatScenarioAgent()

            scenarios = agent.generate_scenarios(
                cve_id="CVE-2024-1234",
                initial_technique="T1190",
                num_scenarios=5
            )

            assert isinstance(scenarios, list)
            if len(scenarios) > 0:
                assert "cve_id" in scenarios[0]
                assert "techniques" in scenarios[0]
                assert "probability" in scenarios[0]

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_generate_scenarios_multiple(self, mock_llm, mock_modeler):
        """Test generating multiple scenarios."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            agent = ThreatScenarioAgent()

            scenarios = agent.generate_scenarios(
                cve_id="CVE-2024-1234",
                initial_technique="T1190",
                num_scenarios=10
            )

            assert len(scenarios) > 0

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_generate_scenarios_includes_cve(self, mock_llm, mock_modeler):
        """Test that scenarios include CVE ID."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            agent = ThreatScenarioAgent()

            scenarios = agent.generate_scenarios(
                cve_id="CVE-2024-1234",
                initial_technique="T1190",
                num_scenarios=5
            )

            if len(scenarios) > 0:
                assert scenarios[0]["cve_id"] == "CVE-2024-1234"


class TestRankByProbability:
    """Test ranking scenarios."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_rank_by_probability(self, mock_llm):
        """Test ranking scenarios by probability."""
        agent = ThreatScenarioAgent()

        scenarios = [
            {"probability": 0.3, "techniques": ["T1", "T2"]},
            {"probability": 0.7, "techniques": ["T1", "T3"]},
            {"probability": 0.1, "techniques": ["T1", "T4"]},
        ]

        ranked = agent.rank_by_probability(scenarios)

        assert ranked[0]["probability"] == 0.7
        assert ranked[1]["probability"] == 0.3
        assert ranked[2]["probability"] == 0.1

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_rank_empty_list(self, mock_llm):
        """Test ranking empty list."""
        agent = ThreatScenarioAgent()
        ranked = agent.rank_by_probability([])
        assert ranked == []


class TestIntegrateWithThreatAgent:
    """Test integration with threat agent."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_integrate_basic(self, mock_llm, mock_modeler):
        """Test basic integration."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            with patch("src.agents.threat_scenario_agent.get_mitre_client") as mock_mitre:
                # Mock MITRE client
                from src.models.schemas import MITRETechnique
                mock_technique = MITRETechnique(
                    technique_id="T1190",
                    name="Exploit Public-Facing Application",
                    description="Test",
                    tactics=["initial-access"],
                    platforms=["Windows", "Linux"]
                )
                mock_mitre.return_value.map_cve_to_techniques.return_value = [mock_technique]

                agent = ThreatScenarioAgent()

                result = agent.integrate_with_threat_agent(
                    cve_id="CVE-2024-1234",
                    cve_description="Remote code execution vulnerability"
                )

                assert "cve_id" in result
                assert result["cve_id"] == "CVE-2024-1234"
                assert "scenarios" in result

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_integrate_no_techniques_mapped(self, mock_llm):
        """Test integration when no techniques are mapped."""
        with patch("src.agents.threat_scenario_agent.get_mitre_client") as mock_mitre:
            mock_mitre.return_value.map_cve_to_techniques.return_value = []

            agent = ThreatScenarioAgent()

            result = agent.integrate_with_threat_agent(
                cve_id="CVE-2024-1234",
                cve_description="Some vulnerability"
            )

            assert result["scenarios"] == []
            assert "message" in result

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_integrate_returns_top_scenarios(self, mock_llm, mock_modeler):
        """Test that integration returns top scenarios."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            with patch("src.agents.threat_scenario_agent.get_mitre_client") as mock_mitre:
                from src.models.schemas import MITRETechnique
                mock_technique = MITRETechnique(
                    technique_id="T1190",
                    name="Test",
                    description="Test",
                    tactics=["initial-access"],
                    platforms=[]
                )
                mock_mitre.return_value.map_cve_to_techniques.return_value = [mock_technique]

                agent = ThreatScenarioAgent()

                result = agent.integrate_with_threat_agent(
                    cve_id="CVE-2024-1234",
                    cve_description="Test vulnerability"
                )

                # Should return top 5 scenarios
                if "scenarios" in result and len(result["scenarios"]) > 0:
                    assert len(result["scenarios"]) <= 5


class TestQueryMethod:
    """Test query method."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_query_returns_string(self, mock_llm):
        """Test that query returns a string."""
        # Mock the executor
        mock_executor = MagicMock()
        mock_executor.invoke.return_value = {"output": "Test response"}

        agent = ThreatScenarioAgent()
        agent.executor = mock_executor

        response = agent.query("Generate scenario from T1190")

        assert isinstance(response, str)
        assert response == "Test response"

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_query_handles_error(self, mock_llm):
        """Test that query handles errors gracefully."""
        mock_executor = MagicMock()
        mock_executor.invoke.side_effect = Exception("Test error")

        agent = ThreatScenarioAgent()
        agent.executor = mock_executor

        response = agent.query("Test query")

        assert "Error" in response

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_query_no_output(self, mock_llm):
        """Test query when no output is generated."""
        mock_executor = MagicMock()
        mock_executor.invoke.return_value = {}

        agent = ThreatScenarioAgent()
        agent.executor = mock_executor

        response = agent.query("Test query")

        assert "No response generated" in response


class TestToolIntegration:
    """Test tool integration with agent."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_agent_has_all_tools(self, mock_llm):
        """Test that agent has all expected tools."""
        agent = ThreatScenarioAgent()

        tool_names = [tool.name for tool in agent.tools]

        expected_tools = [
            "generate_attack_scenario",
            "generate_multiple_scenarios",
            "find_attack_path",
            "get_next_likely_techniques",
            "analyze_technique_reachability",
            "calculate_path_probability",
            "get_modeler_statistics",
        ]

        for expected in expected_tools:
            assert expected in tool_names

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_tools_are_callable(self, mock_llm):
        """Test that all tools have invoke method."""
        agent = ThreatScenarioAgent()

        for tool in agent.tools:
            assert hasattr(tool, 'invoke')


class TestPromptTemplate:
    """Test prompt template."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_prompt_includes_system_message(self, mock_llm):
        """Test that prompt includes system message."""
        agent = ThreatScenarioAgent()

        messages = agent.prompt.messages

        assert len(messages) > 0
        # Check that first message is a system message
        assert hasattr(messages[0], '__class__')
        assert 'System' in messages[0].__class__.__name__

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_prompt_includes_mitre_tactics(self, mock_llm):
        """Test that prompt includes MITRE tactics."""
        agent = ThreatScenarioAgent()

        # Get the system message prompt text
        system_message_prompt = agent.prompt.messages[0].prompt.template

        assert "Initial Access" in system_message_prompt
        assert "Execution" in system_message_prompt
        assert "Exfiltration" in system_message_prompt


class TestErrorHandling:
    """Test error handling."""

    def test_tool_error_handling_generate_scenario(self):
        """Test error handling in generate_attack_scenario."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler") as mock:
            mock.return_value.generate_scenario.side_effect = Exception("Test error")

            result = generate_attack_scenario.invoke(
                {"initial_technique": "T1190", "steps": 5}
            )

            assert "error" in result

    def test_tool_error_handling_multiple_scenarios(self):
        """Test error handling in generate_multiple_scenarios."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler") as mock:
            mock.return_value.generate_monte_carlo_scenarios.side_effect = Exception("Test error")

            result = generate_multiple_scenarios.invoke(
                {"initial_technique": "T1190", "num_scenarios": 10}
            )

            assert "error" in result


class TestEndToEnd:
    """End-to-end tests."""

    @patch("src.agents.threat_scenario_agent.ChatAnthropic")
    def test_complete_workflow(self, mock_llm, mock_modeler):
        """Test complete scenario generation workflow."""
        with patch("src.agents.threat_scenario_agent.get_threat_modeler", return_value=mock_modeler):
            with patch("src.agents.threat_scenario_agent.get_mitre_client") as mock_mitre:
                from src.models.schemas import MITRETechnique

                mock_technique = MITRETechnique(
                    technique_id="T1190",
                    name="Exploit Public-Facing Application",
                    description="Test",
                    tactics=["initial-access"],
                    platforms=["Windows"]
                )
                mock_mitre.return_value.map_cve_to_techniques.return_value = [mock_technique]

                agent = ThreatScenarioAgent()

                # 1. Integrate with threat agent
                result = agent.integrate_with_threat_agent(
                    cve_id="CVE-2024-1234",
                    cve_description="Remote code execution"
                )

                assert "cve_id" in result

                # 2. Generate scenarios directly
                scenarios = agent.generate_scenarios(
                    cve_id="CVE-2024-1234",
                    initial_technique="T1190",
                    num_scenarios=5
                )

                assert isinstance(scenarios, list)

                # 3. Rank scenarios
                ranked = agent.rank_by_probability(scenarios)
                assert isinstance(ranked, list)
