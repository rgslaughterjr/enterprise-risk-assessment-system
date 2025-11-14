"""Tests for Risk Scoring Agent."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.agents.risk_scoring_agent import (
    RiskScoringAgent,
    calculate_cve_severity_score,
    calculate_exploitation_score,
    calculate_asset_exposure_score,
    calculate_threat_capability_score,
    calculate_control_effectiveness_score,
    calculate_likelihood,
    calculate_impact,
)
from src.models.schemas import ExploitationStatus


class TestRiskCalculationFunctions:
    """Test risk calculation helper functions."""

    def test_calculate_cve_severity_score_critical(self):
        """Test CVE severity calculation for critical CVSS scores."""
        # Test CVSS 9.0-10.0 → score 5
        assert calculate_cve_severity_score(9.0) == 5
        assert calculate_cve_severity_score(9.5) == 5
        assert calculate_cve_severity_score(10.0) == 5

    def test_calculate_cve_severity_score_high(self):
        """Test CVE severity calculation for high CVSS scores."""
        # Test CVSS 7.0-8.9 → score 4
        assert calculate_cve_severity_score(7.0) == 4
        assert calculate_cve_severity_score(8.0) == 4
        assert calculate_cve_severity_score(8.9) == 4

    def test_calculate_cve_severity_score_medium(self):
        """Test CVE severity calculation for medium CVSS scores."""
        # Test CVSS 4.0-6.9 → score 3
        assert calculate_cve_severity_score(4.0) == 3
        assert calculate_cve_severity_score(5.5) == 3
        assert calculate_cve_severity_score(6.9) == 3

    def test_calculate_cve_severity_score_low(self):
        """Test CVE severity calculation for low CVSS scores."""
        # Test CVSS 0.1-3.9 → score 2
        assert calculate_cve_severity_score(0.1) == 2
        assert calculate_cve_severity_score(2.0) == 2
        assert calculate_cve_severity_score(3.9) == 2

    def test_calculate_cve_severity_score_none(self):
        """Test CVE severity calculation with None/missing CVSS."""
        # Test None → score 3 (default moderate)
        assert calculate_cve_severity_score(None) == 3

    def test_calculate_exploitation_score_cisa_kev(self):
        """Test exploitation score when CVE is in CISA KEV catalog."""
        # CISA KEV = highest priority → score 5
        status = ExploitationStatus(
            cve_id="CVE-2024-12345",
            in_cisa_kev=True,
            virustotal_detections=0,
            exploit_available=False,
            actively_exploited=False,
        )
        assert calculate_exploitation_score(status) == 5

    def test_calculate_exploitation_score_virustotal_high(self):
        """Test exploitation score with high VirusTotal detections."""
        # 10+ detections → score 4
        status = ExploitationStatus(
            cve_id="CVE-2024-12345",
            in_cisa_kev=False,
            virustotal_detections=15,
            exploit_available=True,
            actively_exploited=True,
        )
        assert calculate_exploitation_score(status) == 4

    def test_calculate_exploitation_score_virustotal_medium(self):
        """Test exploitation score with medium VirusTotal detections."""
        # 5-9 detections → score 3
        status = ExploitationStatus(
            cve_id="CVE-2024-12345",
            in_cisa_kev=False,
            virustotal_detections=7,
            exploit_available=True,
            actively_exploited=False,
        )
        assert calculate_exploitation_score(status) == 3

    def test_calculate_exploitation_score_virustotal_low(self):
        """Test exploitation score with low VirusTotal detections."""
        # 1-4 detections → score 2
        status = ExploitationStatus(
            cve_id="CVE-2024-12345",
            in_cisa_kev=False,
            virustotal_detections=2,
            exploit_available=False,
            actively_exploited=False,
        )
        assert calculate_exploitation_score(status) == 2

    def test_calculate_exploitation_score_none(self):
        """Test exploitation score with no exploitation indicators."""
        # No indicators → score 1
        status = ExploitationStatus(
            cve_id="CVE-2024-12345",
            in_cisa_kev=False,
            virustotal_detections=0,
            exploit_available=False,
            actively_exploited=False,
        )
        assert calculate_exploitation_score(status) == 1

    def test_calculate_asset_exposure_score_high(self):
        """Test asset exposure score for high exposure assets."""
        # Internet-facing, no auth → high exposure
        score = calculate_asset_exposure_score("server", internet_facing=True, authentication_required=False)
        assert score == 5

    def test_calculate_asset_exposure_score_medium(self):
        """Test asset exposure score for medium exposure assets."""
        # Internet-facing with auth → medium exposure
        score = calculate_asset_exposure_score("workstation", internet_facing=True, authentication_required=True)
        assert score == 4

    def test_calculate_asset_exposure_score_low(self):
        """Test asset exposure score for low exposure assets."""
        # Internal, auth required → low exposure
        score = calculate_asset_exposure_score("workstation", internet_facing=False, authentication_required=True)
        assert score == 2

    def test_calculate_threat_capability_score_apt(self):
        """Test threat capability score with known APT actors."""
        # Known APT → score 5
        score = calculate_threat_capability_score(["APT29", "Cozy Bear"], "LOW")
        assert score == 5

    def test_calculate_threat_capability_score_low_complexity(self):
        """Test threat capability score with low attack complexity."""
        # Low complexity increases score
        score = calculate_threat_capability_score([], "LOW")
        assert score == 3

    def test_calculate_threat_capability_score_high_complexity(self):
        """Test threat capability score with high attack complexity."""
        # High complexity decreases score
        score = calculate_threat_capability_score([], "HIGH")
        assert score == 1

    def test_calculate_control_effectiveness_score_full(self):
        """Test control effectiveness with full coverage."""
        # Full coverage → score 1 (strong controls)
        score = calculate_control_effectiveness_score(["WAF", "IPS"], "FULL")
        assert score == 1

    def test_calculate_control_effectiveness_score_partial(self):
        """Test control effectiveness with partial coverage."""
        # Partial coverage → score 3
        score = calculate_control_effectiveness_score(["Firewall"], "PARTIAL")
        assert score == 3

    def test_calculate_control_effectiveness_score_none(self):
        """Test control effectiveness with no coverage."""
        # No coverage → score 5 (weakest controls)
        score = calculate_control_effectiveness_score([], "NONE")
        assert score == 5


class TestRiskScoringTools:
    """Test risk scoring tool functions."""

    def test_calculate_likelihood_tool_success(self):
        """Test likelihood calculation tool with valid inputs."""
        result = calculate_likelihood.invoke({
            "cve_id": "CVE-2024-12345",
            "cvss_score": 9.5,
            "in_cisa_kev": True,
            "vt_detections": 15,
            "asset_type": "server",
            "internet_facing": True,
            "authentication_required": False,
            "threat_actors": ["APT29"],
            "attack_complexity": "LOW",
            "control_coverage": "NONE",
        })

        # Verify result structure
        assert isinstance(result, dict)
        assert "overall_score" in result
        assert "cve_severity" in result
        assert "exploitation_status" in result
        assert "asset_exposure" in result
        assert "threat_capability" in result
        assert "control_effectiveness" in result
        assert "justification" in result

        # Verify scores are in valid range
        assert 1 <= result["overall_score"] <= 5
        assert result["cve_severity"] == 5  # Critical CVSS
        assert result["exploitation_status"] == 5  # CISA KEV

    def test_calculate_likelihood_tool_missing_data(self):
        """Test likelihood calculation with None/missing values."""
        result = calculate_likelihood.invoke({
            "cve_id": "CVE-2024-99999",
            "cvss_score": None,  # Missing CVSS
            "in_cisa_kev": False,
            "vt_detections": 0,
        })

        # Verify defaults applied
        assert isinstance(result, dict)
        assert result["cve_severity"] == 3  # Default moderate
        assert result["overall_score"] >= 1
        assert result["overall_score"] <= 5

    def test_calculate_impact_tool_success(self):
        """Test impact calculation tool with valid inputs."""
        result = calculate_impact.invoke({
            "asset_name": "prod-db-server-01",
            "asset_criticality": 5,
            "data_sensitivity": 5,
            "business_impact": 5,
            "compliance_impact": 4,
            "operational_impact": 5,
        })

        # Verify result structure
        assert isinstance(result, dict)
        assert "overall_score" in result
        assert "asset_criticality" in result
        assert "data_sensitivity" in result
        assert "business_impact" in result
        assert "compliance_impact" in result
        assert "operational_impact" in result
        assert "justification" in result

        # Verify scores
        assert result["asset_criticality"] == 5
        assert result["overall_score"] >= 4  # High impact

    def test_calculate_impact_tool_default_values(self):
        """Test impact calculation with default values."""
        result = calculate_impact.invoke({
            "asset_name": "test-server",
        })

        # Verify defaults (all 3)
        assert result["asset_criticality"] == 3
        assert result["data_sensitivity"] == 3
        assert result["business_impact"] == 3
        assert result["overall_score"] == 3


class TestRiskScoringAgent:
    """Test RiskScoringAgent class."""

    @patch("src.agents.risk_scoring_agent.ChatAnthropic")
    @patch("src.agents.risk_scoring_agent.os.getenv")
    def test_agent_initialization(self, mock_getenv, mock_chat):
        """Test agent initialization with correct tools."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = RiskScoringAgent()

        # Verify
        assert agent.model_name == "claude-3-5-sonnet-20241022"
        assert agent.temperature == 0
        assert len(agent.tools) == 4  # 4 tools: calculate_likelihood, calculate_impact, generate_risk_rating, justify_score
        assert agent.llm is not None
        assert agent.executor is not None

    @patch("src.agents.risk_scoring_agent.ChatAnthropic")
    @patch("src.agents.risk_scoring_agent.os.getenv")
    def test_agent_initialization_custom_params(self, mock_getenv, mock_chat):
        """Test agent initialization with custom parameters."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = RiskScoringAgent(
            model="claude-3-opus-20240229",
            temperature=0.5
        )

        # Verify
        assert agent.model_name == "claude-3-opus-20240229"
        assert agent.temperature == 0.5

    @patch("src.agents.risk_scoring_agent.ChatAnthropic")
    @patch("src.agents.risk_scoring_agent.os.getenv")
    def test_agent_query_success(self, mock_getenv, mock_chat):
        """Test successful agent query execution."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = RiskScoringAgent()

        # Mock executor
        agent.executor = Mock()
        agent.executor.invoke.return_value = {
            "output": "Risk assessment completed: High risk (score 16/25)"
        }

        # Execute
        result = agent.query("Calculate risk for CVE-2024-12345")

        # Verify
        assert "Risk assessment completed" in result
        assert "High risk" in result
        agent.executor.invoke.assert_called_once()

    @patch("src.agents.risk_scoring_agent.ChatAnthropic")
    @patch("src.agents.risk_scoring_agent.os.getenv")
    def test_agent_query_exception(self, mock_getenv, mock_chat):
        """Test agent query handles exceptions gracefully."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = RiskScoringAgent()

        # Mock executor to raise exception
        agent.executor = Mock()
        agent.executor.invoke.side_effect = Exception("LLM API error")

        # Execute
        result = agent.query("Calculate risk")

        # Verify error handling
        assert "Error processing query" in result
        assert "LLM API error" in result

    @patch("src.agents.risk_scoring_agent.ChatAnthropic")
    @patch("src.agents.risk_scoring_agent.os.getenv")
    def test_calculate_risk_method_success(self, mock_getenv, mock_chat):
        """Test calculate_risk programmatic method."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = RiskScoringAgent()

        # Execute
        risk_rating = agent.calculate_risk(
            cve_id="CVE-2024-12345",
            asset_name="prod-server-01",
            cvss_score=9.5,
            in_cisa_kev=True,
            vt_detections=20,
            asset_criticality=5,
            data_sensitivity=5,
        )

        # Verify
        assert risk_rating.cve_id == "CVE-2024-12345"
        assert risk_rating.asset_name == "prod-server-01"
        assert risk_rating.risk_level in ["Critical", "High", "Medium", "Low"]
        assert 1 <= risk_rating.risk_score <= 25
        assert risk_rating.likelihood.overall_score >= 1
        assert risk_rating.impact.overall_score >= 1

    @patch("src.agents.risk_scoring_agent.ChatAnthropic")
    @patch("src.agents.risk_scoring_agent.os.getenv")
    def test_calculate_risk_method_critical_risk(self, mock_getenv, mock_chat):
        """Test calculate_risk returns critical risk for severe vulnerability."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = RiskScoringAgent()

        # Execute - critical CVSS + CISA KEV + high impact
        risk_rating = agent.calculate_risk(
            cve_id="CVE-2024-99999",
            asset_name="critical-server",
            cvss_score=10.0,
            in_cisa_kev=True,
            vt_detections=50,
            asset_criticality=5,
            data_sensitivity=5,
        )

        # Verify critical or high risk
        assert risk_rating.risk_level in ["Critical", "High"]
        assert risk_rating.likelihood.cve_severity == 5
        assert risk_rating.likelihood.exploitation_status == 5

    @patch("src.agents.risk_scoring_agent.ChatAnthropic")
    @patch("src.agents.risk_scoring_agent.os.getenv")
    def test_calculate_risk_method_low_risk(self, mock_getenv, mock_chat):
        """Test calculate_risk returns low risk for low severity vulnerability."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = RiskScoringAgent()

        # Execute - low CVSS, no exploitation
        risk_rating = agent.calculate_risk(
            cve_id="CVE-2024-00001",
            asset_name="test-server",
            cvss_score=2.0,
            in_cisa_kev=False,
            vt_detections=0,
            asset_criticality=2,
            data_sensitivity=2,
        )

        # Verify low or medium risk
        assert risk_rating.risk_level in ["Low", "Medium"]
        assert risk_rating.likelihood.cve_severity == 2

    @patch("src.agents.risk_scoring_agent.ChatAnthropic")
    @patch("src.agents.risk_scoring_agent.os.getenv")
    def test_calculate_risk_handles_exception(self, mock_getenv, mock_chat):
        """Test calculate_risk handles exceptions and returns default low risk."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Mock to raise exception during calculation
        with patch("src.agents.risk_scoring_agent.calculate_cve_severity_score", side_effect=Exception("Test error")):
            agent = RiskScoringAgent()

            # Execute
            risk_rating = agent.calculate_risk(
                cve_id="CVE-2024-ERROR",
                asset_name="test-server",
                cvss_score=7.5,
                in_cisa_kev=False,
                vt_detections=0,
            )

            # Verify default low risk returned
            assert risk_rating.cve_id == "CVE-2024-ERROR"
            assert risk_rating.risk_level == "Low"
            assert "Error" in risk_rating.overall_justification


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
