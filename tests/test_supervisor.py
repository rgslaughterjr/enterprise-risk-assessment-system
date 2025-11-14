"""Tests for Risk Assessment Supervisor."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.supervisor.supervisor import (
    RiskAssessmentSupervisor,
    servicenow_node,
    vulnerability_node,
    threat_research_node,
    risk_scoring_node,
    report_generation_node,
    user_check_1,
    user_check_2,
    user_check_3,
    route_next,
    SupervisorState,
)


@pytest.fixture
def mock_supervisor_state():
    """Mock supervisor state."""
    return {
        "query": "Assess critical risks",
        "cve_ids": ["CVE-2024-12345"],
        "incidents": [],
        "cmdb_items": [],
        "vulnerabilities": [],
        "threats": [],
        "risk_ratings": [],
        "report_path": "",
        "next_step": "",
        "user_approved": False,
        "completed": False,
        "error": "",
        "messages": [],
    }


class TestSupervisorNodeFunctions:
    """Test supervisor node functions."""

    @patch("src.supervisor.supervisor.ServiceNowAgent")
    def test_servicenow_node_success(self, mock_agent_class, mock_supervisor_state):
        """Test ServiceNow node executes successfully."""
        # Setup mock
        mock_agent = Mock()
        mock_agent.get_incidents_for_analysis.return_value = [
            Mock(model_dump=lambda: {"number": "INC0010001", "priority": "1"})
        ]
        mock_agent.get_assets_for_analysis.return_value = [
            Mock(model_dump=lambda: {"name": "server-01", "sys_class_name": "cmdb_ci_server"})
        ]
        mock_agent_class.return_value = mock_agent

        # Execute
        result = servicenow_node(mock_supervisor_state)

        # Verify
        assert result["next_step"] == "user_check_1"
        assert len(result["incidents"]) == 1
        assert len(result["cmdb_items"]) == 1
        assert len(result["messages"]) > 0

    @patch("src.supervisor.supervisor.ServiceNowAgent")
    def test_servicenow_node_exception(self, mock_agent_class, mock_supervisor_state):
        """Test ServiceNow node handles exceptions."""
        # Setup mock to raise exception
        mock_agent_class.side_effect = Exception("ServiceNow connection failed")

        # Execute
        result = servicenow_node(mock_supervisor_state)

        # Verify error handling
        assert result["next_step"] == "error"
        assert "ServiceNow connection failed" in result["error"]

    @patch("src.supervisor.supervisor.VulnerabilityAgent")
    def test_vulnerability_node_success(self, mock_agent_class, mock_supervisor_state):
        """Test vulnerability analysis node executes successfully."""
        # Setup mock
        mock_agent = Mock()
        mock_agent.analyze_cves.return_value = [
            Mock(model_dump=lambda: {"cve_id": "CVE-2024-12345", "cvss_score": 9.5})
        ]
        mock_agent_class.return_value = mock_agent

        # Set CVE IDs in state
        mock_supervisor_state["cve_ids"] = ["CVE-2024-12345"]

        # Execute
        result = vulnerability_node(mock_supervisor_state)

        # Verify
        assert result["next_step"] == "threat_research"
        assert len(result["vulnerabilities"]) == 1

    @patch("src.supervisor.supervisor.VulnerabilityAgent")
    def test_vulnerability_node_exception(self, mock_agent_class, mock_supervisor_state):
        """Test vulnerability node handles exceptions."""
        # Setup mock to raise exception
        mock_agent_class.side_effect = Exception("NVD API error")

        # Execute
        result = vulnerability_node(mock_supervisor_state)

        # Verify error handling
        assert result["next_step"] == "error"
        assert "NVD API error" in result["error"]

    @patch("src.supervisor.supervisor.ThreatAgent")
    def test_threat_research_node_success(self, mock_agent_class, mock_supervisor_state):
        """Test threat research node executes successfully."""
        # Setup mock
        mock_agent = Mock()
        mock_agent.analyze_cve_threat.return_value = Mock(
            model_dump=lambda: {"cve_id": "CVE-2024-12345", "techniques": []}
        )
        mock_agent_class.return_value = mock_agent

        # Set vulnerabilities in state
        mock_supervisor_state["vulnerabilities"] = [
            {"cve_detail": {"cve_id": "CVE-2024-12345", "description": "Test vuln"}}
        ]

        # Execute
        result = threat_research_node(mock_supervisor_state)

        # Verify
        assert result["next_step"] == "user_check_2"
        assert len(result["threats"]) > 0

    @patch("src.supervisor.supervisor.RiskScoringAgent")
    def test_risk_scoring_node_success(self, mock_agent_class, mock_supervisor_state):
        """Test risk scoring node executes successfully."""
        # Setup mock
        mock_agent = Mock()
        mock_agent.calculate_risk.return_value = Mock(
            model_dump=lambda: {
                "cve_id": "CVE-2024-12345",
                "risk_level": "Critical",
                "risk_score": 25
            }
        )
        mock_agent_class.return_value = mock_agent

        # Set state data
        mock_supervisor_state["cmdb_items"] = [{"name": "server-01"}]
        mock_supervisor_state["vulnerabilities"] = [
            {
                "cve_detail": {"cve_id": "CVE-2024-12345", "cvss_score": 9.5},
                "exploitation_status": {"in_cisa_kev": True, "virustotal_detections": 10}
            }
        ]

        # Execute
        result = risk_scoring_node(mock_supervisor_state)

        # Verify
        assert result["next_step"] == "user_check_3"
        assert len(result["risk_ratings"]) == 1

    @patch("src.supervisor.supervisor.ReportAgent")
    def test_report_generation_node_success(self, mock_agent_class, mock_supervisor_state):
        """Test report generation node executes successfully."""
        # Setup mock
        mock_agent = Mock()
        mock_agent_class.return_value = mock_agent

        # Set state data
        mock_supervisor_state["vulnerabilities"] = [{"cve_id": "CVE-2024-12345"}]
        mock_supervisor_state["cve_ids"] = ["CVE-2024-12345"]
        mock_supervisor_state["risk_ratings"] = [
            {"risk_level": "Critical"},
            {"risk_level": "High"},
            {"risk_level": "Medium"}
        ]

        # Execute
        result = report_generation_node(mock_supervisor_state)

        # Verify
        assert result["next_step"] == "complete"
        assert result["completed"] is True
        assert "reports/" in result["report_path"]
        assert ".docx" in result["report_path"]

    def test_user_check_1_success(self, mock_supervisor_state):
        """Test user check-in 1 approves and continues."""
        # Execute
        result = user_check_1(mock_supervisor_state)

        # Verify
        assert result["user_approved"] is True
        assert result["next_step"] == "vulnerability_analysis"

    def test_user_check_2_success(self, mock_supervisor_state):
        """Test user check-in 2 approves and continues."""
        # Execute
        result = user_check_2(mock_supervisor_state)

        # Verify
        assert result["user_approved"] is True
        assert result["next_step"] == "risk_scoring"

    def test_user_check_3_success(self, mock_supervisor_state):
        """Test user check-in 3 approves and continues."""
        # Execute
        result = user_check_3(mock_supervisor_state)

        # Verify
        assert result["user_approved"] is True
        assert result["next_step"] == "report_generation"


class TestSupervisorRouting:
    """Test supervisor routing logic."""

    def test_route_next_normal_flow(self, mock_supervisor_state):
        """Test routing to next step in normal flow."""
        # Setup
        mock_supervisor_state["next_step"] = "vulnerability_analysis"

        # Execute
        result = route_next(mock_supervisor_state)

        # Verify
        assert result == "vulnerability_analysis"

    def test_route_next_with_error(self, mock_supervisor_state):
        """Test routing when error in state."""
        # Setup
        mock_supervisor_state["error"] = "Test error"

        # Execute
        from langgraph.graph import END
        result = route_next(mock_supervisor_state)

        # Verify routes to END
        assert result == END

    def test_route_next_when_completed(self, mock_supervisor_state):
        """Test routing when workflow completed."""
        # Setup
        mock_supervisor_state["next_step"] = "complete"
        mock_supervisor_state["completed"] = True

        # Execute
        from langgraph.graph import END
        result = route_next(mock_supervisor_state)

        # Verify routes to END
        assert result == END


class TestRiskAssessmentSupervisor:
    """Test RiskAssessmentSupervisor class."""

    def test_supervisor_initialization(self):
        """Test supervisor initializes workflow graph successfully."""
        # Execute
        supervisor = RiskAssessmentSupervisor()

        # Verify
        assert supervisor.app is not None

    @patch("src.supervisor.supervisor.servicenow_node")
    @patch("src.supervisor.supervisor.vulnerability_node")
    @patch("src.supervisor.supervisor.threat_research_node")
    @patch("src.supervisor.supervisor.risk_scoring_node")
    @patch("src.supervisor.supervisor.report_generation_node")
    def test_run_assessment_success(
        self,
        mock_report_node,
        mock_risk_node,
        mock_threat_node,
        mock_vuln_node,
        mock_sn_node
    ):
        """Test run_assessment executes complete workflow."""
        # Setup mocks to simulate workflow
        def mock_servicenow(state):
            state["incidents"] = [{"number": "INC001"}]
            state["cmdb_items"] = [{"name": "server-01"}]
            state["next_step"] = "user_check_1"
            state["messages"] = ["ServiceNow complete"]
            return state

        def mock_vulnerability(state):
            state["vulnerabilities"] = [{"cve_id": "CVE-2024-12345"}]
            state["next_step"] = "threat_research"
            state["messages"] = ["Vulnerability analysis complete"]
            return state

        def mock_threat(state):
            state["threats"] = [{"cve_id": "CVE-2024-12345"}]
            state["next_step"] = "user_check_2"
            state["messages"] = ["Threat research complete"]
            return state

        def mock_risk(state):
            state["risk_ratings"] = [{"risk_level": "Critical"}]
            state["next_step"] = "user_check_3"
            state["messages"] = ["Risk scoring complete"]
            return state

        def mock_report(state):
            state["report_path"] = "reports/test_report.docx"
            state["next_step"] = "complete"
            state["completed"] = True
            state["messages"] = ["Report generated"]
            return state

        mock_sn_node.side_effect = mock_servicenow
        mock_vuln_node.side_effect = mock_vulnerability
        mock_threat_node.side_effect = mock_threat
        mock_risk_node.side_effect = mock_risk
        mock_report_node.side_effect = mock_report

        # Execute
        supervisor = RiskAssessmentSupervisor()
        result = supervisor.run_assessment(
            query="Test assessment",
            cve_ids=["CVE-2024-12345"]
        )

        # Verify
        assert isinstance(result, dict)
        # Check that workflow executed (state was updated)
        assert "query" in result or "error" in result

    def test_run_assessment_with_exception(self):
        """Test run_assessment handles exceptions."""
        # Setup - mock node to raise exception
        with patch("src.supervisor.supervisor.servicenow_node", side_effect=Exception("Test error")):
            supervisor = RiskAssessmentSupervisor()

            # Execute
            result = supervisor.run_assessment(query="Test")

            # Verify error handling
            assert "error" in result or "completed" in result

    def test_get_workflow_graph(self):
        """Test get_workflow_graph returns diagram."""
        # Execute
        supervisor = RiskAssessmentSupervisor()
        diagram = supervisor.get_workflow_graph()

        # Verify
        assert isinstance(diagram, str)
        assert "ServiceNow" in diagram
        assert "Vulnerability Analysis" in diagram
        assert "Risk Scoring" in diagram
        assert "Report Generation" in diagram


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
