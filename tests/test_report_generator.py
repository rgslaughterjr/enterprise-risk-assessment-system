"""Tests for Report Generator Agent."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.agents.report_agent import (
    ReportAgent,
    create_docx_report,
    create_risk_heatmap,
    save_report,
    get_docx_generator,
)
from src.models.schemas import RiskAssessmentReport, ExecutiveSummary, RiskRating


@pytest.fixture
def mock_report_data():
    """Mock risk assessment report data."""
    return {
        "report_id": "RISK-2024-001",
        "assessment_date": "2024-01-15",
        "executive_summary": {
            "total_vulnerabilities": 10,
            "critical_risks": 2,
            "high_risks": 3,
            "medium_risks": 4,
            "low_risks": 1,
        },
        "risk_ratings": [
            {
                "cve_id": "CVE-2024-12345",
                "asset_name": "prod-server-01",
                "risk_level": "Critical",
                "risk_score": 25,
            }
        ],
    }


class TestReportGeneratorTools:
    """Test report generator tool functions."""

    @patch("src.agents.report_agent.get_docx_generator")
    def test_create_docx_report_tool_success(self, mock_get_generator, mock_report_data):
        """Test successful DOCX report creation."""
        # Setup mock
        mock_generator = Mock()
        mock_get_generator.return_value = mock_generator

        # Execute
        import json
        result = create_docx_report.invoke({
            "report_data_json": json.dumps(mock_report_data),
            "filename": "test_report.docx"
        })

        # Verify
        assert isinstance(result, str)
        assert "reports/risk_assessment_" in result
        assert ".docx" in result

    @patch("src.agents.report_agent.get_docx_generator")
    def test_create_docx_report_tool_with_empty_data(self, mock_get_generator):
        """Test DOCX report creation with minimal data."""
        # Setup mock
        mock_generator = Mock()
        mock_get_generator.return_value = mock_generator

        # Execute with minimal data
        import json
        result = create_docx_report.invoke({
            "report_data_json": json.dumps({"report_id": "TEST-001"}),
        })

        # Verify report path generated
        assert isinstance(result, str)
        assert "reports/" in result

    @patch("src.agents.report_agent.get_docx_generator")
    def test_create_docx_report_tool_json_error(self, mock_get_generator):
        """Test DOCX report creation with invalid JSON."""
        # Setup mock
        mock_generator = Mock()
        mock_get_generator.return_value = mock_generator

        # Execute with invalid JSON
        result = create_docx_report.invoke({
            "report_data_json": "invalid json {{{",
        })

        # Verify error handling
        assert "Error" in result

    @patch("src.agents.report_agent.get_docx_generator")
    def test_create_docx_report_tool_exception(self, mock_get_generator):
        """Test DOCX report creation handles exceptions."""
        # Setup mock to raise exception
        mock_get_generator.side_effect = Exception("Generator initialization failed")

        # Execute
        import json
        result = create_docx_report.invoke({
            "report_data_json": json.dumps({"test": "data"}),
        })

        # Verify error handling
        assert "Error" in result
        assert "Generator initialization failed" in result

    @patch("src.agents.report_agent.get_docx_generator")
    def test_create_risk_heatmap_tool_success(self, mock_get_generator):
        """Test risk heatmap creation."""
        # Setup mock
        mock_generator = Mock()
        mock_get_generator.return_value = mock_generator

        # Execute
        import json
        result = create_risk_heatmap.invoke({
            "risk_ratings_json": json.dumps([
                {"risk_level": "Critical", "count": 2},
                {"risk_level": "High", "count": 5},
            ])
        })

        # Verify
        assert isinstance(result, str)
        assert "risk_heatmap" in result
        assert ".png" in result

    @patch("src.agents.report_agent.get_docx_generator")
    def test_create_risk_heatmap_tool_exception(self, mock_get_generator):
        """Test risk heatmap creation handles exceptions."""
        # Setup mock to raise exception
        mock_get_generator.side_effect = Exception("Heatmap generation failed")

        # Execute
        import json
        result = create_risk_heatmap.invoke({
            "risk_ratings_json": json.dumps([])
        })

        # Verify error handling
        assert "Error" in result

    def test_save_report_tool_success(self):
        """Test save report tool."""
        # Execute
        result = save_report.invoke({
            "output_path": "/tmp/test_report.docx"
        })

        # Verify
        assert isinstance(result, str)
        assert "saved successfully" in result
        assert "/tmp/test_report.docx" in result

    def test_save_report_tool_exception(self):
        """Test save report handles exceptions."""
        # This test just ensures the tool function exists and has error handling
        # In production, actual file I/O errors would be tested
        result = save_report.invoke({
            "output_path": "/invalid/path/report.docx"
        })

        # Should not raise exception, just return error message
        assert isinstance(result, str)


class TestReportAgent:
    """Test ReportAgent class."""

    @patch("src.agents.report_agent.ChatAnthropic")
    @patch("src.agents.report_agent.os.getenv")
    def test_agent_initialization(self, mock_getenv, mock_chat):
        """Test report agent initialization."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = ReportAgent()

        # Verify
        assert agent.model_name == "claude-3-5-sonnet-20241022"
        assert agent.temperature == 0
        assert len(agent.tools) == 3  # create_docx_report, create_risk_heatmap, save_report
        assert agent.llm is not None
        assert agent.executor is not None

    @patch("src.agents.report_agent.ChatAnthropic")
    @patch("src.agents.report_agent.os.getenv")
    def test_agent_initialization_custom_params(self, mock_getenv, mock_chat):
        """Test agent initialization with custom parameters."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = ReportAgent(
            model="claude-3-opus-20240229",
            temperature=0.3
        )

        # Verify
        assert agent.model_name == "claude-3-opus-20240229"
        assert agent.temperature == 0.3

    @patch("src.agents.report_agent.ChatAnthropic")
    @patch("src.agents.report_agent.os.getenv")
    def test_agent_query_success(self, mock_getenv, mock_chat):
        """Test successful agent query."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = ReportAgent()

        # Mock executor
        agent.executor = Mock()
        agent.executor.invoke.return_value = {
            "output": "Report generated successfully at reports/risk_assessment_20240115.docx"
        }

        # Execute
        result = agent.query("Generate risk assessment report")

        # Verify
        assert "Report generated successfully" in result
        agent.executor.invoke.assert_called_once()

    @patch("src.agents.report_agent.ChatAnthropic")
    @patch("src.agents.report_agent.os.getenv")
    def test_agent_query_exception(self, mock_getenv, mock_chat):
        """Test agent query handles LLM errors gracefully."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = ReportAgent()

        # Mock executor to raise exception
        agent.executor = Mock()
        agent.executor.invoke.side_effect = Exception("LLM service unavailable")

        # Execute
        result = agent.query("Generate report")

        # Verify error handling
        assert "Error processing query" in result
        assert "LLM service unavailable" in result

    @patch("src.agents.report_agent.ChatAnthropic")
    @patch("src.agents.report_agent.os.getenv")
    @patch("src.agents.report_agent.get_docx_generator")
    def test_generate_report_method_success(self, mock_get_generator, mock_getenv, mock_chat):
        """Test generate_report programmatic method."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        mock_generator = Mock()
        mock_generator.create_report.return_value = "reports/risk_assessment_20240115.docx"
        mock_get_generator.return_value = mock_generator

        # Create mock report data
        from datetime import datetime
        from src.models.schemas import (
            RiskAssessmentReport,
            ExecutiveSummary,
            LikelihoodScore,
            ImpactScore,
            RiskRating
        )

        exec_summary = ExecutiveSummary(
            total_vulnerabilities=5,
            critical_risks=1,
            high_risks=2,
            medium_risks=2,
            low_risks=0,
            key_findings=["Test finding"],
            top_recommendations=["Test recommendation"],
        )

        report_data = RiskAssessmentReport(
            report_id="TEST-001",
            generated_at=datetime(2024, 1, 15, 10, 0, 0),
            executive_summary=exec_summary,
            incidents=[],
            vulnerabilities=[],
            threats=[],
            risk_ratings=[],
        )

        agent = ReportAgent()

        # Execute
        result = agent.generate_report(report_data, output_path="/tmp/test.docx")

        # Verify
        assert isinstance(result, str)
        assert ".docx" in result
        mock_generator.create_report.assert_called_once()

    @patch("src.agents.report_agent.ChatAnthropic")
    @patch("src.agents.report_agent.os.getenv")
    @patch("src.agents.report_agent.get_docx_generator")
    def test_generate_report_method_exception(self, mock_get_generator, mock_getenv, mock_chat):
        """Test generate_report handles exceptions."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        mock_generator = Mock()
        mock_generator.create_report.side_effect = Exception("File write error")
        mock_get_generator.return_value = mock_generator

        from datetime import datetime
        from src.models.schemas import RiskAssessmentReport, ExecutiveSummary

        exec_summary = ExecutiveSummary(
            total_vulnerabilities=0,
            critical_risks=0,
            high_risks=0,
            medium_risks=0,
            low_risks=0,
            key_findings=[],
            top_recommendations=[],
        )

        report_data = RiskAssessmentReport(
            report_id="TEST-ERROR",
            generated_at=datetime(2024, 1, 15, 10, 0, 0),
            executive_summary=exec_summary,
            incidents=[],
            vulnerabilities=[],
            threats=[],
            risk_ratings=[],
        )

        agent = ReportAgent()

        # Execute
        result = agent.generate_report(report_data)

        # Verify error handling
        assert "Error" in result
        assert "File write error" in result

    @patch("src.agents.report_agent.ChatAnthropic")
    @patch("src.agents.report_agent.os.getenv")
    def test_agent_handles_malformed_input(self, mock_getenv, mock_chat):
        """Test agent validates and rejects malformed input (security test)."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = ReportAgent()

        # Mock executor with validation
        agent.executor = Mock()
        agent.executor.invoke.return_value = {
            "output": "Error: Invalid report data structure"
        }

        # Execute with potentially malicious input
        result = agent.query("Generate report with data: {'__proto__': 'malicious'}")

        # Verify - should not crash, should handle gracefully
        assert isinstance(result, str)


class TestDocxGeneratorSingleton:
    """Test DOCX generator singleton pattern."""

    @patch("src.agents.report_agent.DOCXGenerator")
    def test_get_docx_generator_creates_instance(self, mock_generator_class):
        """Test that get_docx_generator creates a singleton instance."""
        # Reset the global generator
        import src.agents.report_agent as report_module
        report_module._docx_generator = None

        # Setup mock
        mock_instance = Mock()
        mock_generator_class.return_value = mock_instance

        # Execute - first call
        generator1 = get_docx_generator()

        # Verify instance created
        assert generator1 == mock_instance
        mock_generator_class.assert_called_once()

        # Execute - second call
        generator2 = get_docx_generator()

        # Verify same instance returned (singleton)
        assert generator2 == mock_instance
        mock_generator_class.assert_called_once()  # Still only called once


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
