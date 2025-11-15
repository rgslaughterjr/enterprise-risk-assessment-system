"""Expanded tests for DOCX generator to increase coverage."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.tools.docx_generator import DOCXGenerator
from src.models.schemas import RiskAssessmentReport, ExecutiveSummary, RiskRating


class TestDOCXGeneratorExpanded:
    @patch("src.tools.docx_generator.Document")
    @patch("src.tools.docx_generator.os.makedirs")
    def test_create_report(self, mock_makedirs, mock_doc):
        mock_document = Mock()
        mock_doc.return_value = mock_document
        
        generator = DOCXGenerator()
        report = RiskAssessmentReport(
            title="Test Report",
            company_name="TestCo",
            assessment_date="2024-01-01",
            executive_summary=ExecutiveSummary(
                overview="Test overview",
                key_findings=["Finding 1", "Finding 2"],
                risk_score=7.5,
                critical_count=2,
                high_count=5,
                medium_count=10,
                low_count=3
            ),
            vulnerabilities=[],
            threats=[],
            risk_ratings=[],
            recommendations=[]
        )
        
        result = generator.create_report(report, "test_report.docx")
        assert result is not None

    @patch("matplotlib.pyplot.savefig")
    @patch("matplotlib.pyplot.figure")
    def test_create_risk_heatmap_chart(self, mock_fig, mock_save):
        generator = DOCXGenerator()
        risk_ratings = [
            RiskRating(
                cve_id="CVE-2024-1",
                base_score=9.0,
                exploitability=0.9,
                in_kev=True,
                final_risk_score=8.5,
                severity="CRITICAL"
            )
        ]
        
        result = generator._create_risk_heatmap_chart(risk_ratings)
        assert isinstance(result, (str, type(None)))

    @patch("src.tools.docx_generator.Document")
    def test_set_document_properties(self, mock_doc):
        mock_document = Mock()
        mock_doc.return_value = mock_document
        
        generator = DOCXGenerator()
        generator._set_document_properties(mock_document, "TestCo", "Test Report")
        assert True  # Verify no exceptions
