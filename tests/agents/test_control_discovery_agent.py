"""Tests for Control Discovery Agent.

Comprehensive test suite covering:
- Agent initialization and configuration
- Multi-source control discovery
- Deduplication workflow
- Risk mapping orchestration
- Coverage analysis
- Full discovery workflow
- Error handling and recovery
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.agents.control_discovery_agent import ControlDiscoveryAgent


class TestControlDiscoveryAgent:
    """Test suite for control discovery agent."""

    def test_init_default(self):
        """Test agent initialization with defaults."""
        agent = ControlDiscoveryAgent()

        assert agent.mock_mode is True
        assert agent.max_workers == 3
        assert agent.confluence_adapter is not None
        assert agent.servicenow_adapter is not None
        assert agent.filesystem_scanner is not None

    def test_init_custom_settings(self):
        """Test agent initialization with custom settings."""
        agent = ControlDiscoveryAgent(mock_mode=True, max_workers=5)

        assert agent.max_workers == 5

    def test_discover_controls_confluence_only(self):
        """Test discovering controls from Confluence only."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = agent.discover_controls(
            sources=['confluence'],
            confluence_spaces=['SEC']
        )

        assert isinstance(controls, list)
        assert len(controls) > 0
        assert agent.discovered_controls == controls

    def test_discover_controls_servicenow_only(self):
        """Test discovering controls from ServiceNow only."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = agent.discover_controls(sources=['servicenow'])

        assert isinstance(controls, list)
        assert len(controls) > 0

    def test_discover_controls_filesystem_with_temp_dir(self):
        """Test discovering controls from filesystem."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            test_file = Path(tmpdir) / "controls.md"
            test_file.write_text("# Controls\nNIST AC-1\nCIS 1.1")

            controls = agent.discover_controls(
                sources=['filesystem'],
                filesystem_paths=[tmpdir]
            )

            assert isinstance(controls, list)
            # May or may not find controls depending on scanner

    def test_discover_controls_all_sources(self):
        """Test discovering from all sources in parallel."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = agent.discover_controls()  # Default = all sources

        assert isinstance(controls, list)
        assert len(controls) > 0

    def test_discover_from_source_confluence(self):
        """Test discovering from single Confluence source."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = agent._discover_from_source('confluence', 'SEC', None)

        assert isinstance(controls, list)
        assert len(controls) > 0

    def test_discover_from_source_servicenow(self):
        """Test discovering from single ServiceNow source."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = agent._discover_from_source('servicenow', None, {})

        assert isinstance(controls, list)
        assert len(controls) > 0

    def test_discover_from_source_unknown(self):
        """Test discovering from unknown source."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = agent._discover_from_source('unknown_source', None, None)

        assert isinstance(controls, list)
        assert len(controls) == 0

    def test_deduplicate_and_enrich_no_controls(self):
        """Test deduplication with no controls."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        unique = agent.deduplicate_and_enrich([])

        assert isinstance(unique, list)
        assert len(unique) == 0

    def test_deduplicate_and_enrich_with_controls(self):
        """Test deduplication with controls."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = [
            {"id": "NIST-AC-1", "title": "Access Control", "source": "confluence"},
            {"id": "NIST-AC-1", "title": "Access Control", "source": "servicenow"},
            {"id": "NIST-AU-2", "title": "Audit Events", "source": "filesystem"},
        ]

        unique = agent.deduplicate_and_enrich(controls)

        assert isinstance(unique, list)
        assert len(unique) <= len(controls)
        assert agent.unique_controls == unique

    def test_deduplicate_uses_discovered_controls(self):
        """Test deduplication uses discovered controls when none provided."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        agent.discovered_controls = [
            {"id": "CTRL-1", "title": "Control"},
        ]

        unique = agent.deduplicate_and_enrich()

        assert len(unique) > 0

    def test_map_to_risks_no_controls(self):
        """Test risk mapping with no controls."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        risks = [{"id": "RISK-1", "title": "Risk"}]
        mappings = agent.map_to_risks(risks, [])

        assert isinstance(mappings, list)
        assert len(mappings) == 0

    def test_map_to_risks_no_risks(self):
        """Test risk mapping with no risks."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = [{"id": "CTRL-1", "title": "Control"}]
        mappings = agent.map_to_risks([], controls)

        assert isinstance(mappings, list)
        assert len(mappings) == 0

    def test_map_to_risks_with_data(self):
        """Test risk mapping with controls and risks."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = [
            {"id": "CTRL-1", "title": "Access Control", "category": "Access Control"}
        ]

        risks = [
            {"id": "RISK-1", "title": "Unauthorized Access", "description": "Access risk"}
        ]

        mappings = agent.map_to_risks(risks, controls)

        assert isinstance(mappings, list)
        assert agent.control_mappings == mappings

    def test_map_to_risks_uses_unique_controls(self):
        """Test risk mapping uses unique controls when none provided."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        agent.unique_controls = [
            {"id": "CTRL-1", "title": "Control", "category": "Security"}
        ]

        risks = [{"id": "RISK-1", "title": "Risk", "description": "Security risk"}]
        mappings = agent.map_to_risks(risks)

        assert isinstance(mappings, list)

    def test_analyze_coverage_no_data(self):
        """Test coverage analysis with no data."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        analysis = agent.analyze_coverage([])

        assert isinstance(analysis, dict)
        assert not analysis  # Should be empty

    def test_analyze_coverage_with_data(self):
        """Test coverage analysis with controls and risks."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        controls = [
            {"id": "CTRL-1", "title": "Control", "implementation_status": "Implemented", "effectiveness_score": 0.85}
        ]

        risks = [
            {"id": "RISK-1", "title": "Risk", "risk_level": "High", "description": "Test risk"}
        ]

        # Need to set up mappings
        from src.tools.control_risk_matcher import ControlRiskMatcher
        matcher = ControlRiskMatcher()
        mappings = matcher.match_controls_to_risks(controls, risks)

        analysis = agent.analyze_coverage(risks, controls, mappings)

        assert isinstance(analysis, dict)
        assert "summary" in analysis
        assert "gaps" in analysis
        assert agent.gap_analysis == analysis

    def test_run_full_discovery(self):
        """Test complete discovery workflow."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        risks = [
            {"id": "RISK-1", "title": "Access Risk", "risk_level": "High", "description": "Risk"}
        ]

        report = agent.run_full_discovery(
            risks=risks,
            sources=['confluence', 'servicenow']
        )

        assert isinstance(report, dict)
        assert "execution_summary" in report
        assert "discovery_results" in report
        assert "risk_mappings" in report
        assert "gap_analysis" in report

    def test_run_full_discovery_execution_summary(self):
        """Test execution summary in full discovery."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        risks = [{"id": "RISK-1", "title": "Risk", "risk_level": "Medium", "description": "Test"}]
        report = agent.run_full_discovery(risks=risks)

        summary = report["execution_summary"]
        assert "start_time" in summary
        assert "end_time" in summary
        assert "duration_seconds" in summary
        assert "sources_queried" in summary
        assert summary["mock_mode"] is True

    def test_run_full_discovery_results(self):
        """Test discovery results in full discovery."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        risks = [{"id": "RISK-1", "title": "Risk", "risk_level": "Low", "description": "Test"}]
        report = agent.run_full_discovery(risks=risks)

        results = report["discovery_results"]
        assert "total_discovered" in results
        assert "unique_controls" in results
        assert "deduplication_rate" in results
        assert "controls" in results

    def test_get_discovery_summary(self):
        """Test getting discovery summary."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        # No discovery yet
        summary = agent.get_discovery_summary()

        assert "discovered_count" in summary
        assert summary["discovered_count"] == 0

        # After discovery
        agent.discovered_controls = [{"id": "CTRL-1"}]
        agent.unique_controls = [{"id": "CTRL-1"}]

        summary = agent.get_discovery_summary()
        assert summary["discovered_count"] == 1
        assert summary["unique_count"] == 1

    def test_export_report_json(self):
        """Test exporting report as JSON."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        report = {
            "test": "data",
            "summary": {"controls": 10}
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "report.json")

            success = agent.export_report(report, output_path, format="json")

            assert success is True
            assert Path(output_path).exists()

            # Verify content
            with open(output_path) as f:
                loaded = json.load(f)
                assert loaded["test"] == "data"

    def test_export_report_text(self):
        """Test exporting report as text."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        report = {
            "execution_summary": {"duration_seconds": 10, "sources_queried": ["confluence"], "mock_mode": True},
            "discovery_results": {"total_discovered": 5, "unique_controls": 3, "deduplication_rate": 40},
            "gap_analysis": {
                "summary": {"total_risks": 2, "gaps_identified": 1, "coverage_rate": 50, "average_coverage_score": 0.6},
                "gaps": [{"risk_name": "Test Risk", "priority": "High", "coverage_score": 0.3, "residual_risk": "High"}]
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "report.txt")

            success = agent.export_report(report, output_path, format="text")

            assert success is True
            assert Path(output_path).exists()

            # Verify some content
            with open(output_path) as f:
                content = f.read()
                assert "CONTROL DISCOVERY REPORT" in content

    def test_export_report_unsupported_format(self):
        """Test exporting with unsupported format."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        report = {"test": "data"}

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = str(Path(tmpdir) / "report.xml")

            success = agent.export_report(report, output_path, format="xml")

            assert success is False

    def test_parallel_discovery_execution(self):
        """Test parallel execution of discovery tasks."""
        agent = ControlDiscoveryAgent(mock_mode=True, max_workers=2)

        controls = agent.discover_controls(
            sources=['confluence', 'servicenow']
        )

        # Should successfully discover from multiple sources
        assert isinstance(controls, list)
        assert len(controls) > 0

    def test_error_recovery_in_discovery(self):
        """Test error recovery when one source fails."""
        agent = ControlDiscoveryAgent(mock_mode=True)

        # Even if one source fails, others should succeed
        controls = agent.discover_controls(
            sources=['confluence', 'servicenow', 'filesystem'],
            filesystem_paths=['/nonexistent/path']
        )

        # Should still get controls from confluence and servicenow
        assert isinstance(controls, list)
