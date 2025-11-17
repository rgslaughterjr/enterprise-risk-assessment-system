"""Tests for Week 8 Control Discovery Adapters"""
import pytest
from src.tools.confluence_adapter import ConfluenceAdapter
from src.tools.jira_adapter import JiraAdapter
from src.tools.servicenow_grc_adapter import ServiceNowGRCAdapter
from src.tools.filesystem_control_scanner import FilesystemControlScanner
from src.tools.control_deduplicator import ControlDeduplicator


class TestConfluenceAdapter:
    def test_init(self):
        adapter = ConfluenceAdapter(mock_mode=True)
        assert adapter.mock_mode is True

    def test_search_controls_nist(self):
        adapter = ConfluenceAdapter(mock_mode=True)
        controls = adapter.search_controls(query="access control", frameworks=["NIST"])
        assert len(controls) > 0
        assert all(c.framework == "NIST" for c in controls)

    def test_search_controls_cis(self):
        adapter = ConfluenceAdapter(mock_mode=True)
        controls = adapter.search_controls(frameworks=["CIS"])
        assert len(controls) > 0

    def test_get_page_content(self):
        adapter = ConfluenceAdapter(mock_mode=True)
        content = adapter.get_page_content("12345")
        assert content is not None
        assert "NIST" in content


class TestJiraAdapter:
    def test_init(self):
        adapter = JiraAdapter(mock_mode=True)
        assert adapter.mock_mode is True

    def test_search_issues(self):
        adapter = JiraAdapter(mock_mode=True)
        issues = adapter.search_issues()
        assert len(issues) == 10

    def test_get_issue(self):
        adapter = JiraAdapter(mock_mode=True)
        issue = adapter.get_issue("SEC-101")
        assert issue is not None
        assert issue.issue_key == "SEC-101"

    def test_get_issue_controls(self):
        adapter = JiraAdapter(mock_mode=True)
        controls = adapter.get_issue_controls("SEC-101")
        assert len(controls) == 1


class TestServiceNowGRCAdapter:
    def test_init(self):
        adapter = ServiceNowGRCAdapter(mock_mode=True)
        assert adapter.mock_mode is True

    def test_query_all_controls(self):
        adapter = ServiceNowGRCAdapter(mock_mode=True)
        controls = adapter.query_grc_controls()
        assert len(controls) == 15

    def test_query_by_framework(self):
        adapter = ServiceNowGRCAdapter(mock_mode=True)
        controls = adapter.query_grc_controls({'framework': 'NIST'})
        assert all(c.framework == 'NIST' for c in controls)


class TestFilesystemControlScanner:
    def test_init(self):
        scanner = FilesystemControlScanner()
        assert scanner.max_file_size_bytes > 0

    def test_extract_nist_controls(self):
        scanner = FilesystemControlScanner()
        text = "NIST AC-1: Access Control Policy and Procedures"
        controls = scanner.extract_controls_from_text(text, "/tmp/test.md")
        assert len(controls) >= 1
        assert controls[0].control_id == "NIST-AC-1"


class TestControlDeduplicator:
    def test_init(self):
        dedup = ControlDeduplicator(similarity_threshold=0.8)
        assert dedup.similarity_threshold == 0.8

    def test_deduplicate_no_duplicates(self):
        dedup = ControlDeduplicator()
        controls = [
            {'control_id': 'NIST-AC-1', 'title': 'Access Control', 'description': 'Policy', 'confidence': 0.9},
            {'control_id': 'CIS-1.1', 'title': 'Asset Inventory', 'description': 'Maintain inventory', 'confidence': 0.8}
        ]
        result = dedup.deduplicate_controls(controls)
        assert len(result) == 2

    def test_deduplicate_with_duplicates(self):
        dedup = ControlDeduplicator(similarity_threshold=0.7)
        controls = [
            {'control_id': 'NIST-AC-1', 'title': 'Access Control Policy', 'description': 'Establish access control policy', 'confidence': 0.9},
            {'control_id': 'AC-1', 'title': 'Access Control Policy', 'description': 'Establish access control policy', 'confidence': 0.8}
        ]
        result = dedup.deduplicate_controls(controls)
        assert len(result) == 1  # Should deduplicate
