"""
Jira Adapter for Control Discovery

Simplified mock Jira API for discovering security controls tracked in Jira issues.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class JiraControl:
    """Security control tracked in Jira."""
    issue_key: str
    control_id: str
    framework: str
    title: str
    description: str
    status: str
    assignee: str
    project: str
    labels: List[str]
    created: str
    updated: str


class JiraAdapter:
    """Mock Jira API adapter for control discovery."""

    def __init__(self, base_url: str = "https://jira.example.com",
                 username: Optional[str] = None,
                 api_token: Optional[str] = None,
                 mock_mode: bool = True):
        """Initialize Jira adapter."""
        self.base_url = base_url
        self.username = username
        self.api_token = api_token
        self.mock_mode = mock_mode
        self._mock_issues = self._load_mock_issues()
        logger.info(f"Initialized JiraAdapter (mock_mode={mock_mode})")

    def _load_mock_issues(self) -> List[JiraControl]:
        """Load 10 hardcoded control issues."""
        return [
            JiraControl("SEC-101", "NIST-AC-6", "NIST", "Implement Least Privilege",
                       "Deploy privileged access management across enterprise", "Done",
                       "security.team", "SECURITY", ["PAM", "access-control"], "2024-01-15", "2024-03-01"),
            JiraControl("SEC-102", "CIS-5.1", "CIS", "Establish Secure Configurations",
                       "Apply CIS benchmarks to all systems", "In Progress",
                       "engineering.team", "SECURITY", ["hardening", "benchmarks"], "2024-01-20", "2024-03-05"),
            JiraControl("SEC-103", "ISO-A.12.4", "ISO27001", "Logging and Monitoring",
                       "Centralize security event logging", "Done",
                       "soc.team", "COMPLIANCE", ["SIEM", "logging"], "2024-02-01", "2024-02-28"),
            JiraControl("SEC-104", "NIST-IA-2", "NIST", "Multi-Factor Authentication",
                       "Deploy MFA for all users", "In Progress",
                       "iam.team", "SECURITY", ["MFA", "authentication"], "2024-01-10", "2024-03-10"),
            JiraControl("SEC-105", "CIS-8.1", "CIS", "Anti-Malware Software",
                       "Deploy CrowdStrike EDR enterprise-wide", "Done",
                       "endpoint.team", "SECURITY", ["EDR", "malware"], "2023-11-15", "2024-01-30"),
            JiraControl("SEC-106", "NIST-SC-28", "NIST", "Protection of Data at Rest",
                       "Enable encryption for all databases", "Done",
                       "dba.team", "SECURITY", ["encryption", "TDE"], "2024-01-25", "2024-02-20"),
            JiraControl("SEC-107", "ISO-A.9.2", "ISO27001", "User Access Management",
                       "Implement quarterly access recertification", "In Progress",
                       "identity.team", "COMPLIANCE", ["access-review", "recertification"], "2024-02-10", "2024-03-08"),
            JiraControl("SEC-108", "CIS-3.1", "CIS", "Vulnerability Scanning",
                       "Deploy continuous vulnerability assessment", "Done",
                       "vuln.team", "SECURITY", ["scanning", "Tenable"], "2023-12-01", "2024-02-15"),
            JiraControl("SEC-109", "NIST-AU-6", "NIST", "Audit Review and Analysis",
                       "Establish 24x7 SOC operations", "Done",
                       "soc.manager", "SECURITY", ["SOC", "monitoring"], "2024-01-05", "2024-02-25"),
            JiraControl("SEC-110", "ISO-A.16.1", "ISO27001", "Incident Management",
                       "Develop incident response playbooks", "In Progress",
                       "ir.team", "COMPLIANCE", ["incident-response", "playbooks"], "2024-02-15", "2024-03-12"),
        ]

    def search_issues(self, jql: Optional[str] = None,
                     project: Optional[str] = None,
                     labels: Optional[List[str]] = None) -> List[JiraControl]:
        """
        Search Jira issues for security controls.

        Args:
            jql: JQL query (ignored in mock mode)
            project: Filter by project
            labels: Filter by labels

        Returns:
            List of control issues
        """
        logger.info(f"Searching Jira: jql='{jql}', project={project}, labels={labels}")

        issues = self._mock_issues

        if project:
            issues = [i for i in issues if i.project == project]

        if labels:
            issues = [i for i in issues if any(l in i.labels for l in labels)]

        logger.info(f"Found {len(issues)} control issues in Jira")
        return issues

    def get_issue(self, issue_key: str) -> Optional[JiraControl]:
        """Get specific issue by key."""
        for issue in self._mock_issues:
            if issue.issue_key == issue_key:
                return issue
        return None

    def get_issue_controls(self, issue_key: str) -> List[Dict]:
        """Get control details from issue."""
        issue = self.get_issue(issue_key)
        if not issue:
            return []

        return [{
            "control_id": issue.control_id,
            "framework": issue.framework,
            "title": issue.title,
            "description": issue.description,
            "implementation_status": "implemented" if issue.status == "Done" else "in_progress",
            "owner": issue.assignee,
            "evidence": f"Jira issue {issue.issue_key}",
            "last_review": issue.updated,
            "source": "jira",
            "metadata": {
                "issue_key": issue.issue_key,
                "project": issue.project,
                "labels": issue.labels,
                "status": issue.status
            }
        }]

    def to_dict(self, controls: List[JiraControl]) -> List[Dict]:
        """Convert controls to dictionary format."""
        return [asdict(control) for control in controls]
