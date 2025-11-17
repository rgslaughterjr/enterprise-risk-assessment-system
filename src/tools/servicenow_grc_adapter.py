"""
ServiceNow GRC Adapter

Integrates with ServiceNow GRC module for control discovery.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class SNowGRCControl:
    """Control from ServiceNow GRC."""
    sys_id: str
    control_id: str
    framework: str
    title: str
    description: str
    status: str
    owner: str
    test_date: str
    test_result: str
    evidence: str


class ServiceNowGRCAdapter:
    """Mock ServiceNow GRC adapter."""

    def __init__(self, instance_url: str = "https://instance.service-now.com",
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 mock_mode: bool = True):
        """Initialize ServiceNow GRC adapter."""
        self.instance_url = instance_url
        self.username = username
        self.password = password
        self.mock_mode = mock_mode
        self._mock_controls = self._load_mock_controls()
        logger.info(f"Initialized ServiceNowGRCAdapter (mock_mode={mock_mode})")

    def _load_mock_controls(self) -> List[SNowGRCControl]:
        """Load 15 mock GRC controls."""
        return [
            SNowGRCControl("abc123", "NIST-AC-1", "NIST", "Access Control Policy",
                          "Documented access control policy and procedures", "Effective",
                          "CISO", "2024-03-01", "Pass", "Policy document v2.1"),
            SNowGRCControl("abc124", "NIST-AC-2", "NIST", "Account Management",
                          "Account lifecycle management procedures", "Effective",
                          "IT Operations", "2024-02-28", "Pass", "ServiceNow provisioning workflow"),
            SNowGRCControl("abc125", "CIS-1.1", "CIS", "Asset Inventory",
                          "Maintain detailed asset inventory", "Effective",
                          "Asset Management", "2024-03-05", "Pass", "CMDB 99.5% accurate"),
            SNowGRCControl("abc126", "CIS-5.1", "CIS", "Secure Configurations",
                          "Establish and maintain secure configurations", "Effective",
                          "Security Engineering", "2024-02-20", "Pass", "CIS benchmarks applied"),
            SNowGRCControl("abc127", "ISO-A.9.1", "ISO27001", "Access Control Policy",
                          "Business requirements for access control", "Effective",
                          "Compliance", "2024-03-10", "Pass", "Policy v2.3"),
            SNowGRCControl("abc128", "NIST-IA-2", "NIST", "Identification and Authentication",
                          "Uniquely identify and authenticate users", "Effective",
                          "Identity Management", "2024-03-08", "Pass", "SSO with MFA"),
            SNowGRCControl("abc129", "CIS-3.1", "CIS", "Vulnerability Scanning",
                          "Run automated vulnerability scanning", "Effective",
                          "Vuln Management", "2024-03-01", "Pass", "Weekly Tenable scans"),
            SNowGRCControl("abc130", "NIST-AU-6", "NIST", "Audit Review",
                          "Review and analyze audit records", "Effective",
                          "SOC Team", "2024-02-25", "Pass", "24x7 SIEM monitoring"),
            SNowGRCControl("abc131", "ISO-A.12.4", "ISO27001", "Logging and Monitoring",
                          "Event logs produced and reviewed", "Effective",
                          "Security Operations", "2024-03-05", "Pass", "Splunk centralized logging"),
            SNowGRCControl("abc132", "CIS-8.1", "CIS", "Anti-Malware",
                          "Centrally managed anti-malware", "Effective",
                          "Endpoint Security", "2024-02-18", "Pass", "CrowdStrike EDR"),
            SNowGRCControl("abc133", "NIST-SC-28", "NIST", "Data at Rest Protection",
                          "Protect confidentiality of data at rest", "Effective",
                          "Data Security", "2024-03-10", "Pass", "TDE + disk encryption"),
            SNowGRCControl("abc134", "ISO-A.16.1", "ISO27001", "Incident Management",
                          "Manage information security incidents", "Testing",
                          "Incident Response", "2024-03-12", "In Progress", "IR plan v3.0"),
            SNowGRCControl("abc135", "CIS-6.2", "CIS", "Activate Audit Logging",
                          "Enable logging on all systems", "Effective",
                          "IT Operations", "2024-02-28", "Pass", "100% coverage"),
            SNowGRCControl("abc136", "NIST-SC-7", "NIST", "Boundary Protection",
                          "Monitor and control communications at boundaries", "Effective",
                          "Network Security", "2024-03-08", "Pass", "Next-gen firewalls + IDS/IPS"),
            SNowGRCControl("abc137", "ISO-A.18.1", "ISO27001", "Legal Compliance",
                          "Comply with legal and contractual requirements", "Effective",
                          "Legal", "2024-03-05", "Pass", "Compliance register maintained"),
        ]

    def query_grc_controls(self, filters: Optional[Dict] = None) -> List[SNowGRCControl]:
        """
        Query GRC controls from ServiceNow.

        Args:
            filters: Query filters (framework, status, owner, etc.)

        Returns:
            List of GRC controls
        """
        logger.info(f"Querying ServiceNow GRC controls with filters: {filters}")

        controls = self._mock_controls

        if filters:
            if 'framework' in filters:
                controls = [c for c in controls if c.framework == filters['framework']]
            if 'status' in filters:
                controls = [c for c in controls if c.status == filters['status']]
            if 'owner' in filters:
                controls = [c for c in controls if c.owner == filters['owner']]

        logger.info(f"Found {len(controls)} GRC controls")
        return controls

    def get_control(self, sys_id: str) -> Optional[SNowGRCControl]:
        """Get specific control by sys_id."""
        for control in self._mock_controls:
            if control.sys_id == sys_id:
                return control
        return None

    def to_dict(self, controls: List[SNowGRCControl]) -> List[Dict]:
        """Convert controls to dictionary format."""
        return [asdict(control) for control in controls]
