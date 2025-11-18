"""ServiceNow GRC (Governance, Risk, and Compliance) API adapter for control discovery.

This adapter provides methods to query GRC controls, control tests, and compliance
records from ServiceNow GRC module. Supports real ServiceNow integration with mock fallback.
"""

import os
import requests
from typing import List, Dict, Optional, Any
from datetime import datetime
from dotenv import load_dotenv
import logging

from ..utils.error_handler import (
    handle_api_response,
    retry_on_api_error,
    validate_api_key,
    log_api_call,
    APIError,
)

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


class ServiceNowGRCAdapter:
    """Adapter for ServiceNow GRC module interactions.

    Provides methods for querying GRC controls, control tests, and compliance
    assessments with comprehensive error handling and retry logic.
    """

    def __init__(
        self,
        instance_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        mock_mode: bool = False,
    ):
        """Initialize ServiceNow GRC adapter.

        Args:
            instance_url: ServiceNow instance URL (e.g., https://dev12345.service-now.com)
            username: ServiceNow username
            password: ServiceNow password
            mock_mode: If True, use mock data instead of real API calls

        Raises:
            ValueError: If required credentials are missing and not in mock mode
        """
        self.instance_url = instance_url or os.getenv("SERVICENOW_INSTANCE")
        self.username = username or os.getenv("SERVICENOW_USERNAME")
        self.password = password or os.getenv("SERVICENOW_PASSWORD")
        self.mock_mode = mock_mode

        if not self.mock_mode:
            # Validate credentials for real API calls
            if not self.instance_url:
                raise ValueError("ServiceNow instance URL is required")
            if not self.username:
                raise ValueError("ServiceNow username is required")
            if not self.password:
                raise ValueError("ServiceNow password is required")

            # Remove trailing slash from instance URL
            self.instance_url = self.instance_url.rstrip("/")

            # Set up authentication
            self.auth = (self.username, self.password)

            # Base headers for all requests
            self.headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            logger.info(f"ServiceNow GRC adapter initialized for instance: {self.instance_url}")
        else:
            logger.info("ServiceNow GRC adapter initialized in MOCK mode")

    def _build_url(self, table: str) -> str:
        """Build API endpoint URL for a GRC table.

        Args:
            table: ServiceNow GRC table name (e.g., 'sn_grc_control', 'sn_grc_control_test')

        Returns:
            Full API endpoint URL
        """
        return f"{self.instance_url}/api/now/table/{table}"

    def _generate_mock_controls(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Generate mock GRC control data for testing.

        Args:
            limit: Number of mock controls to generate

        Returns:
            List of mock control dictionaries
        """
        mock_controls = [
            {
                "sys_id": "grc_ctrl_001",
                "number": "CTRL0001",
                "name": "Access Control Policy",
                "description": "Establish and maintain access control policies aligned with NIST AC-1",
                "framework": "NIST SP 800-53",
                "control_id": "AC-1",
                "category": "Access Control",
                "implementation_status": "Implemented",
                "effectiveness_score": "85",
                "owner": "Security Team",
                "last_tested": "2024-01-15",
                "test_result": "Passed",
            },
            {
                "sys_id": "grc_ctrl_002",
                "number": "CTRL0002",
                "name": "Account Management",
                "description": "Implement automated account lifecycle management per NIST AC-2",
                "framework": "NIST SP 800-53",
                "control_id": "AC-2",
                "category": "Access Control",
                "implementation_status": "Implemented",
                "effectiveness_score": "90",
                "owner": "Identity & Access Team",
                "last_tested": "2024-02-01",
                "test_result": "Passed",
            },
            {
                "sys_id": "grc_ctrl_003",
                "number": "CTRL0003",
                "name": "Least Privilege",
                "description": "Enforce principle of least privilege per NIST AC-6",
                "framework": "NIST SP 800-53",
                "control_id": "AC-6",
                "category": "Access Control",
                "implementation_status": "Partially Implemented",
                "effectiveness_score": "75",
                "owner": "Security Team",
                "last_tested": "2024-01-20",
                "test_result": "Failed",
            },
            {
                "sys_id": "grc_ctrl_004",
                "number": "CTRL0004",
                "name": "Asset Inventory",
                "description": "Maintain detailed asset inventory per CIS Control 1.1",
                "framework": "CIS Controls v8",
                "control_id": "1.1",
                "category": "Inventory and Control",
                "implementation_status": "Implemented",
                "effectiveness_score": "88",
                "owner": "Asset Management Team",
                "last_tested": "2024-01-10",
                "test_result": "Passed",
            },
            {
                "sys_id": "grc_ctrl_005",
                "number": "CTRL0005",
                "name": "MFA for External Access",
                "description": "Require multi-factor authentication for external access per CIS 6.3",
                "framework": "CIS Controls v8",
                "control_id": "6.3",
                "category": "Access Control",
                "implementation_status": "Implemented",
                "effectiveness_score": "95",
                "owner": "Security Team",
                "last_tested": "2024-02-05",
                "test_result": "Passed",
            },
            {
                "sys_id": "grc_ctrl_006",
                "number": "CTRL0006",
                "name": "Information Security Policy",
                "description": "Maintain and enforce information security policy per ISO A.5.1",
                "framework": "ISO 27001:2022",
                "control_id": "A.5.1",
                "category": "Organizational Controls",
                "implementation_status": "Implemented",
                "effectiveness_score": "82",
                "owner": "CISO Office",
                "last_tested": "2024-01-25",
                "test_result": "Passed",
            },
            {
                "sys_id": "grc_ctrl_007",
                "number": "CTRL0007",
                "name": "Privileged Access Management",
                "description": "Control and monitor privileged access per ISO A.8.2",
                "framework": "ISO 27001:2022",
                "control_id": "A.8.2",
                "category": "Technological Controls",
                "implementation_status": "Implemented",
                "effectiveness_score": "87",
                "owner": "IAM Team",
                "last_tested": "2024-02-10",
                "test_result": "Passed",
            },
            {
                "sys_id": "grc_ctrl_008",
                "number": "CTRL0008",
                "name": "Audit Logging",
                "description": "Comprehensive audit logging per NIST AU-2",
                "framework": "NIST SP 800-53",
                "control_id": "AU-2",
                "category": "Audit and Accountability",
                "implementation_status": "Implemented",
                "effectiveness_score": "91",
                "owner": "Security Operations",
                "last_tested": "2024-01-30",
                "test_result": "Passed",
            },
            {
                "sys_id": "grc_ctrl_009",
                "number": "CTRL0009",
                "name": "Vulnerability Management",
                "description": "Establish vulnerability management process per CIS 7.1",
                "framework": "CIS Controls v8",
                "control_id": "7.1",
                "category": "Vulnerability Management",
                "implementation_status": "Implemented",
                "effectiveness_score": "80",
                "owner": "Vulnerability Management Team",
                "last_tested": "2024-02-15",
                "test_result": "Passed",
            },
            {
                "sys_id": "grc_ctrl_010",
                "number": "CTRL0010",
                "name": "Malware Protection",
                "description": "Deploy and maintain anti-malware per ISO A.8.7",
                "framework": "ISO 27001:2022",
                "control_id": "A.8.7",
                "category": "Technological Controls",
                "implementation_status": "Implemented",
                "effectiveness_score": "93",
                "owner": "Security Operations",
                "last_tested": "2024-02-20",
                "test_result": "Passed",
            },
        ]

        return mock_controls[:limit]

    @retry_on_api_error(max_attempts=3)
    def _make_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> Dict:
        """Make HTTP request to ServiceNow API with error handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL to request
            params: Query parameters
            data: Request body data

        Returns:
            JSON response data

        Raises:
            APIError: If request fails
        """
        log_api_call("ServiceNow GRC", url, params)

        try:
            response = requests.request(
                method=method,
                url=url,
                auth=self.auth,
                headers=self.headers,
                params=params,
                json=data,
                timeout=30,
            )

            return handle_api_response(response, "ServiceNow GRC")

        except requests.exceptions.Timeout:
            raise APIError("ServiceNow GRC request timed out")
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to ServiceNow instance")

    def query_grc_controls(
        self,
        table: str = "sn_grc_control",
        filters: Optional[Dict[str, str]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query GRC controls from ServiceNow.

        Args:
            table: GRC table name (default: sn_grc_control)
            filters: Dictionary of field filters (e.g., {'framework': 'NIST', 'status': 'Active'})
            limit: Maximum number of results

        Returns:
            List of control dictionaries

        Example:
            >>> adapter = ServiceNowGRCAdapter()
            >>> controls = adapter.query_grc_controls(
            ...     filters={'framework': 'NIST SP 800-53'},
            ...     limit=50
            ... )
        """
        log_api_call("servicenow_grc", "query_grc_controls", {"table": table, "filters": filters})

        if self.mock_mode:
            # Return mock data
            mock_controls = self._generate_mock_controls(limit)

            # Apply filters if provided
            if filters:
                filtered = []
                for control in mock_controls:
                    match = True
                    for key, value in filters.items():
                        if control.get(key) != value:
                            match = False
                            break
                    if match:
                        filtered.append(control)
                mock_controls = filtered

            logger.info(f"Mock query returned {len(mock_controls)} GRC controls")
            return mock_controls

        # Real API call
        url = self._build_url(table)
        params = {
            "sysparm_limit": limit,
            "sysparm_display_value": "true",
        }

        # Build query string from filters
        if filters:
            query_parts = [f"{k}={v}" for k, v in filters.items()]
            params["sysparm_query"] = "^".join(query_parts)

        response = self._make_request("GET", url, params=params)
        controls = response.get("result", [])

        logger.info(f"Retrieved {len(controls)} GRC controls from ServiceNow")
        return controls

    def get_control_details(self, sys_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific GRC control.

        Args:
            sys_id: ServiceNow sys_id of the control

        Returns:
            Control details dictionary or None if not found
        """
        log_api_call("servicenow_grc", "get_control_details", {"sys_id": sys_id})

        if self.mock_mode:
            # Return mock control details
            mock_controls = self._generate_mock_controls(limit=10)
            for control in mock_controls:
                if control["sys_id"] == sys_id:
                    logger.info(f"Mock control details retrieved for {sys_id}")
                    return control
            logger.warning(f"Mock control {sys_id} not found")
            return None

        # Real API call
        url = f"{self._build_url('sn_grc_control')}/{sys_id}"
        params = {"sysparm_display_value": "true"}

        try:
            response = self._make_request("GET", url, params=params)
            control = response.get("result", {})

            logger.info(f"Retrieved control details for {sys_id}")
            return control

        except APIError as e:
            if "404" in str(e):
                logger.warning(f"Control {sys_id} not found")
                return None
            raise

    def get_control_tests(self, control_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get all test records for a specific GRC control.

        Args:
            control_id: Control number or sys_id
            limit: Maximum number of test records to return

        Returns:
            List of control test dictionaries
        """
        log_api_call("servicenow_grc", "get_control_tests", {"control_id": control_id})

        if self.mock_mode:
            # Return mock test results
            mock_tests = [
                {
                    "sys_id": f"test_{control_id}_001",
                    "control": control_id,
                    "test_date": "2024-02-15",
                    "test_result": "Passed",
                    "tester": "Security Auditor",
                    "notes": "All requirements met. Evidence reviewed and verified.",
                    "evidence_collected": True,
                    "score": 95,
                },
                {
                    "sys_id": f"test_{control_id}_002",
                    "control": control_id,
                    "test_date": "2024-01-15",
                    "test_result": "Passed",
                    "tester": "Compliance Team",
                    "notes": "Control operating effectively.",
                    "evidence_collected": True,
                    "score": 92,
                },
            ]
            logger.info(f"Mock query returned {len(mock_tests)} test records")
            return mock_tests[:limit]

        # Real API call
        url = self._build_url("sn_grc_control_test")
        params = {
            "sysparm_query": f"control={control_id}",
            "sysparm_limit": limit,
            "sysparm_display_value": "true",
            "sysparm_order_by": "^ORDERBYDESCtest_date",
        }

        response = self._make_request("GET", url, params=params)
        tests = response.get("result", [])

        logger.info(f"Retrieved {len(tests)} test records for control {control_id}")
        return tests

    def get_controls_by_framework(
        self,
        framework: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get all controls for a specific framework.

        Args:
            framework: Framework name (e.g., 'NIST SP 800-53', 'CIS Controls v8', 'ISO 27001:2022')
            limit: Maximum number of results

        Returns:
            List of control dictionaries
        """
        log_api_call("servicenow_grc", "get_controls_by_framework", {"framework": framework})

        return self.query_grc_controls(
            filters={"framework": framework},
            limit=limit,
        )

    def get_implemented_controls(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all controls with 'Implemented' status.

        Args:
            limit: Maximum number of results

        Returns:
            List of implemented control dictionaries
        """
        log_api_call("servicenow_grc", "get_implemented_controls", {})

        return self.query_grc_controls(
            filters={"implementation_status": "Implemented"},
            limit=limit,
        )

    def search_controls(self, search_term: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for controls by name or description.

        Args:
            search_term: Search keyword
            limit: Maximum number of results

        Returns:
            List of matching control dictionaries
        """
        log_api_call("servicenow_grc", "search_controls", {"search_term": search_term})

        if self.mock_mode:
            # Return filtered mock controls
            mock_controls = self._generate_mock_controls(limit=10)
            filtered = [
                c for c in mock_controls
                if search_term.lower() in c["name"].lower()
                or search_term.lower() in c["description"].lower()
            ]
            logger.info(f"Mock search returned {len(filtered)} controls")
            return filtered[:limit]

        # Real API call with text search
        url = self._build_url("sn_grc_control")
        params = {
            "sysparm_query": f"nameLIKE{search_term}^ORdescriptionLIKE{search_term}",
            "sysparm_limit": limit,
            "sysparm_display_value": "true",
        }

        response = self._make_request("GET", url, params=params)
        controls = response.get("result", [])

        logger.info(f"Search returned {len(controls)} controls")
        return controls

    def get_control_effectiveness(self, sys_id: str) -> Optional[float]:
        """Get effectiveness score for a control.

        Args:
            sys_id: Control sys_id

        Returns:
            Effectiveness score (0-100) or None if not available
        """
        control = self.get_control_details(sys_id)

        if not control:
            return None

        try:
            score = float(control.get("effectiveness_score", 0))
            return score
        except (ValueError, TypeError):
            logger.warning(f"Invalid effectiveness score for control {sys_id}")
            return None
