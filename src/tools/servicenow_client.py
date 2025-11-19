"""ServiceNow REST API client for querying incidents, CMDB, and security data.

This client provides methods to interact with ServiceNow Personal Developer Instance (PDI)
including incident management, CMDB queries, and security exception tracking.
"""

import sys
from pathlib import Path

# Ensure src is in path for absolute imports
_src_path = str(Path(__file__).parent.parent)
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

import os
import requests
from typing import List, Dict, Optional, Any
from dotenv import load_dotenv
import logging

from utils.error_handler import (
    handle_api_response,
    retry_on_api_error,
    validate_api_key,
    log_api_call,
    APIError,
)
from models.schemas import ServiceNowIncident, CMDBItem

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


class ServiceNowClient:
    """Client for ServiceNow REST API interactions.

    Provides methods for querying incidents, CMDB assets, and creating incidents
    with comprehensive error handling and retry logic.
    """

    def __init__(
        self,
        instance_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """Initialize ServiceNow client.

        Args:
            instance_url: ServiceNow instance URL (e.g., https://dev12345.service-now.com)
            username: ServiceNow username
            password: ServiceNow password

        Raises:
            ValidationError: If required credentials are missing
        """
        self.instance_url = instance_url or os.getenv("SERVICENOW_INSTANCE")
        self.username = username or os.getenv("SERVICENOW_USERNAME")
        self.password = password or os.getenv("SERVICENOW_PASSWORD")

        # Validate credentials
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

        logger.info(f"ServiceNow client initialized for instance: {self.instance_url}")

    def _build_url(self, table: str) -> str:
        """Build API endpoint URL for a table.

        Args:
            table: ServiceNow table name (e.g., 'incident', 'cmdb_ci_server')

        Returns:
            Full API endpoint URL
        """
        return f"{self.instance_url}/api/now/table/{table}"

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
        log_api_call("ServiceNow", url, params)

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

            return handle_api_response(response, "ServiceNow")

        except requests.exceptions.Timeout:
            raise APIError("ServiceNow request timed out")
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to ServiceNow instance")

    # ========================================================================
    # Incident Management
    # ========================================================================

    def query_incidents(
        self,
        priority: Optional[str] = None,
        state: Optional[str] = None,
        limit: int = 100,
        query: Optional[str] = None,
    ) -> List[ServiceNowIncident]:
        """Query incidents from ServiceNow.

        Args:
            priority: Filter by priority (1-5)
            state: Filter by state (e.g., 'New', 'In Progress')
            limit: Maximum number of results
            query: Custom query string (sysparm_query format)

        Returns:
            List of ServiceNowIncident objects

        Example:
            >>> client = ServiceNowClient()
            >>> incidents = client.query_incidents(priority="1", limit=10)
            >>> for inc in incidents:
            ...     print(f"{inc.number}: {inc.short_description}")
        """
        url = self._build_url("incident")

        # Build query parameters
        params = {
            "sysparm_limit": limit,
            "sysparm_display_value": "true",
        }

        # Build query string
        query_parts = []
        if priority:
            query_parts.append(f"priority={priority}")
        if state:
            query_parts.append(f"state={state}")
        if query:
            query_parts.append(query)

        if query_parts:
            params["sysparm_query"] = "^".join(query_parts)

        # Make request
        response = self._make_request("GET", url, params=params)

        # Parse results into models
        incidents = []
        for item in response.get("result", []):
            try:
                incident = ServiceNowIncident(
                    number=item.get("number", ""),
                    short_description=item.get("short_description", ""),
                    description=item.get("description"),
                    priority=item.get("priority", ""),
                    state=item.get("state", ""),
                    assigned_to=item.get("assigned_to", {}).get("display_value")
                    if isinstance(item.get("assigned_to"), dict)
                    else item.get("assigned_to"),
                    sys_created_on=item.get("sys_created_on", ""),
                    sys_updated_on=item.get("sys_updated_on", ""),
                    sys_id=item.get("sys_id", ""),
                )
                incidents.append(incident)
            except Exception as e:
                logger.warning(f"Failed to parse incident: {e}")
                continue

        logger.info(f"Retrieved {len(incidents)} incidents from ServiceNow")
        return incidents

    def get_incident(self, incident_number: str) -> Optional[ServiceNowIncident]:
        """Get a specific incident by number.

        Args:
            incident_number: Incident number (e.g., 'INC0010001')

        Returns:
            ServiceNowIncident object or None if not found
        """
        incidents = self.query_incidents(query=f"number={incident_number}", limit=1)
        return incidents[0] if incidents else None

    def create_incident(
        self,
        short_description: str,
        description: Optional[str] = None,
        priority: str = "3",
        caller_id: Optional[str] = None,
    ) -> ServiceNowIncident:
        """Create a new incident in ServiceNow.

        Args:
            short_description: Brief description
            description: Detailed description
            priority: Priority level (1-5, default 3)
            caller_id: Caller user ID

        Returns:
            Created ServiceNowIncident object

        Example:
            >>> client = ServiceNowClient()
            >>> incident = client.create_incident(
            ...     short_description="CVE-2024-12345 detected",
            ...     description="Critical vulnerability detected in production server",
            ...     priority="1"
            ... )
            >>> print(f"Created incident: {incident.number}")
        """
        url = self._build_url("incident")

        data = {
            "short_description": short_description,
            "priority": priority,
        }

        if description:
            data["description"] = description
        if caller_id:
            data["caller_id"] = caller_id

        response = self._make_request("POST", url, data=data)
        result = response.get("result", {})

        incident = ServiceNowIncident(
            number=result.get("number", ""),
            short_description=result.get("short_description", ""),
            description=result.get("description"),
            priority=result.get("priority", ""),
            state=result.get("state", ""),
            assigned_to=result.get("assigned_to"),
            sys_created_on=result.get("sys_created_on", ""),
            sys_updated_on=result.get("sys_updated_on", ""),
            sys_id=result.get("sys_id", ""),
        )

        logger.info(f"Created incident: {incident.number}")
        return incident

    # ========================================================================
    # CMDB Management
    # ========================================================================

    def query_cmdb(
        self,
        asset_class: Optional[str] = None,
        name: Optional[str] = None,
        limit: int = 100,
        query: Optional[str] = None,
    ) -> List[CMDBItem]:
        """Query Configuration Management Database (CMDB) for assets.

        Args:
            asset_class: Filter by asset class (e.g., 'cmdb_ci_server', 'cmdb_ci_computer')
            name: Filter by asset name (partial match)
            limit: Maximum number of results
            query: Custom query string

        Returns:
            List of CMDBItem objects

        Example:
            >>> client = ServiceNowClient()
            >>> servers = client.query_cmdb(asset_class="cmdb_ci_server", limit=10)
            >>> for server in servers:
            ...     print(f"{server.name}: {server.ip_address}")
        """
        # Default to querying all CI tables if no class specified
        table = asset_class or "cmdb_ci"
        url = self._build_url(table)

        # Build query parameters
        params = {
            "sysparm_limit": limit,
            "sysparm_display_value": "true",
        }

        # Build query string
        query_parts = []
        if name:
            query_parts.append(f"nameLIKE{name}")
        if query:
            query_parts.append(query)

        if query_parts:
            params["sysparm_query"] = "^".join(query_parts)

        # Make request
        response = self._make_request("GET", url, params=params)

        # Parse results into models
        cmdb_items = []
        for item in response.get("result", []):
            try:
                cmdb_item = CMDBItem(
                    name=item.get("name", ""),
                    sys_class_name=item.get("sys_class_name", ""),
                    sys_id=item.get("sys_id", ""),
                    ip_address=item.get("ip_address"),
                    dns_domain=item.get("dns_domain"),
                    operational_status=item.get("operational_status"),
                )
                cmdb_items.append(cmdb_item)
            except Exception as e:
                logger.warning(f"Failed to parse CMDB item: {e}")
                continue

        logger.info(f"Retrieved {len(cmdb_items)} CMDB items from ServiceNow")
        return cmdb_items

    def get_asset(self, asset_name: str) -> Optional[CMDBItem]:
        """Get a specific asset by name.

        Args:
            asset_name: Asset name

        Returns:
            CMDBItem object or None if not found
        """
        items = self.query_cmdb(query=f"name={asset_name}", limit=1)
        return items[0] if items else None

    # ========================================================================
    # Security Exception Management
    # ========================================================================

    def query_security_exceptions(
        self,
        state: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Query security exceptions (risk acceptances).

        Note: This may require Security Incident Response plugin in ServiceNow.
        Falls back to custom table if available.

        Args:
            state: Filter by state (e.g., 'Approved', 'Pending')
            limit: Maximum number of results

        Returns:
            List of security exception dictionaries

        Example:
            >>> client = ServiceNowClient()
            >>> exceptions = client.query_security_exceptions(state="Approved")
            >>> for exc in exceptions:
            ...     print(f"{exc.get('number')}: {exc.get('short_description')}")
        """
        # Try security incident table first, fall back to regular incident table
        # with security-related filters
        url = self._build_url("incident")

        params = {
            "sysparm_limit": limit,
            "sysparm_display_value": "true",
        }

        # Query for incidents with "security exception" or "risk acceptance" in description
        query_parts = [
            "short_descriptionLIKEsecurity exception^ORshort_descriptionLIKErisk acceptance"
        ]

        if state:
            query_parts.append(f"state={state}")

        params["sysparm_query"] = "^".join(query_parts)

        try:
            response = self._make_request("GET", url, params=params)
            exceptions = response.get("result", [])
            logger.info(f"Retrieved {len(exceptions)} security exceptions")
            return exceptions
        except APIError as e:
            logger.warning(f"Failed to query security exceptions: {e}")
            return []

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def test_connection(self) -> bool:
        """Test connection to ServiceNow instance.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            url = self._build_url("incident")
            params = {"sysparm_limit": 1}
            self._make_request("GET", url, params=params)
            logger.info("ServiceNow connection test successful")
            return True
        except Exception as e:
            logger.error(f"ServiceNow connection test failed: {e}")
            return False

    def get_table_schema(self, table: str) -> Dict[str, Any]:
        """Get schema information for a table.

        Args:
            table: Table name

        Returns:
            Schema information dictionary
        """
        url = f"{self.instance_url}/api/now/table/sys_dictionary"
        params = {
            "sysparm_query": f"name={table}",
            "sysparm_limit": 100,
        }

        try:
            response = self._make_request("GET", url, params=params)
            return response.get("result", [])
        except APIError as e:
            logger.error(f"Failed to get schema for table {table}: {e}")
            return {}
