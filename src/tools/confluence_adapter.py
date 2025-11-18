"""Confluence REST API adapter for control discovery.

This adapter provides methods to search and extract security controls from
Confluence wiki pages. Supports mocked responses for testing and development.
"""

import os
import re
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from dotenv import load_dotenv

from ..utils.error_handler import (
    handle_api_response,
    retry_on_api_error,
    log_api_call,
    APIError,
)

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


class ConfluenceAdapter:
    """Adapter for Confluence REST API interactions.

    Provides methods for searching wiki pages and extracting security controls
    from Confluence content. Uses mock data by default for testing.
    """

    def __init__(
        self,
        instance_url: Optional[str] = None,
        username: Optional[str] = None,
        api_token: Optional[str] = None,
        mock_mode: bool = True,
    ):
        """Initialize Confluence adapter.

        Args:
            instance_url: Confluence instance URL (e.g., https://yourcompany.atlassian.net)
            username: Confluence username (email)
            api_token: Confluence API token
            mock_mode: If True, use mock data instead of real API calls

        Raises:
            ValueError: If required credentials are missing and not in mock mode
        """
        self.instance_url = instance_url or os.getenv("CONFLUENCE_INSTANCE")
        self.username = username or os.getenv("CONFLUENCE_USERNAME")
        self.api_token = api_token or os.getenv("CONFLUENCE_API_TOKEN")
        self.mock_mode = mock_mode

        if not self.mock_mode:
            # Validate credentials for real API calls
            if not self.instance_url:
                raise ValueError("Confluence instance URL is required")
            if not self.username:
                raise ValueError("Confluence username is required")
            if not self.api_token:
                raise ValueError("Confluence API token is required")

            # Remove trailing slash from instance URL
            self.instance_url = self.instance_url.rstrip("/")

            # Set up authentication
            self.auth = (self.username, self.api_token)

            # Base headers for all requests
            self.headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            logger.info(f"Confluence adapter initialized for instance: {self.instance_url}")
        else:
            logger.info("Confluence adapter initialized in MOCK mode")

    def _build_url(self, endpoint: str) -> str:
        """Build API endpoint URL.

        Args:
            endpoint: API endpoint path

        Returns:
            Full API endpoint URL
        """
        return f"{self.instance_url}/rest/api/{endpoint}"

    def _extract_control_from_text(self, text: str, source_page: str = "") -> List[Dict[str, Any]]:
        """Extract security control references from text using regex.

        Args:
            text: Text content to parse
            source_page: Source page ID or title for metadata

        Returns:
            List of control dictionaries with metadata
        """
        controls = []

        # Regex patterns for different control frameworks
        patterns = {
            "NIST SP 800-53": r"NIST\s+(AC|AU|AT|CA|CM|CP|IA|IR|MA|MP|PE|PL|PS|RA|SA|SC|SI|SR|PM)-(\d+)",
            "CIS Controls v8": r"CIS\s+(\d+)\.(\d+)",
            "ISO 27001:2022": r"ISO\s+A\.(\d+)\.(\d+)",
        }

        for framework, pattern in patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                if framework == "NIST SP 800-53":
                    control_id = f"NIST-{match.group(1)}-{match.group(2)}"
                elif framework == "CIS Controls v8":
                    control_id = f"CIS-{match.group(1)}.{match.group(2)}"
                else:  # ISO 27001
                    control_id = f"ISO-A.{match.group(1)}.{match.group(2)}"

                # Extract context around the match (up to 200 chars)
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                context = text[start:end].strip()

                controls.append({
                    "id": control_id,
                    "framework": framework,
                    "source": "confluence",
                    "source_page": source_page,
                    "context": context,
                    "discovered_at": datetime.utcnow().isoformat(),
                })

        return controls

    def _generate_mock_page_content(self, space_key: str, page_id: str) -> str:
        """Generate mock Confluence page content for testing.

        Args:
            space_key: Confluence space key
            page_id: Page ID

        Returns:
            Mock page content with control references
        """
        mock_pages = {
            "SEC-001": """
            # Security Controls Implementation Guide

            This page documents the implementation of NIST SP 800-53 controls for our organization.

            ## Access Control (AC)

            - **NIST AC-1**: Access Control Policy and Procedures - Implemented with security policy documentation
            - **NIST AC-2**: Account Management - Automated through Active Directory
            - **NIST AC-3**: Access Enforcement - Role-based access control implemented
            - **NIST AC-6**: Least Privilege - Enforced through permission reviews

            ## Audit and Accountability (AU)

            - **NIST AU-2**: Audit Events - Comprehensive logging enabled
            - **NIST AU-6**: Audit Review and Analysis - Weekly SIEM reviews conducted

            ## Configuration Management (CM)

            - **NIST CM-2**: Baseline Configuration - Configuration baselines documented
            - **NIST CM-6**: Configuration Settings - Security hardening applied
            """,
            "SEC-002": """
            # CIS Controls Implementation Status

            ## Control Family 1: Inventory and Control of Enterprise Assets

            - **CIS 1.1**: Establish and Maintain Detailed Enterprise Asset Inventory - IMPLEMENTED
            - **CIS 1.2**: Address Unauthorized Assets - IMPLEMENTED
            - **CIS 1.3**: Utilize an Active Discovery Tool - PARTIALLY IMPLEMENTED

            ## Control Family 5: Account Management

            - **CIS 5.1**: Establish and Maintain an Inventory of Accounts - IMPLEMENTED
            - **CIS 5.2**: Use Unique Passwords - IMPLEMENTED
            - **CIS 5.3**: Disable Dormant Accounts - IMPLEMENTED

            ## Control Family 6: Access Control Management

            - **CIS 6.3**: Require MFA for Externally-Exposed Applications - IMPLEMENTED
            - **CIS 6.4**: Require MFA for Remote Network Access - IMPLEMENTED
            """,
            "SEC-003": """
            # ISO 27001:2022 Compliance Matrix

            ## A.5 Organizational Controls

            - **ISO A.5.1**: Policies for Information Security - Policy documents approved
            - **ISO A.5.2**: Information Security Roles and Responsibilities - Roles defined

            ## A.8 Technological Controls

            - **ISO A.8.2**: Privileged Access Rights - PAM solution implemented
            - **ISO A.8.3**: Information Access Restriction - Access controls enforced
            - **ISO A.8.5**: Secure Authentication - MFA enabled for all users
            - **ISO A.8.7**: Protection Against Malware - Endpoint protection deployed
            - **ISO A.8.15**: Logging - Centralized logging infrastructure
            """,
        }

        return mock_pages.get(page_id, "# Empty Page\n\nNo controls found.")

    @retry_on_api_error(max_attempts=3)
    def search_pages(
        self,
        space: str,
        query: str = "security controls",
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """Search for Confluence pages in a space.

        Args:
            space: Confluence space key (e.g., 'SEC', 'COMP')
            query: Search query string
            limit: Maximum number of results to return

        Returns:
            List of page metadata dictionaries

        Raises:
            APIError: If API call fails
        """
        log_api_call("confluence", "search_pages", {"space": space, "query": query})

        if self.mock_mode:
            # Return mock search results
            mock_results = [
                {
                    "id": "SEC-001",
                    "title": "Security Controls Implementation Guide",
                    "space": {"key": space},
                    "type": "page",
                    "status": "current",
                    "url": f"https://mock.atlassian.net/wiki/spaces/{space}/pages/SEC-001",
                },
                {
                    "id": "SEC-002",
                    "title": "CIS Controls Implementation Status",
                    "space": {"key": space},
                    "type": "page",
                    "status": "current",
                    "url": f"https://mock.atlassian.net/wiki/spaces/{space}/pages/SEC-002",
                },
                {
                    "id": "SEC-003",
                    "title": "ISO 27001:2022 Compliance Matrix",
                    "space": {"key": space},
                    "type": "page",
                    "status": "current",
                    "url": f"https://mock.atlassian.net/wiki/spaces/{space}/pages/SEC-003",
                },
            ]
            logger.info(f"Mock search returned {len(mock_results)} pages")
            return mock_results[:limit]

        # Real API call implementation would go here
        import requests

        url = self._build_url("content/search")
        params = {
            "cql": f"space = {space} and text ~ \"{query}\"",
            "limit": limit,
        }

        try:
            response = requests.get(
                url,
                auth=self.auth,
                headers=self.headers,
                params=params,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            results = data.get("results", [])
            logger.info(f"Found {len(results)} pages matching query")
            return results

        except requests.exceptions.RequestException as e:
            logger.error(f"Confluence API error: {str(e)}")
            raise APIError(f"Failed to search Confluence pages: {str(e)}")

    @retry_on_api_error(max_attempts=3)
    def get_page_content(self, page_id: str, expand: str = "body.storage") -> Dict[str, Any]:
        """Get full content of a Confluence page.

        Args:
            page_id: Confluence page ID
            expand: Fields to expand (default: body.storage for page content)

        Returns:
            Page content dictionary with metadata

        Raises:
            APIError: If API call fails
        """
        log_api_call("confluence", "get_page_content", {"page_id": page_id})

        if self.mock_mode:
            # Return mock page content
            content = self._generate_mock_page_content("SEC", page_id)
            mock_page = {
                "id": page_id,
                "title": f"Page {page_id}",
                "type": "page",
                "status": "current",
                "body": {
                    "storage": {
                        "value": content,
                        "representation": "storage",
                    }
                },
            }
            logger.info(f"Mock page content retrieved for {page_id}")
            return mock_page

        # Real API call implementation
        import requests

        url = self._build_url(f"content/{page_id}")
        params = {"expand": expand}

        try:
            response = requests.get(
                url,
                auth=self.auth,
                headers=self.headers,
                params=params,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            logger.info(f"Retrieved content for page {page_id}")
            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"Confluence API error: {str(e)}")
            raise APIError(f"Failed to get page content: {str(e)}")

    def get_space_controls(
        self,
        space_key: str,
        query: str = "security controls",
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """Get all security controls from a Confluence space.

        Args:
            space_key: Confluence space key
            query: Search query for finding control pages
            limit: Maximum number of pages to process

        Returns:
            List of control dictionaries with metadata
        """
        log_api_call("confluence", "get_space_controls", {"space": space_key})

        all_controls = []

        try:
            # Search for pages in the space
            pages = self.search_pages(space_key, query, limit)
            logger.info(f"Processing {len(pages)} pages from space {space_key}")

            # Extract controls from each page
            for page in pages:
                page_id = page["id"]
                page_title = page.get("title", "Unknown")

                try:
                    # Get page content
                    page_data = self.get_page_content(page_id)
                    content = page_data.get("body", {}).get("storage", {}).get("value", "")

                    # Extract controls from content
                    controls = self._extract_control_from_text(
                        content,
                        source_page=f"{page_title} ({page_id})",
                    )

                    all_controls.extend(controls)
                    logger.info(f"Extracted {len(controls)} controls from page {page_title}")

                except Exception as e:
                    logger.warning(f"Failed to process page {page_id}: {str(e)}")
                    continue

            logger.info(f"Total controls extracted from Confluence: {len(all_controls)}")
            return all_controls

        except Exception as e:
            logger.error(f"Failed to get space controls: {str(e)}")
            raise

    def extract_controls_from_page(self, page_id: str) -> List[Dict[str, Any]]:
        """Extract security controls from a single Confluence page.

        Args:
            page_id: Confluence page ID

        Returns:
            List of control dictionaries
        """
        log_api_call("confluence", "extract_controls_from_page", {"page_id": page_id})

        try:
            page_data = self.get_page_content(page_id)
            content = page_data.get("body", {}).get("storage", {}).get("value", "")
            page_title = page_data.get("title", "Unknown")

            controls = self._extract_control_from_text(
                content,
                source_page=f"{page_title} ({page_id})",
            )

            logger.info(f"Extracted {len(controls)} controls from page {page_id}")
            return controls

        except Exception as e:
            logger.error(f"Failed to extract controls from page: {str(e)}")
            raise
