"""NVD (National Vulnerability Database) API client for CVE details.

This client queries the NVD API v2.0 for CVE vulnerability data including
CVSS scores, descriptions, and affected products.

Rate Limits: 5 requests per 30 seconds (free tier), 50 requests per 30 seconds (with API key)
"""

import sys
from pathlib import Path

# Ensure src is in path for absolute imports
_src_path = str(Path(__file__).parent.parent)
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

import os
import time
import requests
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
import logging

from utils.error_handler import (
    handle_api_response,
    retry_on_rate_limit,
    APIRateLimiter,
    log_api_call,
    APIError,
)
from models.schemas import CVEDetail

load_dotenv()
logger = logging.getLogger(__name__)


class NVDClient:
    """Client for NVD API v2.0.

    Provides methods to query CVE details, CVSS scores, and affected products
    with automatic rate limiting and retry logic.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        """Initialize NVD client.

        Args:
            api_key: NVD API key (optional, but recommended for higher rate limits)
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")

        # Set up rate limiter based on API key availability
        if self.api_key:
            # With API key: 50 requests per 30 seconds
            self.rate_limiter = APIRateLimiter(calls_per_period=50, period_seconds=30)
            logger.info("NVD client initialized with API key (50 req/30s)")
        else:
            # Without API key: 5 requests per 30 seconds
            self.rate_limiter = APIRateLimiter(calls_per_period=5, period_seconds=30)
            logger.warning("NVD client initialized without API key (5 req/30s)")

        self.headers = {"Accept": "application/json"}
        if self.api_key:
            self.headers["apiKey"] = self.api_key

    @retry_on_rate_limit(max_attempts=5)
    def _make_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make request to NVD API with rate limiting.

        Args:
            params: Query parameters

        Returns:
            JSON response data

        Raises:
            APIError: If request fails
        """
        with self.rate_limiter:
            log_api_call("NVD", self.BASE_URL, params)

            try:
                response = requests.get(
                    self.BASE_URL, headers=self.headers, params=params, timeout=30
                )

                return handle_api_response(response, "NVD")

            except requests.exceptions.Timeout:
                raise APIError("NVD API request timed out")
            except requests.exceptions.ConnectionError:
                raise APIError("Failed to connect to NVD API")

    def get_cve(self, cve_id: str) -> Optional[CVEDetail]:
        """Get details for a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            CVEDetail object or None if not found

        Example:
            >>> client = NVDClient()
            >>> cve = client.get_cve("CVE-2024-1234")
            >>> if cve:
            ...     print(f"{cve.cve_id}: {cve.cvss_score} - {cve.description}")
        """
        params = {"cveId": cve_id.upper()}

        try:
            response = self._make_request(params)

            vulnerabilities = response.get("vulnerabilities", [])
            if not vulnerabilities:
                logger.warning(f"CVE {cve_id} not found in NVD")
                return None

            # Parse first (and should be only) result
            vuln_data = vulnerabilities[0].get("cve", {})

            # Extract CVSS data (prefer v3.1, fall back to v3.0, then v2.0)
            cvss_score = None
            cvss_severity = None

            metrics = vuln_data.get("metrics", {})
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                # Map v2 score to severity
                if cvss_score:
                    if cvss_score >= 7.0:
                        cvss_severity = "HIGH"
                    elif cvss_score >= 4.0:
                        cvss_severity = "MEDIUM"
                    else:
                        cvss_severity = "LOW"

            # Extract description
            descriptions = vuln_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CPE matches (affected products)
            cpe_matches = []
            configurations = vuln_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            cpe_matches.append(cpe_match.get("criteria", ""))

            # Extract references
            references = []
            for ref in vuln_data.get("references", []):
                references.append(ref.get("url", ""))

            # Create CVEDetail object
            cve_detail = CVEDetail(
                cve_id=cve_id.upper(),
                description=description,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                published_date=vuln_data.get("published"),
                last_modified=vuln_data.get("lastModified"),
                cpe_matches=cpe_matches[:10],  # Limit to first 10
                references=references[:10],  # Limit to first 10
            )

            logger.info(f"Retrieved CVE {cve_id}: {cvss_severity} ({cvss_score})")
            return cve_detail

        except APIError as e:
            logger.error(f"Error retrieving CVE {cve_id}: {e}")
            return None

    def get_multiple_cves(self, cve_ids: List[str]) -> Dict[str, Optional[CVEDetail]]:
        """Get details for multiple CVEs.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE ID to CVEDetail (or None if not found)

        Example:
            >>> client = NVDClient()
            >>> cves = client.get_multiple_cves(["CVE-2024-1234", "CVE-2024-5678"])
            >>> for cve_id, cve in cves.items():
            ...     if cve:
            ...         print(f"{cve_id}: {cve.cvss_score}")
        """
        results = {}

        for cve_id in cve_ids:
            results[cve_id] = self.get_cve(cve_id)

        return results

    def search_cves(
        self,
        keyword: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        results_per_page: int = 20,
    ) -> List[CVEDetail]:
        """Search for CVEs by keyword or severity.

        Args:
            keyword: Keyword to search in CVE descriptions
            cvss_v3_severity: Filter by CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)
            results_per_page: Number of results per page (max 2000)

        Returns:
            List of CVEDetail objects

        Example:
            >>> client = NVDClient()
            >>> cves = client.search_cves(keyword="apache", cvss_v3_severity="CRITICAL")
            >>> print(f"Found {len(cves)} critical CVEs related to apache")
        """
        params = {"resultsPerPage": min(results_per_page, 2000)}

        if keyword:
            params["keywordSearch"] = keyword
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity.upper()

        try:
            response = self._make_request(params)

            vulnerabilities = response.get("vulnerabilities", [])
            cve_details = []

            for vuln in vulnerabilities:
                vuln_data = vuln.get("cve", {})
                cve_id = vuln_data.get("id", "")

                # Use get_cve to parse details (this will use rate limiter)
                cve_detail = self.get_cve(cve_id)
                if cve_detail:
                    cve_details.append(cve_detail)

            logger.info(f"Found {len(cve_details)} CVEs matching search criteria")
            return cve_details

        except APIError as e:
            logger.error(f"Error searching CVEs: {e}")
            return []

    def get_recent_cves(self, days: int = 7, severity: Optional[str] = None) -> List[CVEDetail]:
        """Get recently published CVEs.

        Args:
            days: Number of days to look back
            severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)

        Returns:
            List of CVEDetail objects

        Example:
            >>> client = NVDClient()
            >>> recent = client.get_recent_cves(days=7, severity="CRITICAL")
            >>> print(f"Found {len(recent)} critical CVEs in last 7 days")
        """
        from datetime import datetime, timedelta

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
        }

        if severity:
            params["cvssV3Severity"] = severity.upper()

        try:
            response = self._make_request(params)

            vulnerabilities = response.get("vulnerabilities", [])
            cve_details = []

            for vuln in vulnerabilities:
                vuln_data = vuln.get("cve", {})
                cve_id = vuln_data.get("id", "")

                cve_detail = self.get_cve(cve_id)
                if cve_detail:
                    cve_details.append(cve_detail)

            logger.info(f"Found {len(cve_details)} recent CVEs")
            return cve_details

        except APIError as e:
            logger.error(f"Error retrieving recent CVEs: {e}")
            return []
