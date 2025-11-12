"""VirusTotal API client for checking vulnerability exploitation status.

This client queries VirusTotal API v3 to check if exploits or malware samples
related to CVEs have been detected.

Rate Limits: 4 requests per minute (free tier), 1000 requests per day
"""

import os
import time
import requests
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
import logging

from ..utils.error_handler import (
    handle_api_response,
    retry_on_rate_limit,
    APIRateLimiter,
    log_api_call,
    APIError,
    validate_api_key,
)

load_dotenv()
logger = logging.getLogger(__name__)


class VirusTotalClient:
    """Client for VirusTotal API v3.

    Provides methods to check if CVEs have associated exploits or malware samples
    detected by VirusTotal.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        """Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key (required)

        Raises:
            ValidationError: If API key is not provided
        """
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        validate_api_key(self.api_key, "VirusTotal")

        # Rate limiter: 4 requests per minute for free tier
        self.rate_limiter = APIRateLimiter(calls_per_period=4, period_seconds=60)

        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        logger.info("VirusTotal client initialized (4 req/min)")

    @retry_on_rate_limit(max_attempts=5, min_wait=15)
    def _make_request(self, endpoint: str, method: str = "GET", params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make request to VirusTotal API with rate limiting.

        Args:
            endpoint: API endpoint path
            method: HTTP method (GET, POST)
            params: Query parameters

        Returns:
            JSON response data

        Raises:
            APIError: If request fails
        """
        with self.rate_limiter:
            url = f"{self.BASE_URL}/{endpoint}"
            log_api_call("VirusTotal", url, params)

            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=self.headers,
                    params=params,
                    timeout=30,
                )

                return handle_api_response(response, "VirusTotal")

            except requests.exceptions.Timeout:
                raise APIError("VirusTotal API request timed out")
            except requests.exceptions.ConnectionError:
                raise APIError("Failed to connect to VirusTotal API")

    def search_cve(self, cve_id: str) -> Dict[str, Any]:
        """Search VirusTotal for files/URLs related to a CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            Dictionary with search results including detection count

        Example:
            >>> client = VirusTotalClient()
            >>> result = client.search_cve("CVE-2024-1234")
            >>> print(f"Detections: {result['detection_count']}")
        """
        # Search for the CVE in VirusTotal's database
        endpoint = "search"
        params = {"query": cve_id}

        try:
            response = self._make_request(endpoint, params=params)

            data = response.get("data", [])
            detection_count = len(data)

            # Aggregate detection statistics
            total_detections = 0
            malicious_count = 0

            for item in data:
                attributes = item.get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})

                malicious = last_analysis_stats.get("malicious", 0)
                total_detections += malicious
                if malicious > 0:
                    malicious_count += 1

            result = {
                "cve_id": cve_id,
                "detection_count": detection_count,
                "malicious_count": malicious_count,
                "total_detections": total_detections,
                "samples": data[:5],  # Keep first 5 samples for reference
            }

            logger.info(
                f"VirusTotal search for {cve_id}: {detection_count} samples, "
                f"{malicious_count} malicious"
            )
            return result

        except APIError as e:
            logger.error(f"Error searching VirusTotal for {cve_id}: {e}")
            return {
                "cve_id": cve_id,
                "detection_count": 0,
                "malicious_count": 0,
                "total_detections": 0,
                "samples": [],
                "error": str(e),
            }

    def check_exploitation(self, cve_id: str) -> Dict[str, Any]:
        """Check if a CVE has known exploits in VirusTotal.

        Args:
            cve_id: CVE identifier

        Returns:
            Dictionary with exploitation status

        Example:
            >>> client = VirusTotalClient()
            >>> status = client.check_exploitation("CVE-2024-1234")
            >>> if status['exploit_detected']:
            ...     print(f"Exploit detected with {status['detection_count']} samples")
        """
        search_result = self.search_cve(cve_id)

        # Determine exploitation status based on detections
        exploit_detected = search_result["malicious_count"] > 0
        confidence = "high" if search_result["malicious_count"] >= 3 else "medium" if search_result["malicious_count"] > 0 else "low"

        result = {
            "cve_id": cve_id,
            "exploit_detected": exploit_detected,
            "detection_count": search_result["detection_count"],
            "malicious_count": search_result["malicious_count"],
            "confidence": confidence,
            "evidence": f"Found {search_result['malicious_count']} malicious samples" if exploit_detected else "No malicious samples found",
        }

        return result

    def check_multiple_cves(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Check exploitation status for multiple CVEs.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE ID to exploitation status

        Example:
            >>> client = VirusTotalClient()
            >>> results = client.check_multiple_cves(["CVE-2024-1234", "CVE-2024-5678"])
            >>> for cve_id, status in results.items():
            ...     print(f"{cve_id}: {'Exploited' if status['exploit_detected'] else 'Not exploited'}")
        """
        results = {}

        for cve_id in cve_ids:
            results[cve_id] = self.check_exploitation(cve_id)
            # Small delay to avoid rate limiting
            time.sleep(0.5)

        return results

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Get analysis report for a file by hash.

        Args:
            file_hash: File hash (MD5, SHA-1, or SHA-256)

        Returns:
            File analysis report

        Example:
            >>> client = VirusTotalClient()
            >>> report = client.get_file_report("44d88612fea8a8f36de82e1278abb02f")
        """
        endpoint = f"files/{file_hash}"

        try:
            response = self._make_request(endpoint)
            return response.get("data", {})

        except APIError as e:
            logger.error(f"Error getting file report for {file_hash}: {e}")
            return {"error": str(e)}

    def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get analysis report for a URL.

        Args:
            url: URL to check

        Returns:
            URL analysis report
        """
        import base64

        # VirusTotal expects URL identifier (base64 of URL without padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"urls/{url_id}"

        try:
            response = self._make_request(endpoint)
            return response.get("data", {})

        except APIError as e:
            logger.error(f"Error getting URL report for {url}: {e}")
            return {"error": str(e)}
