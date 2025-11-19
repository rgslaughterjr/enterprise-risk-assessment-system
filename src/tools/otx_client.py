"""AlienVault OTX (Open Threat Exchange) API client for threat intelligence.

This client queries AlienVault OTX for threat intelligence including IOCs,
threat actor profiles, and campaign information.

Rate Limits: 10 requests per second (free tier)
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
    APIRateLimiter,
    log_api_call,
    APIError,
    validate_api_key,
)

load_dotenv()
logger = logging.getLogger(__name__)


class OTXClient:
    """Client for AlienVault OTX API.

    Provides methods to query threat intelligence including pulses (threat feeds),
    IOCs (indicators of compromise), and threat actor information.
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        """Initialize OTX client.

        Args:
            api_key: AlienVault OTX API key (required)

        Raises:
            ValidationError: If API key is not provided
        """
        self.api_key = api_key or os.getenv("ALIENVAULT_OTX_KEY")
        validate_api_key(self.api_key, "AlienVault OTX")

        # Rate limiter: 10 requests per second
        self.rate_limiter = APIRateLimiter(calls_per_period=10, period_seconds=1)

        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

        logger.info("AlienVault OTX client initialized (10 req/sec)")

    @retry_on_api_error(max_attempts=3)
    def _make_request(
        self, endpoint: str, params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make request to OTX API with rate limiting.

        Args:
            endpoint: API endpoint path
            params: Query parameters

        Returns:
            JSON response data

        Raises:
            APIError: If request fails
        """
        with self.rate_limiter:
            url = f"{self.BASE_URL}/{endpoint}"
            log_api_call("AlienVault OTX", url, params)

            try:
                response = requests.get(
                    url, headers=self.headers, params=params, timeout=30
                )

                return handle_api_response(response, "AlienVault OTX")

            except requests.exceptions.Timeout:
                raise APIError("AlienVault OTX request timed out")
            except requests.exceptions.ConnectionError:
                raise APIError("Failed to connect to AlienVault OTX")

    def search_pulses(
        self, query: str, limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Search threat intelligence pulses.

        Pulses are threat feeds containing IOCs and threat context.

        Args:
            query: Search query (CVE, malware name, threat actor, etc.)
            limit: Maximum number of results

        Returns:
            List of pulse dictionaries

        Example:
            >>> client = OTXClient()
            >>> pulses = client.search_pulses("CVE-2024-1234")
            >>> for pulse in pulses:
            ...     print(f"{pulse['name']}: {pulse['description']}")
        """
        endpoint = "search/pulses"
        params = {"q": query, "limit": limit}

        try:
            response = self._make_request(endpoint, params=params)
            results = response.get("results", [])

            logger.info(f"Found {len(results)} pulses for query '{query}'")
            return results

        except APIError as e:
            logger.error(f"Error searching pulses for '{query}': {e}")
            return []

    def get_pulse(self, pulse_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific pulse.

        Args:
            pulse_id: Pulse ID

        Returns:
            Pulse details dictionary or None if not found

        Example:
            >>> client = OTXClient()
            >>> pulse = client.get_pulse("abc123...")
            >>> if pulse:
            ...     print(f"IOCs: {len(pulse['indicators'])}")
        """
        endpoint = f"pulses/{pulse_id}"

        try:
            response = self._make_request(endpoint)
            return response

        except APIError as e:
            logger.error(f"Error getting pulse {pulse_id}: {e}")
            return None

    def get_cve_pulses(self, cve_id: str) -> List[Dict[str, Any]]:
        """Get pulses related to a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            List of pulse dictionaries related to the CVE

        Example:
            >>> client = OTXClient()
            >>> pulses = client.get_cve_pulses("CVE-2024-1234")
            >>> print(f"Found {len(pulses)} pulses about this CVE")
        """
        return self.search_pulses(cve_id)

    def get_threat_actor_pulses(self, actor_name: str) -> List[Dict[str, Any]]:
        """Get pulses related to a threat actor.

        Args:
            actor_name: Threat actor name (e.g., "APT29", "Lazarus")

        Returns:
            List of pulse dictionaries

        Example:
            >>> client = OTXClient()
            >>> pulses = client.get_threat_actor_pulses("APT29")
            >>> for pulse in pulses:
            ...     print(f"{pulse['name']}")
        """
        return self.search_pulses(actor_name)

    def extract_iocs(self, pulse: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from a pulse.

        Args:
            pulse: Pulse dictionary

        Returns:
            Dictionary mapping IOC type to list of indicators

        Example:
            >>> client = OTXClient()
            >>> pulse = client.get_pulse("abc123...")
            >>> if pulse:
            ...     iocs = client.extract_iocs(pulse)
            ...     print(f"IPs: {len(iocs['ip'])}")
            ...     print(f"Domains: {len(iocs['domain'])}")
        """
        iocs: Dict[str, List[str]] = {
            "ip": [],
            "domain": [],
            "url": [],
            "hash": [],
            "email": [],
            "file": [],
        }

        indicators = pulse.get("indicators", [])

        for indicator in indicators:
            ind_type = indicator.get("type", "").lower()
            ind_value = indicator.get("indicator", "")

            if not ind_value:
                continue

            # Map indicator types to categories
            if "ipv4" in ind_type or "ipv6" in ind_type:
                iocs["ip"].append(ind_value)
            elif "domain" in ind_type or "hostname" in ind_type:
                iocs["domain"].append(ind_value)
            elif "url" in ind_type or "uri" in ind_type:
                iocs["url"].append(ind_value)
            elif any(
                hash_type in ind_type
                for hash_type in ["md5", "sha1", "sha256", "hash"]
            ):
                iocs["hash"].append(ind_value)
            elif "email" in ind_type:
                iocs["email"].append(ind_value)
            elif "file" in ind_type:
                iocs["file"].append(ind_value)

        # Count total
        total_iocs = sum(len(v) for v in iocs.values())
        logger.info(f"Extracted {total_iocs} IOCs from pulse")

        return iocs

    def get_iocs_for_cve(self, cve_id: str) -> Dict[str, List[str]]:
        """Get IOCs related to a CVE from all relevant pulses.

        Args:
            cve_id: CVE identifier

        Returns:
            Dictionary mapping IOC type to list of indicators

        Example:
            >>> client = OTXClient()
            >>> iocs = client.get_iocs_for_cve("CVE-2024-1234")
            >>> if iocs['ip']:
            ...     print(f"Known malicious IPs: {iocs['ip']}")
        """
        pulses = self.get_cve_pulses(cve_id)

        all_iocs: Dict[str, List[str]] = {
            "ip": [],
            "domain": [],
            "url": [],
            "hash": [],
            "email": [],
            "file": [],
        }

        for pulse in pulses[:10]:  # Limit to first 10 pulses to avoid rate limits
            pulse_id = pulse.get("id")
            if pulse_id:
                full_pulse = self.get_pulse(pulse_id)
                if full_pulse:
                    iocs = self.extract_iocs(full_pulse)

                    # Merge IOCs
                    for ioc_type, values in iocs.items():
                        all_iocs[ioc_type].extend(values)

        # Remove duplicates
        for ioc_type in all_iocs:
            all_iocs[ioc_type] = list(set(all_iocs[ioc_type]))

        total = sum(len(v) for v in all_iocs.values())
        logger.info(f"Collected {total} unique IOCs for {cve_id}")

        return all_iocs

    def get_subscribed_pulses(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get pulses from subscribed users/sources.

        Args:
            limit: Maximum number of pulses

        Returns:
            List of pulse dictionaries

        Example:
            >>> client = OTXClient()
            >>> pulses = client.get_subscribed_pulses(limit=10)
            >>> for pulse in pulses:
            ...     print(f"{pulse['name']}")
        """
        endpoint = "pulses/subscribed"
        params = {"limit": limit}

        try:
            response = self._make_request(endpoint, params=params)
            results = response.get("results", [])

            logger.info(f"Retrieved {len(results)} subscribed pulses")
            return results

        except APIError as e:
            logger.error(f"Error getting subscribed pulses: {e}")
            return []

    def get_user_pulses(self, username: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get pulses created by a specific user.

        Args:
            username: OTX username
            limit: Maximum number of pulses

        Returns:
            List of pulse dictionaries

        Example:
            >>> client = OTXClient()
            >>> pulses = client.get_user_pulses("AlienVault", limit=10)
        """
        endpoint = f"users/{username}/pulses"
        params = {"limit": limit}

        try:
            response = self._make_request(endpoint, params=params)
            results = response.get("results", [])

            logger.info(f"Retrieved {len(results)} pulses from user '{username}'")
            return results

        except APIError as e:
            logger.error(f"Error getting pulses for user '{username}': {e}")
            return []

    def get_indicator_details(
        self, indicator_type: str, indicator: str
    ) -> Dict[str, Any]:
        """Get details for a specific indicator.

        Args:
            indicator_type: Type of indicator (IPv4, domain, file_hash, etc.)
            indicator: Indicator value

        Returns:
            Indicator details dictionary

        Example:
            >>> client = OTXClient()
            >>> details = client.get_indicator_details("IPv4", "192.168.1.1")
            >>> print(f"Pulses: {len(details.get('pulse_info', {}).get('pulses', []))}")
        """
        endpoint = f"indicators/{indicator_type}/{indicator}"

        try:
            response = self._make_request(endpoint)
            return response

        except APIError as e:
            logger.error(f"Error getting indicator details for {indicator}: {e}")
            return {}

    def generate_threat_narrative(
        self, cve_id: str, pulses: List[Dict[str, Any]]
    ) -> str:
        """Generate a threat narrative from pulses.

        Args:
            cve_id: CVE identifier
            pulses: List of pulse dictionaries

        Returns:
            Human-readable threat narrative

        Example:
            >>> client = OTXClient()
            >>> pulses = client.get_cve_pulses("CVE-2024-1234")
            >>> narrative = client.generate_threat_narrative("CVE-2024-1234", pulses)
            >>> print(narrative)
        """
        if not pulses:
            return f"No threat intelligence found for {cve_id} in AlienVault OTX."

        narrative_parts = [
            f"Threat Intelligence for {cve_id} from AlienVault OTX:",
            f"\nFound {len(pulses)} related threat intelligence pulses.\n",
        ]

        # Summarize top pulses
        for i, pulse in enumerate(pulses[:5], 1):
            pulse_name = pulse.get("name", "Unknown")
            pulse_desc = pulse.get("description", "No description")
            created = pulse.get("created", "Unknown date")

            narrative_parts.append(
                f"{i}. {pulse_name} (Created: {created})\n   {pulse_desc[:200]}...\n"
            )

        # Aggregate threat tags
        all_tags = set()
        for pulse in pulses:
            tags = pulse.get("tags", [])
            all_tags.update(tags)

        if all_tags:
            narrative_parts.append(f"\nThreat Tags: {', '.join(list(all_tags)[:10])}")

        return "\n".join(narrative_parts)
