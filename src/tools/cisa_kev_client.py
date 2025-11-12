"""CISA KEV (Known Exploited Vulnerabilities) Catalog client.

This client queries CISA's Known Exploited Vulnerabilities catalog to check
if CVEs are being actively exploited in the wild.

No API key required - public JSON feed.
"""

import requests
from typing import Optional, Dict, Any, List, Set
from datetime import datetime
import logging

from ..utils.error_handler import (
    handle_api_response,
    retry_on_api_error,
    log_api_call,
    APIError,
)

logger = logging.getLogger(__name__)


class CISAKEVClient:
    """Client for CISA Known Exploited Vulnerabilities (KEV) catalog.

    Provides methods to check if CVEs are in CISA's KEV catalog, indicating
    active exploitation in the wild.
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        """Initialize CISA KEV client.

        The KEV catalog is loaded once and cached for performance.
        """
        self.kev_data: Optional[Dict[str, Any]] = None
        self.kev_cves: Set[str] = set()
        self.kev_dict: Dict[str, Dict[str, Any]] = {}
        self.last_updated: Optional[datetime] = None

        logger.info("CISA KEV client initialized")

    @retry_on_api_error(max_attempts=3)
    def _fetch_kev_catalog(self) -> None:
        """Fetch and cache the KEV catalog.

        Raises:
            APIError: If fetch fails
        """
        log_api_call("CISA KEV", self.KEV_URL)

        try:
            response = requests.get(self.KEV_URL, timeout=30)
            self.kev_data = handle_api_response(response, "CISA KEV")

            # Parse and cache CVE list
            vulnerabilities = self.kev_data.get("vulnerabilities", [])

            self.kev_cves = set()
            self.kev_dict = {}

            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "").upper()
                if cve_id:
                    self.kev_cves.add(cve_id)
                    self.kev_dict[cve_id] = vuln

            self.last_updated = datetime.utcnow()

            catalog_version = self.kev_data.get("catalogVersion", "unknown")
            logger.info(
                f"Loaded CISA KEV catalog v{catalog_version} "
                f"with {len(self.kev_cves)} CVEs"
            )

        except requests.exceptions.Timeout:
            raise APIError("CISA KEV request timed out")
        except requests.exceptions.ConnectionError:
            raise APIError("Failed to connect to CISA KEV")

    def _ensure_catalog_loaded(self) -> None:
        """Ensure KEV catalog is loaded (lazy loading)."""
        if self.kev_data is None:
            self._fetch_kev_catalog()

    def refresh_catalog(self) -> bool:
        """Refresh the KEV catalog with latest data.

        Returns:
            True if refresh successful, False otherwise
        """
        try:
            self._fetch_kev_catalog()
            return True
        except Exception as e:
            logger.error(f"Failed to refresh KEV catalog: {e}")
            return False

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the CISA KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            True if CVE is in KEV catalog (actively exploited)

        Example:
            >>> client = CISAKEVClient()
            >>> if client.is_in_kev("CVE-2024-1234"):
            ...     print("WARNING: CVE is actively exploited!")
        """
        self._ensure_catalog_loaded()
        return cve_id.upper() in self.kev_cves

    def get_kev_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get KEV details for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            Dictionary with KEV details or None if not in catalog

        Example:
            >>> client = CISAKEVClient()
            >>> details = client.get_kev_details("CVE-2024-1234")
            >>> if details:
            ...     print(f"Due date: {details['dueDate']}")
            ...     print(f"Threat: {details['knownRansomwareCampaignUse']}")
        """
        self._ensure_catalog_loaded()

        cve_id = cve_id.upper()
        if cve_id not in self.kev_dict:
            return None

        vuln = self.kev_dict[cve_id]

        return {
            "cveID": vuln.get("cveID"),
            "vendorProject": vuln.get("vendorProject"),
            "product": vuln.get("product"),
            "vulnerabilityName": vuln.get("vulnerabilityName"),
            "dateAdded": vuln.get("dateAdded"),
            "shortDescription": vuln.get("shortDescription"),
            "requiredAction": vuln.get("requiredAction"),
            "dueDate": vuln.get("dueDate"),
            "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            "notes": vuln.get("notes", ""),
        }

    def check_multiple_cves(self, cve_ids: List[str]) -> Dict[str, bool]:
        """Check if multiple CVEs are in KEV catalog.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dictionary mapping CVE ID to boolean (in KEV or not)

        Example:
            >>> client = CISAKEVClient()
            >>> results = client.check_multiple_cves(["CVE-2024-1234", "CVE-2024-5678"])
            >>> exploited = [cve for cve, in_kev in results.items() if in_kev]
            >>> print(f"Actively exploited: {exploited}")
        """
        self._ensure_catalog_loaded()

        results = {}
        for cve_id in cve_ids:
            results[cve_id] = self.is_in_kev(cve_id)

        return results

    def get_kev_by_vendor(self, vendor: str) -> List[Dict[str, Any]]:
        """Get all KEV entries for a specific vendor.

        Args:
            vendor: Vendor name (case-insensitive)

        Returns:
            List of KEV entries for the vendor

        Example:
            >>> client = CISAKEVClient()
            >>> microsoft_kevs = client.get_kev_by_vendor("Microsoft")
            >>> print(f"Microsoft has {len(microsoft_kevs)} CVEs in KEV")
        """
        self._ensure_catalog_loaded()

        vendor_lower = vendor.lower()
        results = []

        for vuln in self.kev_dict.values():
            vendor_project = vuln.get("vendorProject", "").lower()
            if vendor_lower in vendor_project:
                results.append(vuln)

        logger.info(f"Found {len(results)} KEV entries for vendor '{vendor}'")
        return results

    def get_kev_by_product(self, product: str) -> List[Dict[str, Any]]:
        """Get all KEV entries for a specific product.

        Args:
            product: Product name (case-insensitive)

        Returns:
            List of KEV entries for the product

        Example:
            >>> client = CISAKEVClient()
            >>> chrome_kevs = client.get_kev_by_product("Chrome")
        """
        self._ensure_catalog_loaded()

        product_lower = product.lower()
        results = []

        for vuln in self.kev_dict.values():
            vuln_product = vuln.get("product", "").lower()
            if product_lower in vuln_product:
                results.append(vuln)

        logger.info(f"Found {len(results)} KEV entries for product '{product}'")
        return results

    def get_recent_additions(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get CVEs added to KEV catalog in recent days.

        Args:
            days: Number of days to look back

        Returns:
            List of recently added KEV entries

        Example:
            >>> client = CISAKEVClient()
            >>> recent = client.get_recent_additions(days=7)
            >>> print(f"Added in last 7 days: {len(recent)}")
        """
        self._ensure_catalog_loaded()

        from datetime import timedelta

        cutoff_date = datetime.utcnow() - timedelta(days=days)
        results = []

        for vuln in self.kev_dict.values():
            date_added_str = vuln.get("dateAdded")
            if date_added_str:
                try:
                    date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                    if date_added >= cutoff_date:
                        results.append(vuln)
                except ValueError:
                    continue

        # Sort by date added (newest first)
        results.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)

        logger.info(f"Found {len(results)} KEV entries added in last {days} days")
        return results

    def get_ransomware_cves(self) -> List[Dict[str, Any]]:
        """Get CVEs associated with ransomware campaigns.

        Returns:
            List of KEV entries with known ransomware use

        Example:
            >>> client = CISAKEVClient()
            >>> ransomware = client.get_ransomware_cves()
            >>> print(f"Found {len(ransomware)} ransomware-related CVEs")
        """
        self._ensure_catalog_loaded()

        results = []

        for vuln in self.kev_dict.values():
            ransomware_use = vuln.get("knownRansomwareCampaignUse", "Unknown")
            if ransomware_use.lower() == "known":
                results.append(vuln)

        logger.info(f"Found {len(results)} ransomware-related CVEs")
        return results

    def get_catalog_stats(self) -> Dict[str, Any]:
        """Get statistics about the KEV catalog.

        Returns:
            Dictionary with catalog statistics

        Example:
            >>> client = CISAKEVClient()
            >>> stats = client.get_catalog_stats()
            >>> print(f"Total CVEs: {stats['total_cves']}")
            >>> print(f"Ransomware CVEs: {stats['ransomware_cves']}")
        """
        self._ensure_catalog_loaded()

        ransomware_count = len(self.get_ransomware_cves())

        # Count by vendor (top 10)
        vendor_counts = {}
        for vuln in self.kev_dict.values():
            vendor = vuln.get("vendorProject", "Unknown")
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

        top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_cves": len(self.kev_cves),
            "ransomware_cves": ransomware_count,
            "catalog_version": self.kev_data.get("catalogVersion"),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "top_vendors": dict(top_vendors),
        }
