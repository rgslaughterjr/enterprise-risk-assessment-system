"""Unit tests for CISA KEV catalog client.

Tests cover KEV catalog fetching, CVE checking, vendor/product queries, and caching.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from src.tools.cisa_kev_client import CISAKEVClient
from src.utils.error_handler import APIError


class TestCISAKEVInitialization:
    """Test CISA KEV client initialization."""

    def test_client_initialization(self):
        """Test client initializes with empty cache."""
        client = CISAKEVClient()

        assert client.kev_data is None
        assert len(client.kev_cves) == 0
        assert len(client.kev_dict) == 0
        assert client.last_updated is None

    def test_client_url_configured(self):
        """Test KEV URL is properly configured."""
        client = CISAKEVClient()

        assert "cisa.gov" in client.KEV_URL
        assert "known_exploited_vulnerabilities" in client.KEV_URL


class TestCISAKEVCatalogFetching:
    """Test KEV catalog fetching and caching."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_fetch_kev_catalog_success(self, mock_get):
        """Test successful KEV catalog fetch."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "2024.01.01",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "Microsoft",
                    "product": "Windows",
                    "vulnerabilityName": "Test Vulnerability",
                    "dateAdded": "2024-01-01"
                },
                {
                    "cveID": "CVE-2024-5678",
                    "vendorProject": "Apache",
                    "product": "Struts",
                    "vulnerabilityName": "Another Vulnerability",
                    "dateAdded": "2024-01-02"
                }
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        client._fetch_kev_catalog()

        assert client.kev_data is not None
        assert len(client.kev_cves) == 2
        assert "CVE-2024-1234" in client.kev_cves
        assert "CVE-2024-5678" in client.kev_cves

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_fetch_kev_catalog_normalizes_cve_ids(self, mock_get):
        """Test CVE IDs are normalized to uppercase."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "cve-2024-1234", "vendorProject": "Test", "product": "Test"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        client._fetch_kev_catalog()

        assert "CVE-2024-1234" in client.kev_cves

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_fetch_kev_catalog_timeout(self, mock_get):
        """Test handling of fetch timeout."""
        import requests
        from tenacity import RetryError
        mock_get.side_effect = requests.exceptions.Timeout()

        client = CISAKEVClient()

        with pytest.raises((APIError, RetryError)):
            client._fetch_kev_catalog()

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_fetch_kev_catalog_connection_error(self, mock_get):
        """Test handling of connection error."""
        import requests
        from tenacity import RetryError
        mock_get.side_effect = requests.exceptions.ConnectionError()

        client = CISAKEVClient()

        with pytest.raises((APIError, RetryError)):
            client._fetch_kev_catalog()

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_lazy_loading(self, mock_get):
        """Test that catalog is loaded lazily on first use."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": []
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()

        # Catalog not loaded yet
        assert client.kev_data is None

        # First use triggers load
        client.is_in_kev("CVE-2024-1234")

        assert client.kev_data is not None
        assert mock_get.called


class TestCISAKEVChecking:
    """Test CVE checking functionality."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_is_in_kev_true(self, mock_get):
        """Test checking CVE that is in KEV."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-2024-1234", "vendorProject": "Test", "product": "Test"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        result = client.is_in_kev("CVE-2024-1234")

        assert result is True

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_is_in_kev_false(self, mock_get):
        """Test checking CVE that is not in KEV."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": []
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        result = client.is_in_kev("CVE-9999-9999")

        assert result is False

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_is_in_kev_case_insensitive(self, mock_get):
        """Test KEV checking is case insensitive."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-2024-1234", "vendorProject": "Test", "product": "Test"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()

        assert client.is_in_kev("cve-2024-1234") is True
        assert client.is_in_kev("CVE-2024-1234") is True


class TestCISAKEVDetails:
    """Test KEV details retrieval."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_kev_details_success(self, mock_get):
        """Test getting details for CVE in KEV."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "Microsoft",
                    "product": "Windows",
                    "vulnerabilityName": "Test Vuln",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "Test description",
                    "requiredAction": "Patch immediately",
                    "dueDate": "2024-02-01",
                    "knownRansomwareCampaignUse": "Known"
                }
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        details = client.get_kev_details("CVE-2024-1234")

        assert details is not None
        assert details["cveID"] == "CVE-2024-1234"
        assert details["vendorProject"] == "Microsoft"
        assert details["knownRansomwareCampaignUse"] == "Known"

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_kev_details_not_found(self, mock_get):
        """Test getting details for CVE not in KEV."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": []
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        details = client.get_kev_details("CVE-9999-9999")

        assert details is None


class TestCISAKEVMultipleCheck:
    """Test batch CVE checking."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_check_multiple_cves(self, mock_get):
        """Test checking multiple CVEs at once."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-2024-1", "vendorProject": "Test", "product": "Test"},
                {"cveID": "CVE-2024-2", "vendorProject": "Test", "product": "Test"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        results = client.check_multiple_cves(["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"])

        assert len(results) == 3
        assert results["CVE-2024-1"] is True
        assert results["CVE-2024-2"] is True
        assert results["CVE-2024-3"] is False


class TestCISAKEVVendorQueries:
    """Test vendor-based queries."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_kev_by_vendor(self, mock_get):
        """Test getting KEV entries by vendor."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-1", "vendorProject": "Microsoft", "product": "Windows"},
                {"cveID": "CVE-2", "vendorProject": "Microsoft", "product": "Office"},
                {"cveID": "CVE-3", "vendorProject": "Apache", "product": "Struts"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        results = client.get_kev_by_vendor("Microsoft")

        assert len(results) == 2
        assert all("Microsoft" in v["vendorProject"] for v in results)

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_kev_by_vendor_case_insensitive(self, mock_get):
        """Test vendor search is case insensitive."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-1", "vendorProject": "Microsoft", "product": "Test"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        results = client.get_kev_by_vendor("microsoft")

        assert len(results) == 1


class TestCISAKEVProductQueries:
    """Test product-based queries."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_kev_by_product(self, mock_get):
        """Test getting KEV entries by product."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-1", "vendorProject": "Microsoft", "product": "Windows 10"},
                {"cveID": "CVE-2", "vendorProject": "Microsoft", "product": "Windows Server"},
                {"cveID": "CVE-3", "vendorProject": "Adobe", "product": "Acrobat"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        results = client.get_kev_by_product("Windows")

        assert len(results) == 2


class TestCISAKEVRecentAdditions:
    """Test recent additions functionality."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_recent_additions(self, mock_get):
        """Test getting recently added CVEs."""
        today = datetime.utcnow()
        old_date = (today - timedelta(days=60)).strftime("%Y-%m-%d")
        recent_date = (today - timedelta(days=5)).strftime("%Y-%m-%d")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-OLD", "vendorProject": "Test", "product": "Test", "dateAdded": old_date},
                {"cveID": "CVE-RECENT", "vendorProject": "Test", "product": "Test", "dateAdded": recent_date}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        results = client.get_recent_additions(days=30)

        assert len(results) == 1
        assert results[0]["cveID"] == "CVE-RECENT"

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_recent_additions_handles_invalid_dates(self, mock_get):
        """Test that invalid dates are handled gracefully."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-1", "vendorProject": "Test", "product": "Test", "dateAdded": "invalid-date"},
                {"cveID": "CVE-2", "vendorProject": "Test", "product": "Test", "dateAdded": "2024-01-01"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        results = client.get_recent_additions(days=365)

        # Should skip invalid date entry
        assert all(v["cveID"] != "CVE-1" or v["dateAdded"] != "invalid-date" for v in results)


class TestCISAKEVRansomware:
    """Test ransomware-related queries."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_ransomware_cves(self, mock_get):
        """Test getting ransomware-related CVEs."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {"cveID": "CVE-1", "vendorProject": "Test", "product": "Test", "knownRansomwareCampaignUse": "Known"},
                {"cveID": "CVE-2", "vendorProject": "Test", "product": "Test", "knownRansomwareCampaignUse": "Unknown"},
                {"cveID": "CVE-3", "vendorProject": "Test", "product": "Test", "knownRansomwareCampaignUse": "Known"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        results = client.get_ransomware_cves()

        assert len(results) == 2
        assert all(v["knownRansomwareCampaignUse"] == "Known" for v in results)


class TestCISAKEVStatistics:
    """Test catalog statistics."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_get_catalog_stats(self, mock_get):
        """Test getting catalog statistics."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "2024.01.01",
            "vulnerabilities": [
                {"cveID": "CVE-1", "vendorProject": "Microsoft", "product": "Test", "knownRansomwareCampaignUse": "Known"},
                {"cveID": "CVE-2", "vendorProject": "Microsoft", "product": "Test", "knownRansomwareCampaignUse": "Unknown"},
                {"cveID": "CVE-3", "vendorProject": "Apache", "product": "Test", "knownRansomwareCampaignUse": "Known"}
            ]
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        stats = client.get_catalog_stats()

        assert stats["total_cves"] == 3
        assert stats["ransomware_cves"] == 2
        assert stats["catalog_version"] == "2024.01.01"
        assert "Microsoft" in stats["top_vendors"]


class TestCISAKEVRefresh:
    """Test catalog refresh functionality."""

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_refresh_catalog_success(self, mock_get):
        """Test successful catalog refresh."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": []
        }
        mock_get.return_value = mock_response

        client = CISAKEVClient()
        result = client.refresh_catalog()

        assert result is True
        assert client.kev_data is not None

    @patch("src.tools.cisa_kev_client.requests.get")
    def test_refresh_catalog_failure(self, mock_get):
        """Test catalog refresh failure."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError()

        client = CISAKEVClient()
        result = client.refresh_catalog()

        assert result is False
