"""Unit tests for NVD API client.

Tests cover CVE lookups, batch queries, rate limiting, error handling, and data parsing.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from src.tools.nvd_client import NVDClient
from src.utils.error_handler import APIError
from src.models.schemas import CVEDetail


class TestNVDClientInitialization:
    """Test NVD client initialization."""

    def test_client_with_api_key(self):
        """Test client initialization with API key."""
        client = NVDClient(api_key="test_key")

        assert client.api_key == "test_key"
        assert "apiKey" in client.headers
        assert client.headers["apiKey"] == "test_key"
        assert client.rate_limiter.calls_per_period == 50  # With key

    def test_client_without_api_key(self):
        """Test client initialization without API key."""
        with patch.dict("os.environ", {}, clear=True):
            client = NVDClient()

            assert client.api_key is None
            assert "apiKey" not in client.headers
            assert client.rate_limiter.calls_per_period == 5  # Without key

    @patch.dict("os.environ", {"NVD_API_KEY": "env_key"})
    def test_client_with_env_api_key(self):
        """Test client picks up API key from environment."""
        client = NVDClient()

        assert client.api_key == "env_key"
        assert client.headers["apiKey"] == "env_key"

    def test_client_headers_configuration(self):
        """Test HTTP headers are properly configured."""
        client = NVDClient(api_key="test")

        assert "Accept" in client.headers
        assert client.headers["Accept"] == "application/json"


class TestNVDCVELookup:
    """Test CVE lookup functionality."""

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_success(self, mock_get):
        """Test successful CVE retrieval."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Test vulnerability description"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }]
                    },
                    "configurations": [],
                    "references": []
                }
            }]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert cve is not None
        assert cve.cve_id == "CVE-2024-1234"
        assert cve.cvss_score == 9.8
        assert cve.cvss_severity == "CRITICAL"
        assert "vulnerability" in cve.description.lower()

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_not_found(self, mock_get):
        """Test CVE not found in database."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-9999-9999")

        assert cve is None

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_with_cvss_v30(self, mock_get):
        """Test CVE with CVSS v3.0 scoring."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {
                        "cvssMetricV30": [{
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH"
                            }
                        }]
                    },
                    "configurations": [],
                    "references": []
                }
            }]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert cve.cvss_score == 7.5
        assert cve.cvss_severity == "HIGH"

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_with_cvss_v2(self, mock_get):
        """Test CVE with only CVSS v2 scoring."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {
                        "cvssMetricV2": [{
                            "cvssData": {
                                "baseScore": 8.0
                            }
                        }]
                    },
                    "configurations": [],
                    "references": []
                }
            }]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert cve.cvss_score == 8.0
        assert cve.cvss_severity == "HIGH"  # Mapped from v2 score

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_with_cpe_matches(self, mock_get):
        """Test CVE with CPE product matches."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {},
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
                                {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"}
                            ]
                        }]
                    }],
                    "references": []
                }
            }]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert len(cve.cpe_matches) == 2
        assert "vendor:product" in cve.cpe_matches[0]

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_with_references(self, mock_get):
        """Test CVE with reference URLs."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {},
                    "configurations": [],
                    "references": [
                        {"url": "https://example.com/advisory1"},
                        {"url": "https://example.com/advisory2"}
                    ]
                }
            }]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert len(cve.references) == 2
        assert "https://example.com/advisory1" in cve.references

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_api_error(self, mock_get):
        """Test handling of API errors during CVE lookup."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert cve is None

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_timeout(self, mock_get):
        """Test handling of request timeout."""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert cve is None

    @patch("src.tools.nvd_client.requests.get")
    def test_get_cve_connection_error(self, mock_get):
        """Test handling of connection errors."""
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError()

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert cve is None


class TestNVDMultipleCVEs:
    """Test batch CVE lookup functionality."""

    @patch("src.tools.nvd_client.NVDClient.get_cve")
    def test_get_multiple_cves_success(self, mock_get_cve):
        """Test successful batch CVE retrieval."""
        mock_get_cve.side_effect = [
            CVEDetail(cve_id="CVE-2024-1", description="Test 1", cvss_score=7.5),
            CVEDetail(cve_id="CVE-2024-2", description="Test 2", cvss_score=9.0)
        ]

        client = NVDClient(api_key="test")
        results = client.get_multiple_cves(["CVE-2024-1", "CVE-2024-2"])

        assert len(results) == 2
        assert "CVE-2024-1" in results
        assert "CVE-2024-2" in results
        assert results["CVE-2024-1"].cvss_score == 7.5

    @patch("src.tools.nvd_client.NVDClient.get_cve")
    def test_get_multiple_cves_partial_failure(self, mock_get_cve):
        """Test batch lookup with some CVEs not found."""
        mock_get_cve.side_effect = [
            CVEDetail(cve_id="CVE-2024-1", description="Test", cvss_score=7.5),
            None  # Not found
        ]

        client = NVDClient(api_key="test")
        results = client.get_multiple_cves(["CVE-2024-1", "CVE-9999-9999"])

        assert len(results) == 2
        assert results["CVE-2024-1"] is not None
        assert results["CVE-9999-9999"] is None


class TestNVDSearch:
    """Test CVE search functionality."""

    @patch("src.tools.nvd_client.requests.get")
    @patch("src.tools.nvd_client.NVDClient.get_cve")
    def test_search_cves_by_severity(self, mock_get_cve, mock_get):
        """Test searching CVEs by severity."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-1"}},
                {"cve": {"id": "CVE-2024-2"}}
            ]
        }
        mock_get.return_value = mock_response

        mock_get_cve.side_effect = [
            CVEDetail(cve_id="CVE-2024-1", description="Test", cvss_score=9.0, cvss_severity="CRITICAL"),
            CVEDetail(cve_id="CVE-2024-2", description="Test", cvss_score=9.5, cvss_severity="CRITICAL")
        ]

        client = NVDClient(api_key="test")
        results = client.search_cves(cvss_v3_severity="CRITICAL")

        assert len(results) == 2
        assert all(r.cvss_severity == "CRITICAL" for r in results)

    @patch("src.tools.nvd_client.requests.get")
    def test_search_cves_by_keyword(self, mock_get):
        """Test searching CVEs by keyword."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        results = client.search_cves(keyword="apache")

        # Verify request was made with keyword parameter
        assert mock_get.called
        call_params = mock_get.call_args[1]["params"]
        assert "keywordSearch" in call_params
        assert call_params["keywordSearch"] == "apache"

    @patch("src.tools.nvd_client.requests.get")
    def test_search_cves_api_error(self, mock_get):
        """Test handling of search API errors."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Error"
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        results = client.search_cves(keyword="test")

        assert results == []


class TestNVDRecentCVEs:
    """Test recent CVE retrieval functionality."""

    @patch("src.tools.nvd_client.requests.get")
    @patch("src.tools.nvd_client.NVDClient.get_cve")
    def test_get_recent_cves(self, mock_get_cve, mock_get):
        """Test retrieving recent CVEs."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-1"}}
            ]
        }
        mock_get.return_value = mock_response

        mock_get_cve.return_value = CVEDetail(
            cve_id="CVE-2024-1",
            description="Recent vulnerability",
            cvss_score=7.5
        )

        client = NVDClient(api_key="test")
        results = client.get_recent_cves(days=7)

        assert len(results) == 1
        # Verify date range parameters were included
        call_params = mock_get.call_args[1]["params"]
        assert "pubStartDate" in call_params
        assert "pubEndDate" in call_params

    @patch("src.tools.nvd_client.requests.get")
    def test_get_recent_cves_with_severity_filter(self, mock_get):
        """Test retrieving recent CVEs with severity filter."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        results = client.get_recent_cves(days=30, severity="HIGH")

        call_params = mock_get.call_args[1]["params"]
        assert call_params["cvssV3Severity"] == "HIGH"


class TestNVDRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limiter_exists(self):
        """Test that rate limiter is properly configured."""
        client = NVDClient(api_key="test")

        assert hasattr(client, "rate_limiter")
        assert client.rate_limiter is not None

    def test_rate_limiter_configuration_with_key(self):
        """Test rate limiter settings with API key."""
        client = NVDClient(api_key="test")

        assert client.rate_limiter.calls_per_period == 50
        assert client.rate_limiter.period_seconds == 30

    def test_rate_limiter_configuration_without_key(self):
        """Test rate limiter settings without API key."""
        with patch.dict("os.environ", {}, clear=True):
            client = NVDClient()

            assert client.rate_limiter.calls_per_period == 5
            assert client.rate_limiter.period_seconds == 30


class TestNVDErrorHandling:
    """Test error handling and edge cases."""

    @patch("src.tools.nvd_client.requests.get")
    def test_cve_id_normalization(self, mock_get):
        """Test CVE ID is normalized to uppercase."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {},
                    "configurations": [],
                    "references": []
                }
            }]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("cve-2024-1234")  # lowercase

        # Should be normalized to uppercase
        call_params = mock_get.call_args[1]["params"]
        assert call_params["cveId"] == "CVE-2024-1234"

    @patch("src.tools.nvd_client.requests.get")
    def test_empty_description_handling(self, mock_get):
        """Test handling of CVEs with no English description."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "fr", "value": "Description en français"}],
                    "metrics": {},
                    "configurations": [],
                    "references": []
                }
            }]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert cve.description == ""  # No English description

    @patch("src.tools.nvd_client.requests.get")
    def test_no_cvss_score_handling(self, mock_get):
        """Test handling of CVEs without CVSS scores."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {},  # No metrics
                    "configurations": [],
                    "references": []
                }
            }]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test")
        cve = client.get_cve("CVE-2024-1234")

        assert cve.cvss_score is None
        assert cve.cvss_severity is None
