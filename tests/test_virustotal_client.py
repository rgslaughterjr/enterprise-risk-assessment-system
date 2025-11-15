"""Unit tests for VirusTotal API client.

Tests cover file/URL lookups, CVE searches, rate limiting, and error handling.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import time
import requests

from src.tools.virustotal_client import VirusTotalClient
from src.utils.error_handler import APIError, ValidationError


class TestVirusTotalInitialization:
    """Test VirusTotal client initialization."""

    def test_client_with_api_key(self):
        """Test client initialization with API key."""
        client = VirusTotalClient(api_key="test_key")

        assert client.api_key == "test_key"
        assert client.headers["x-apikey"] == "test_key"
        assert client.headers["Accept"] == "application/json"

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "env_key"})
    def test_client_with_env_api_key(self):
        """Test client picks up API key from environment."""
        client = VirusTotalClient()

        assert client.api_key == "env_key"
        assert client.headers["x-apikey"] == "env_key"

    def test_client_without_api_key_raises_error(self):
        """Test client raises error without API key."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValidationError):
                VirusTotalClient()

    def test_rate_limiter_configured(self):
        """Test rate limiter is properly configured."""
        client = VirusTotalClient(api_key="test")

        assert client.rate_limiter.calls_per_period == 4
        assert client.rate_limiter.period_seconds == 60


class TestVirusTotalCVESearch:
    """Test CVE search functionality."""

    @patch("src.tools.virustotal_client.requests.request")
    def test_search_cve_success(self, mock_request):
        """Test successful CVE search."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 2
                        }
                    }
                },
                {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3
                        }
                    }
                }
            ]
        }
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        result = client.search_cve("CVE-2024-1234")

        assert result["cve_id"] == "CVE-2024-1234"
        assert result["detection_count"] == 2
        assert result["malicious_count"] == 2
        assert result["total_detections"] == 8

    @patch("src.tools.virustotal_client.requests.request")
    def test_search_cve_not_found(self, mock_request):
        """Test CVE search with no results."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        result = client.search_cve("CVE-9999-9999")

        assert result["detection_count"] == 0
        assert result["malicious_count"] == 0

    @patch("src.tools.virustotal_client.requests.request")
    def test_search_cve_api_error(self, mock_request):
        """Test CVE search with API error."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.raise_for_status = Mock(side_effect=requests.exceptions.HTTPError())
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        result = client.search_cve("CVE-2024-1234")

        assert "error" in result
        assert result["detection_count"] == 0

    @patch("src.tools.virustotal_client.requests.request")
    def test_search_cve_keeps_top_samples(self, mock_request):
        """Test that search keeps only first 5 samples."""
        mock_data = [{"attributes": {}} for _ in range(10)]
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": mock_data}
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        result = client.search_cve("CVE-2024-1234")

        assert len(result["samples"]) == 5


class TestVirusTotalExploitationCheck:
    """Test exploitation checking functionality."""

    @patch("src.tools.virustotal_client.VirusTotalClient.search_cve")
    def test_check_exploitation_detected(self, mock_search):
        """Test exploitation detection with malicious samples."""
        mock_search.return_value = {
            "cve_id": "CVE-2024-1234",
            "detection_count": 10,
            "malicious_count": 5,
            "total_detections": 20,
            "samples": []
        }

        client = VirusTotalClient(api_key="test")
        result = client.check_exploitation("CVE-2024-1234")

        assert result["exploit_detected"] is True
        assert result["confidence"] == "high"
        assert "malicious samples" in result["evidence"]

    @patch("src.tools.virustotal_client.VirusTotalClient.search_cve")
    def test_check_exploitation_not_detected(self, mock_search):
        """Test exploitation check with no malicious samples."""
        mock_search.return_value = {
            "cve_id": "CVE-2024-1234",
            "detection_count": 5,
            "malicious_count": 0,
            "total_detections": 0,
            "samples": []
        }

        client = VirusTotalClient(api_key="test")
        result = client.check_exploitation("CVE-2024-1234")

        assert result["exploit_detected"] is False
        assert result["confidence"] == "low"
        assert "No malicious samples" in result["evidence"]

    @patch("src.tools.virustotal_client.VirusTotalClient.search_cve")
    def test_check_exploitation_medium_confidence(self, mock_search):
        """Test exploitation check with medium confidence."""
        mock_search.return_value = {
            "cve_id": "CVE-2024-1234",
            "detection_count": 3,
            "malicious_count": 1,
            "total_detections": 5,
            "samples": []
        }

        client = VirusTotalClient(api_key="test")
        result = client.check_exploitation("CVE-2024-1234")

        assert result["confidence"] == "medium"


class TestVirusTotalMultipleCVEs:
    """Test batch CVE checking."""

    @patch("src.tools.virustotal_client.VirusTotalClient.check_exploitation")
    @patch("time.sleep")  # Mock sleep to speed up tests
    def test_check_multiple_cves(self, mock_sleep, mock_check):
        """Test checking multiple CVEs."""
        mock_check.side_effect = [
            {"cve_id": "CVE-2024-1", "exploit_detected": True},
            {"cve_id": "CVE-2024-2", "exploit_detected": False}
        ]

        client = VirusTotalClient(api_key="test")
        results = client.check_multiple_cves(["CVE-2024-1", "CVE-2024-2"])

        assert len(results) == 2
        assert results["CVE-2024-1"]["exploit_detected"] is True
        assert results["CVE-2024-2"]["exploit_detected"] is False


class TestVirusTotalFileReport:
    """Test file hash lookup functionality."""

    @patch("src.tools.virustotal_client.requests.request")
    def test_get_file_report_success(self, mock_request):
        """Test successful file hash lookup."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "id": "test_hash",
                "attributes": {
                    "meaningful_name": "test.exe",
                    "last_analysis_stats": {"malicious": 45}
                }
            }
        }
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        report = client.get_file_report("44d88612fea8a8f36de82e1278abb02f")

        assert "id" in report
        assert report["id"] == "test_hash"

    @patch("src.tools.virustotal_client.requests.request")
    def test_get_file_report_not_found(self, mock_request):
        """Test file hash not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not found"
        mock_response.raise_for_status = Mock(side_effect=requests.exceptions.HTTPError())
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        report = client.get_file_report("nonexistent_hash")

        assert "error" in report

    @patch("src.tools.virustotal_client.requests.request")
    def test_get_file_report_api_error(self, mock_request):
        """Test file report with API error."""
        import requests
        mock_request.side_effect = requests.exceptions.Timeout()

        client = VirusTotalClient(api_key="test")
        report = client.get_file_report("test_hash")

        assert "error" in report


class TestVirusTotalURLReport:
    """Test URL analysis functionality."""

    @patch("src.tools.virustotal_client.requests.request")
    def test_get_url_report_success(self, mock_request):
        """Test successful URL lookup."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "id": "url_id",
                "attributes": {
                    "url": "https://example.com",
                    "last_analysis_stats": {"malicious": 10}
                }
            }
        }
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        report = client.get_url_report("https://example.com")

        assert "id" in report

    @patch("src.tools.virustotal_client.requests.request")
    def test_get_url_report_encoding(self, mock_request):
        """Test URL is properly base64 encoded."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {}}
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        client.get_url_report("https://example.com")

        # Verify URL was encoded in endpoint
        call_url = mock_request.call_args[1]["url"]
        assert "urls/" in call_url

    @patch("src.tools.virustotal_client.requests.request")
    def test_get_url_report_error(self, mock_request):
        """Test URL report with error."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Error"
        mock_response.raise_for_status = Mock(side_effect=requests.exceptions.HTTPError())
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        report = client.get_url_report("https://example.com")

        assert "error" in report


class TestVirusTotalErrorHandling:
    """Test error handling and edge cases."""

    @patch("src.tools.virustotal_client.requests.request")
    def test_timeout_handling(self, mock_request):
        """Test handling of request timeouts."""
        import requests
        mock_request.side_effect = requests.exceptions.Timeout()

        client = VirusTotalClient(api_key="test")
        result = client.search_cve("CVE-2024-1234")

        assert "error" in result

    @patch("src.tools.virustotal_client.requests.request")
    def test_connection_error_handling(self, mock_request):
        """Test handling of connection errors."""
        import requests
        mock_request.side_effect = requests.exceptions.ConnectionError()

        client = VirusTotalClient(api_key="test")
        result = client.search_cve("CVE-2024-1234")

        assert "error" in result

    @patch("src.tools.virustotal_client.requests.request")
    def test_empty_analysis_stats(self, mock_request):
        """Test handling of samples without analysis stats."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {"attributes": {}},  # No last_analysis_stats
                {"attributes": {"last_analysis_stats": {}}}  # Empty stats
            ]
        }
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")
        result = client.search_cve("CVE-2024-1234")

        assert result["malicious_count"] == 0
        assert result["total_detections"] == 0


class TestVirusTotalRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limiter_exists(self):
        """Test that rate limiter is configured."""
        client = VirusTotalClient(api_key="test")

        assert hasattr(client, "rate_limiter")
        assert client.rate_limiter.calls_per_period == 4
        assert client.rate_limiter.period_seconds == 60

    @patch("src.tools.virustotal_client.requests.request")
    def test_rate_limiter_used_in_requests(self, mock_request):
        """Test that rate limiter is used for API calls."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_request.return_value = mock_response

        client = VirusTotalClient(api_key="test")

        # Make request - should use rate limiter
        client.search_cve("CVE-2024-1234")

        assert mock_request.called
