"""Expanded tests for OTX client to increase coverage."""

import pytest
from unittest.mock import Mock, patch
from src.tools.otx_client import OTXClient


class TestOTXClientExpanded:
    @patch.dict("os.environ", {"ALIENVAULT_OTX_KEY": "test_key"})
    @patch("src.tools.otx_client.requests.get")
    def test_get_cve_pulses(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": [{"id": "123", "name": "Test Pulse"}]}
        mock_get.return_value = mock_response
        
        client = OTXClient()
        result = client.get_cve_pulses("CVE-2024-1234")
        assert isinstance(result, list)

    @patch.dict("os.environ", {"ALIENVAULT_OTX_KEY": "test_key"})
    @patch("src.tools.otx_client.requests.get")
    def test_get_iocs_for_cve(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{
                "id": "123",
                "indicators": [
                    {"type": "IPv4", "indicator": "1.2.3.4"},
                    {"type": "domain", "indicator": "evil.com"}
                ]
            }]
        }
        mock_get.return_value = mock_response
        
        client = OTXClient()
        result = client.get_iocs_for_cve("CVE-2024-1234")
        assert isinstance(result, dict)

    @patch.dict("os.environ", {"ALIENVAULT_OTX_KEY": "test_key"})
    def test_extract_iocs(self):
        client = OTXClient()
        pulse = {
            "indicators": [
                {"type": "IPv4", "indicator": "1.2.3.4"},
                {"type": "domain", "indicator": "test.com"},
                {"type": "FileHash-MD5", "indicator": "abc123"}
            ]
        }

        result = client.extract_iocs(pulse)
        assert "ip" in result
        assert "domain" in result
        assert "hash" in result

    @patch.dict("os.environ", {"ALIENVAULT_OTX_KEY": "test_key"})
    @patch("src.tools.otx_client.requests.get")
    def test_generate_threat_narrative(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{
                "name": "APT28 Campaign",
                "description": "Test threat",
                "tags": ["apt28", "russia"]
            }]
        }
        mock_get.return_value = mock_response

        client = OTXClient()
        pulses = [{
            "name": "APT28 Campaign",
            "description": "Test threat",
            "tags": ["apt28", "russia"]
        }]
        result = client.generate_threat_narrative("CVE-2024-1234", pulses)
        assert isinstance(result, str)
