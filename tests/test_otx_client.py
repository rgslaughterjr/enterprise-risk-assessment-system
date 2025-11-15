"""Unit tests for AlienVault OTX client."""

import pytest
from unittest.mock import Mock, patch

from src.utils.error_handler import ValidationError


class TestOTXInitialization:
    def test_client_requires_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises((ValidationError, Exception)):
                from src.tools.otx_client import OTXClient
                OTXClient()

    @patch.dict("os.environ", {"ALIENVAULT_OTX_KEY": "test_key"})
    def test_client_with_api_key(self):
        from src.tools.otx_client import OTXClient
        client = OTXClient()
        assert client.api_key == "test_key"


class TestOTXPulses:
    @patch.dict("os.environ", {"ALIENVAULT_OTX_KEY": "test_key"})
    @patch("src.tools.otx_client.requests.get")
    def test_get_pulses(self, mock_get):
        from src.tools.otx_client import OTXClient
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": []}
        mock_get.return_value = mock_response

        client = OTXClient()
        result = client.search_pulses(query="malware", limit=5)
        assert isinstance(result, list)
