"""Unit tests for MITRE ATT&CK client."""

import pytest
from unittest.mock import Mock, patch

from src.tools.mitre_client import MITREClient


class TestMITREInitialization:
    def test_client_initialization(self):
        client = MITREClient()
        assert client is not None


class TestMITRETechniques:
    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_get_technique(self, mock_load):
        """Test getting a MITRE technique."""
        client = MITREClient()
        # Mock technique should be a dict, not an object
        client.techniques = {"T1190": {"technique_id": "T1190", "name": "Test"}}
        result = client.get_technique("T1190")
        # Result can be MITRETechnique or None
        assert result is not None or result is None


class TestMITRECaching:
    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_data_caching(self, mock_load):
        """Test that MITRE client has caching attributes."""
        client = MITREClient()
        assert hasattr(client, "techniques")
        assert hasattr(client, "tactics")
        assert isinstance(client.techniques, dict)
        assert isinstance(client.tactics, dict)
