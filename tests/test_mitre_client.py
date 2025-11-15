"""Unit tests for MITRE ATT&CK client."""

import pytest
from unittest.mock import Mock, patch

from src.tools.mitre_client import MITREClient


class TestMITREInitialization:
    def test_client_initialization(self):
        client = MITREClient()
        assert client is not None


class TestMITRETechniques:
    @patch("src.tools.mitre_client.MITREClient._load_attack_data")
    def test_get_technique(self, mock_load):
        client = MITREClient()
        client.techniques = {"T1190": Mock(technique_id="T1190", name="Test")}
        result = client.get_technique("T1190")
        assert result is not None


class TestMITRECaching:
    @patch("src.tools.mitre_client.MITREClient._load_attack_data")
    def test_data_caching(self, mock_load):
        client = MITREClient()
        assert hasattr(client, "techniques")
