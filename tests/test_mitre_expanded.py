"""Expanded tests for MITRE client to increase coverage."""

import pytest
from unittest.mock import Mock, patch
from src.tools.mitre_client import MITREClient
from src.models.schemas import MITRETechnique


class TestMITREClientExpanded:
    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_search_techniques(self, mock_load):
        client = MITREClient()
        mock_tech = MITRETechnique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactic="initial-access",
            description="Test"
        )
        client.techniques = {"T1190": mock_tech}
        
        results = client.search_techniques("exploit")
        assert isinstance(results, list)

    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_get_techniques_by_tactic(self, mock_load):
        client = MITREClient()
        mock_tech = MITRETechnique(
            technique_id="T1190",
            name="Test",
            tactic="initial-access",
            description="Test"
        )
        client.techniques = {"T1190": mock_tech}
        
        results = client.get_techniques_by_tactic("initial-access")
        assert isinstance(results, list)

    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_map_cve_to_techniques(self, mock_load):
        client = MITREClient()
        client.techniques = {}
        
        results = client.map_cve_to_techniques("CVE-2024-1234", "Exploit vulnerability")
        assert isinstance(results, list)

    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_get_statistics(self, mock_load):
        client = MITREClient()
        client.techniques = {"T1190": Mock()}
        client.tactics = [{"name": "initial-access"}]
        
        stats = client.get_statistics()
        assert "total_techniques" in stats
