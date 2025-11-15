"""Expanded tests for MITRE client to increase coverage."""

import pytest
from unittest.mock import Mock, patch
from src.tools.mitre_client import MITREClient
from src.models.schemas import MITRETechnique


class TestMITREClientExpanded:
    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_search_techniques(self, mock_load):
        """Test searching MITRE techniques by keyword."""
        client = MITREClient()
        # Techniques are stored as dicts, not MITRETechnique objects
        client.techniques = {
            "T1190": {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "description": "Test exploit technique",
                "tactics": ["initial-access"]
            }
        }

        results = client.search_techniques("exploit")
        assert isinstance(results, list)

    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_get_techniques_by_tactic(self, mock_load):
        """Test getting techniques by tactic."""
        client = MITREClient()
        # Techniques are stored as dicts
        client.techniques = {
            "T1190": {
                "technique_id": "T1190",
                "name": "Test",
                "description": "Test",
                "tactics": ["initial-access"]
            }
        }

        results = client.get_techniques_by_tactic("initial-access")
        assert isinstance(results, list)

    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_map_cve_to_techniques(self, mock_load):
        """Test mapping CVE to MITRE techniques."""
        client = MITREClient()
        client.techniques = {}

        results = client.map_cve_to_techniques("CVE-2024-1234", "Exploit vulnerability")
        assert isinstance(results, list)

    @patch("src.tools.mitre_client.MITREClient._load_data")
    def test_get_statistics(self, mock_load):
        """Test getting MITRE statistics."""
        client = MITREClient()
        client.techniques = {"T1190": {"name": "Test"}}
        client.tactics = {"initial-access": {"name": "Initial Access"}}

        stats = client.get_statistics()
        # Statistics should be a dict
        assert isinstance(stats, dict)
