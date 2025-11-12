"""Tests for Threat Research Agent."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.agents.threat_agent import (
    ThreatAgent,
    map_cve_to_techniques,
    get_technique_details,
    search_techniques,
    research_threat_actor,
    get_threat_intelligence,
    get_threat_iocs,
    generate_threat_narrative,
    get_mitre_client,
    get_otx_client,
)
from src.models.schemas import MITRETechnique, ThreatIntelligence


@pytest.fixture
def mock_mitre_technique():
    """Mock MITRE ATT&CK technique."""
    return MITRETechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        description="Adversaries may abuse command and script interpreters",
        tactics=["Execution"],
        platforms=["Windows", "Linux", "macOS"],
        data_sources=["Process", "Command"],
        mitigations=["Code Signing", "Execution Prevention"],
    )


@pytest.fixture
def mock_threat_intelligence():
    """Mock threat intelligence data."""
    return {
        "cve_id": "CVE-2024-12345",
        "pulse_count": 2,
        "pulses": [
            {
                "name": "Critical RCE Vulnerability",
                "description": "Remote code execution in web server",
                "tags": ["rce", "exploit"],
            }
        ],
        "iocs": {
            "IPv4": ["192.168.1.100", "10.0.0.50"],
            "domain": ["malicious.example.com"],
            "FileHash-MD5": ["d41d8cd98f00b204e9800998ecf8427e"],
        },
        "narrative": "Active exploitation detected in the wild",
    }


@pytest.fixture
def mock_mitre_client():
    """Mock MITRE client."""
    client = Mock()
    client.map_cve_to_techniques = Mock()
    client.get_technique = Mock()
    client.search_techniques = Mock()
    client.get_group = Mock()
    return client


@pytest.fixture
def mock_otx_client():
    """Mock OTX client."""
    client = Mock()
    client.get_cve_pulses = Mock()
    client.get_iocs_for_cve = Mock()
    client.generate_threat_narrative = Mock()
    return client


class TestThreatAgentTools:
    """Test threat agent tool functions."""

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_map_cve_to_techniques_success(self, mock_get_mitre, mock_mitre_technique):
        """Test successful CVE to technique mapping."""
        # Setup mock
        mock_client = Mock()
        mock_client.map_cve_to_techniques.return_value = [mock_mitre_technique]
        mock_get_mitre.return_value = mock_client

        # Execute
        result = map_cve_to_techniques.invoke({
            "cve_id": "CVE-2024-12345",
            "cve_description": "Remote code execution vulnerability"
        })

        # Verify
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1059"
        assert result[0]["name"] == "Command and Scripting Interpreter"
        mock_client.map_cve_to_techniques.assert_called_once_with(
            "CVE-2024-12345",
            "Remote code execution vulnerability"
        )

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_map_cve_to_techniques_exception(self, mock_get_mitre):
        """Test CVE mapping with exception."""
        # Setup mock to raise exception
        mock_client = Mock()
        mock_client.map_cve_to_techniques.side_effect = Exception("API error")
        mock_get_mitre.return_value = mock_client

        # Execute
        result = map_cve_to_techniques.invoke({
            "cve_id": "CVE-2024-12345",
            "cve_description": "Test description"
        })

        # Verify
        assert isinstance(result, list)
        assert len(result) == 1
        assert "error" in result[0]

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_get_technique_details_success(self, mock_get_mitre, mock_mitre_technique):
        """Test getting technique details."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_technique.return_value = mock_mitre_technique
        mock_get_mitre.return_value = mock_client

        # Execute
        result = get_technique_details.invoke({"technique_id": "T1059"})

        # Verify
        assert isinstance(result, dict)
        assert result["technique_id"] == "T1059"
        assert result["name"] == "Command and Scripting Interpreter"
        assert "Execution" in result["tactics"]

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_get_technique_details_not_found(self, mock_get_mitre):
        """Test getting technique details when not found."""
        # Setup mock to return None
        mock_client = Mock()
        mock_client.get_technique.return_value = None
        mock_get_mitre.return_value = mock_client

        # Execute
        result = get_technique_details.invoke({"technique_id": "T9999"})

        # Verify
        assert isinstance(result, dict)
        assert "error" in result
        assert "not found" in result["error"]

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_search_techniques_success(self, mock_get_mitre, mock_mitre_technique):
        """Test searching techniques by keyword."""
        # Setup mock
        mock_client = Mock()
        mock_client.search_techniques.return_value = [mock_mitre_technique]
        mock_get_mitre.return_value = mock_client

        # Execute
        result = search_techniques.invoke({"keyword": "command execution"})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1059"
        mock_client.search_techniques.assert_called_once_with("command execution")

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_search_techniques_no_results(self, mock_get_mitre):
        """Test searching techniques with no results."""
        # Setup mock
        mock_client = Mock()
        mock_client.search_techniques.return_value = []
        mock_get_mitre.return_value = mock_client

        # Execute
        result = search_techniques.invoke({"keyword": "nonexistent"})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 0

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_research_threat_actor_success(self, mock_get_mitre):
        """Test researching threat actor."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_group.return_value = {
            "name": "APT29",
            "description": "Russian state-sponsored group",
            "aliases": ["Cozy Bear", "The Dukes"],
            "type": "intrusion-set",
        }
        mock_get_mitre.return_value = mock_client

        # Execute
        result = research_threat_actor.invoke({"actor_name": "APT29"})

        # Verify
        assert isinstance(result, dict)
        assert result["name"] == "APT29"
        assert "Cozy Bear" in result["aliases"]
        assert result["type"] == "intrusion-set"

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_research_threat_actor_not_found(self, mock_get_mitre):
        """Test researching threat actor not found."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_group.return_value = None
        mock_get_mitre.return_value = mock_client

        # Execute
        result = research_threat_actor.invoke({"actor_name": "UNKNOWN"})

        # Verify
        assert isinstance(result, dict)
        assert "error" in result
        assert "not found" in result["error"]

    @patch("src.agents.threat_agent.get_otx_client")
    def test_get_threat_intelligence_success(self, mock_get_otx):
        """Test getting threat intelligence."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_cve_pulses.return_value = [
            {"name": "Test Pulse", "description": "Test"}
        ]
        mock_client.generate_threat_narrative.return_value = "Threat detected"
        mock_client.get_iocs_for_cve.return_value = {
            "IPv4": ["192.168.1.100"],
            "domain": ["evil.com"]
        }
        mock_get_otx.return_value = mock_client

        # Execute
        result = get_threat_intelligence.invoke({"cve_id": "CVE-2024-12345"})

        # Verify
        assert isinstance(result, dict)
        assert result["cve_id"] == "CVE-2024-12345"
        assert result["pulse_count"] == 1
        assert "IPv4" in result["iocs"]
        assert result["narrative"] == "Threat detected"

    @patch("src.agents.threat_agent.get_otx_client")
    def test_get_threat_intelligence_no_pulses(self, mock_get_otx):
        """Test getting threat intelligence with no pulses."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_cve_pulses.return_value = []
        mock_client.generate_threat_narrative.return_value = "No threat data available"
        mock_get_otx.return_value = mock_client

        # Execute
        result = get_threat_intelligence.invoke({"cve_id": "CVE-2024-99999"})

        # Verify
        assert isinstance(result, dict)
        assert result["pulse_count"] == 0
        assert result["iocs"] == {}
        assert "No threat data" in result["narrative"]

    @patch("src.agents.threat_agent.get_otx_client")
    def test_get_threat_intelligence_exception(self, mock_get_otx):
        """Test getting threat intelligence with exception."""
        # Setup mock to raise exception
        mock_client = Mock()
        mock_client.get_cve_pulses.side_effect = Exception("API error")
        mock_get_otx.return_value = mock_client

        # Execute
        result = get_threat_intelligence.invoke({"cve_id": "CVE-2024-12345"})

        # Verify
        assert isinstance(result, dict)
        assert "error" in result
        assert "API error" in result["error"]

    @patch("src.agents.threat_agent.get_otx_client")
    def test_get_threat_iocs_success(self, mock_get_otx):
        """Test getting IOCs for CVE."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_iocs_for_cve.return_value = {
            "IPv4": ["192.168.1.100", "10.0.0.50"],
            "domain": ["malicious.example.com"],
            "FileHash-MD5": ["abc123"],
        }
        mock_get_otx.return_value = mock_client

        # Execute
        result = get_threat_iocs.invoke({"cve_id": "CVE-2024-12345"})

        # Verify
        assert isinstance(result, dict)
        assert len(result["IPv4"]) == 2
        assert len(result["domain"]) == 1
        assert "malicious.example.com" in result["domain"]

    @patch("src.agents.threat_agent.get_otx_client")
    def test_get_threat_iocs_empty(self, mock_get_otx):
        """Test getting IOCs with no results."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_iocs_for_cve.return_value = {}
        mock_get_otx.return_value = mock_client

        # Execute
        result = get_threat_iocs.invoke({"cve_id": "CVE-2024-99999"})

        # Verify
        assert isinstance(result, dict)
        assert len(result) == 0

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_generate_threat_narrative_success(self, mock_get_mitre, mock_mitre_technique):
        """Test generating threat narrative."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_technique.return_value = mock_mitre_technique
        mock_get_mitre.return_value = mock_client

        # Execute
        result = generate_threat_narrative.invoke({
            "cve_id": "CVE-2024-12345",
            "techniques": ["T1059"],
            "threat_intel": "Active exploitation detected"
        })

        # Verify
        assert isinstance(result, str)
        assert "CVE-2024-12345" in result
        assert "T1059" in result
        assert "Active exploitation detected" in result
        assert "Threat Assessment" in result

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_generate_threat_narrative_no_techniques(self, mock_get_mitre):
        """Test generating narrative without techniques."""
        # Setup mock
        mock_client = Mock()
        mock_get_mitre.return_value = mock_client

        # Execute
        result = generate_threat_narrative.invoke({
            "cve_id": "CVE-2024-12345",
            "techniques": [],
            "threat_intel": "Limited information available"
        })

        # Verify
        assert isinstance(result, str)
        assert "CVE-2024-12345" in result
        assert "Limited information available" in result

    @patch("src.agents.threat_agent.get_mitre_client")
    def test_generate_threat_narrative_exception(self, mock_get_mitre):
        """Test generating narrative with exception."""
        # Setup mock to raise exception
        mock_client = Mock()
        mock_client.get_technique.side_effect = Exception("MITRE API error")
        mock_get_mitre.return_value = mock_client

        # Execute
        result = generate_threat_narrative.invoke({
            "cve_id": "CVE-2024-12345",
            "techniques": ["T1059"],
            "threat_intel": "Test"
        })

        # Verify
        assert isinstance(result, str)
        assert "Error generating threat narrative" in result


class TestThreatAgent:
    """Test ThreatAgent class."""

    @patch("src.agents.threat_agent.ChatAnthropic")
    @patch("src.agents.threat_agent.os.getenv")
    def test_agent_initialization(self, mock_getenv, mock_chat):
        """Test agent initialization."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = ThreatAgent()

        # Verify
        assert agent.model_name == "claude-3-5-sonnet-20241022"
        assert agent.temperature == 0
        assert len(agent.tools) == 7
        assert agent.llm is not None
        assert agent.executor is not None

    @patch("src.agents.threat_agent.ChatAnthropic")
    @patch("src.agents.threat_agent.os.getenv")
    def test_agent_initialization_custom_params(self, mock_getenv, mock_chat):
        """Test agent initialization with custom parameters."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = ThreatAgent(
            model="claude-3-opus-20240229",
            temperature=0.7
        )

        # Verify
        assert agent.model_name == "claude-3-opus-20240229"
        assert agent.temperature == 0.7

    @patch("src.agents.threat_agent.ChatAnthropic")
    @patch("src.agents.threat_agent.os.getenv")
    def test_agent_query_success(self, mock_getenv, mock_chat):
        """Test successful agent query."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = ThreatAgent()

        # Mock executor
        agent.executor = Mock()
        agent.executor.invoke.return_value = {
            "output": "Threat analysis completed"
        }

        # Execute
        result = agent.query("Analyze CVE-2024-12345")

        # Verify
        assert result == "Threat analysis completed"
        agent.executor.invoke.assert_called_once()

    @patch("src.agents.threat_agent.ChatAnthropic")
    @patch("src.agents.threat_agent.os.getenv")
    def test_agent_query_exception(self, mock_getenv, mock_chat):
        """Test agent query with exception."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = ThreatAgent()

        # Mock executor to raise exception
        agent.executor = Mock()
        agent.executor.invoke.side_effect = Exception("Analysis error")

        # Execute
        result = agent.query("Analyze CVE-2024-12345")

        # Verify
        assert "Error processing query" in result
        assert "Analysis error" in result

    @patch("src.agents.threat_agent.ChatAnthropic")
    @patch("src.agents.threat_agent.os.getenv")
    @patch("src.agents.threat_agent.get_mitre_client")
    @patch("src.agents.threat_agent.get_otx_client")
    def test_analyze_cve_threat_success(
        self, mock_get_otx, mock_get_mitre, mock_getenv, mock_chat, mock_mitre_technique
    ):
        """Test analyze_cve_threat method."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Mock MITRE client
        mock_mitre_client = Mock()
        mock_mitre_client.map_cve_to_techniques.return_value = [mock_mitre_technique]
        mock_get_mitre.return_value = mock_mitre_client

        # Mock OTX client
        mock_otx_client = Mock()
        mock_otx_client.get_cve_pulses.return_value = [
            {"name": "Test Pulse", "description": "Test"}
        ]
        mock_otx_client.get_iocs_for_cve.return_value = {"IPv4": ["192.168.1.1"]}
        mock_otx_client.generate_threat_narrative.return_value = "Threat narrative"
        mock_get_otx.return_value = mock_otx_client

        agent = ThreatAgent()

        # Execute
        result = agent.analyze_cve_threat(
            "CVE-2024-12345",
            "Remote code execution vulnerability"
        )

        # Verify
        assert isinstance(result, ThreatIntelligence)
        assert result.cve_id == "CVE-2024-12345"
        assert len(result.techniques) == 1
        assert result.techniques[0].technique_id == "T1059"
        assert "IPv4" in result.iocs
        assert result.narrative == "Threat narrative"

    @patch("src.agents.threat_agent.ChatAnthropic")
    @patch("src.agents.threat_agent.os.getenv")
    @patch("src.agents.threat_agent.get_mitre_client")
    def test_analyze_cve_threat_exception(self, mock_get_mitre, mock_getenv, mock_chat):
        """Test analyze_cve_threat with exception."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Mock MITRE client to raise exception
        mock_mitre_client = Mock()
        mock_mitre_client.map_cve_to_techniques.side_effect = Exception("API error")
        mock_get_mitre.return_value = mock_mitre_client

        agent = ThreatAgent()

        # Execute
        result = agent.analyze_cve_threat(
            "CVE-2024-12345",
            "Test description"
        )

        # Verify - should return empty threat intelligence
        assert isinstance(result, ThreatIntelligence)
        assert result.cve_id == "CVE-2024-12345"
        assert len(result.techniques) == 0
        assert "Error analyzing threat intelligence" in result.narrative


class TestClientSingletons:
    """Test client singleton patterns."""

    @patch("src.agents.threat_agent.MITREClient")
    def test_get_mitre_client_creates_instance(self, mock_client_class):
        """Test that get_mitre_client creates a singleton instance."""
        # Reset the global client
        import src.agents.threat_agent as agent_module
        agent_module._mitre_client = None

        # Setup mock
        mock_instance = Mock()
        mock_client_class.return_value = mock_instance

        # Execute - first call
        client1 = get_mitre_client()

        # Verify instance created
        assert client1 == mock_instance
        mock_client_class.assert_called_once()

        # Execute - second call
        client2 = get_mitre_client()

        # Verify same instance returned (singleton)
        assert client2 == mock_instance
        mock_client_class.assert_called_once()  # Still only called once

    @patch("src.agents.threat_agent.OTXClient")
    def test_get_otx_client_creates_instance(self, mock_client_class):
        """Test that get_otx_client creates a singleton instance."""
        # Reset the global client
        import src.agents.threat_agent as agent_module
        agent_module._otx_client = None

        # Setup mock
        mock_instance = Mock()
        mock_client_class.return_value = mock_instance

        # Execute - first call
        client1 = get_otx_client()

        # Verify instance created
        assert client1 == mock_instance
        mock_client_class.assert_called_once()

        # Execute - second call
        client2 = get_otx_client()

        # Verify same instance returned (singleton)
        assert client2 == mock_instance
        mock_client_class.assert_called_once()  # Still only called once


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
