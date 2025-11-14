"""Tests for ServiceNow Agent Wrapper."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.agents.servicenow_agent import (
    ServiceNowAgent,
    query_incidents,
    get_incident_by_number,
    query_cmdb,
    get_asset_by_name,
    get_servicenow_client,
)
from src.models.schemas import ServiceNowIncident, CMDBItem


@pytest.fixture
def mock_servicenow_client():
    """Mock ServiceNow client."""
    client = Mock()
    client.query_incidents = Mock()
    client.get_incident = Mock()
    client.query_cmdb = Mock()
    client.get_asset = Mock()
    client.query_security_exceptions = Mock()
    client.create_incident = Mock()
    return client


@pytest.fixture
def mock_incident():
    """Mock ServiceNow incident."""
    return ServiceNowIncident(
        number="INC0010001",
        short_description="Critical security vulnerability",
        description="CVE-2024-12345 found on production server",
        priority="1",
        state="New",
        assigned_to="security_team",
        sys_created_on="2024-01-15 10:00:00",
        sys_updated_on="2024-01-15 10:00:00",
        sys_id="abc123",
    )


@pytest.fixture
def mock_cmdb_item():
    """Mock CMDB asset."""
    return CMDBItem(
        name="prod-server-01",
        sys_class_name="cmdb_ci_server",
        sys_id="xyz789",
        ip_address="192.168.1.100",
        dns_domain="example.com",
        operational_status="Operational",
    )


class TestServiceNowAgentTools:
    """Test ServiceNow agent tool functions."""

    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_query_incidents_tool_success(self, mock_get_client, mock_incident):
        """Test successful incident query."""
        # Setup mock
        mock_client = Mock()
        mock_client.query_incidents.return_value = [mock_incident]
        mock_get_client.return_value = mock_client

        # Execute
        result = query_incidents.invoke({
            "priority": "1",
            "state": "New",
            "limit": 10
        })

        # Verify
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["number"] == "INC0010001"
        assert result[0]["priority"] == "1"
        mock_client.query_incidents.assert_called_once_with(priority="1", state="New", limit=10)

    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_query_incidents_tool_empty_results(self, mock_get_client):
        """Test incident query with no results."""
        # Setup mock to return empty list
        mock_client = Mock()
        mock_client.query_incidents.return_value = []
        mock_get_client.return_value = mock_client

        # Execute
        result = query_incidents.invoke({"priority": "1"})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 0

    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_query_incidents_tool_exception(self, mock_get_client):
        """Test incident query handles exceptions."""
        # Setup mock to raise exception
        mock_client = Mock()
        mock_client.query_incidents.side_effect = Exception("ServiceNow API error")
        mock_get_client.return_value = mock_client

        # Execute
        result = query_incidents.invoke({"priority": "1"})

        # Verify error handling
        assert isinstance(result, list)
        assert len(result) == 1
        assert "error" in result[0]
        assert "ServiceNow API error" in result[0]["error"]

    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_get_incident_by_number_success(self, mock_get_client, mock_incident):
        """Test getting specific incident by number."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_incident.return_value = mock_incident
        mock_get_client.return_value = mock_client

        # Execute
        result = get_incident_by_number.invoke({"incident_number": "INC0010001"})

        # Verify
        assert isinstance(result, dict)
        assert result["number"] == "INC0010001"
        assert result["priority"] == "1"
        mock_client.get_incident.assert_called_once_with("INC0010001")

    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_get_incident_by_number_not_found(self, mock_get_client):
        """Test getting incident that doesn't exist."""
        # Setup mock to return None
        mock_client = Mock()
        mock_client.get_incident.return_value = None
        mock_get_client.return_value = mock_client

        # Execute
        result = get_incident_by_number.invoke({"incident_number": "INC9999999"})

        # Verify error response
        assert isinstance(result, dict)
        assert "error" in result
        assert "not found" in result["error"]

    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_query_cmdb_tool_success(self, mock_get_client, mock_cmdb_item):
        """Test successful CMDB query."""
        # Setup mock
        mock_client = Mock()
        mock_client.query_cmdb.return_value = [mock_cmdb_item]
        mock_get_client.return_value = mock_client

        # Execute
        result = query_cmdb.invoke({
            "asset_class": "cmdb_ci_server",
            "limit": 20
        })

        # Verify
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["name"] == "prod-server-01"
        assert result[0]["sys_class_name"] == "cmdb_ci_server"

    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_get_asset_by_name_success(self, mock_get_client, mock_cmdb_item):
        """Test getting specific asset by name."""
        # Setup mock
        mock_client = Mock()
        mock_client.get_asset.return_value = mock_cmdb_item
        mock_get_client.return_value = mock_client

        # Execute
        result = get_asset_by_name.invoke({"asset_name": "prod-server-01"})

        # Verify
        assert isinstance(result, dict)
        assert result["name"] == "prod-server-01"
        assert result["ip_address"] == "192.168.1.100"


class TestServiceNowAgent:
    """Test ServiceNowAgent class."""

    @patch("src.agents.servicenow_agent.ChatAnthropic")
    @patch("src.agents.servicenow_agent.os.getenv")
    def test_agent_initialization(self, mock_getenv, mock_chat):
        """Test ServiceNow agent initialization."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = ServiceNowAgent()

        # Verify
        assert agent.model_name == "claude-3-5-sonnet-20241022"
        assert agent.temperature == 0
        assert len(agent.tools) == 6  # 6 ServiceNow tools
        assert agent.llm is not None
        assert agent.executor is not None

    @patch("src.agents.servicenow_agent.ChatAnthropic")
    @patch("src.agents.servicenow_agent.os.getenv")
    def test_agent_initialization_custom_params(self, mock_getenv, mock_chat):
        """Test agent initialization with custom parameters."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = ServiceNowAgent(
            model="claude-3-opus-20240229",
            temperature=0.2
        )

        # Verify
        assert agent.model_name == "claude-3-opus-20240229"
        assert agent.temperature == 0.2

    @patch("src.agents.servicenow_agent.ChatAnthropic")
    @patch("src.agents.servicenow_agent.os.getenv")
    def test_agent_query_success(self, mock_getenv, mock_chat):
        """Test successful agent query execution."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = ServiceNowAgent()

        # Mock executor
        agent.executor = Mock()
        agent.executor.invoke.return_value = {
            "output": "Found 3 critical priority incidents"
        }

        # Execute
        result = agent.query("Show me critical incidents")

        # Verify
        assert "Found 3 critical priority incidents" in result
        agent.executor.invoke.assert_called_once()

    @patch("src.agents.servicenow_agent.ChatAnthropic")
    @patch("src.agents.servicenow_agent.os.getenv")
    def test_agent_query_exception(self, mock_getenv, mock_chat):
        """Test agent query handles exceptions gracefully."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = ServiceNowAgent()

        # Mock executor to raise exception
        agent.executor = Mock()
        agent.executor.invoke.side_effect = Exception("Connection timeout")

        # Execute
        result = agent.query("Get incidents")

        # Verify error handling
        assert "Error processing query" in result
        assert "Connection timeout" in result

    @patch("src.agents.servicenow_agent.ChatAnthropic")
    @patch("src.agents.servicenow_agent.os.getenv")
    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_get_incidents_for_analysis(self, mock_get_client, mock_getenv, mock_chat, mock_incident):
        """Test get_incidents_for_analysis programmatic method."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        mock_client = Mock()
        mock_client.query_incidents.return_value = [mock_incident]
        mock_get_client.return_value = mock_client

        agent = ServiceNowAgent()

        # Execute
        incidents = agent.get_incidents_for_analysis(priority="1", limit=10)

        # Verify
        assert isinstance(incidents, list)
        assert len(incidents) == 1
        assert isinstance(incidents[0], ServiceNowIncident)
        assert incidents[0].number == "INC0010001"

    @patch("src.agents.servicenow_agent.ChatAnthropic")
    @patch("src.agents.servicenow_agent.os.getenv")
    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_get_incidents_for_analysis_exception(self, mock_get_client, mock_getenv, mock_chat):
        """Test get_incidents_for_analysis handles exceptions."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        mock_client = Mock()
        mock_client.query_incidents.side_effect = Exception("API error")
        mock_get_client.return_value = mock_client

        agent = ServiceNowAgent()

        # Execute
        incidents = agent.get_incidents_for_analysis()

        # Verify returns empty list on error
        assert isinstance(incidents, list)
        assert len(incidents) == 0

    @patch("src.agents.servicenow_agent.ChatAnthropic")
    @patch("src.agents.servicenow_agent.os.getenv")
    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_get_assets_for_analysis(self, mock_get_client, mock_getenv, mock_chat, mock_cmdb_item):
        """Test get_assets_for_analysis programmatic method."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        mock_client = Mock()
        mock_client.query_cmdb.return_value = [mock_cmdb_item]
        mock_get_client.return_value = mock_client

        agent = ServiceNowAgent()

        # Execute
        assets = agent.get_assets_for_analysis(asset_class="cmdb_ci_server")

        # Verify
        assert isinstance(assets, list)
        assert len(assets) == 1
        assert isinstance(assets[0], CMDBItem)
        assert assets[0].name == "prod-server-01"

    @patch("src.agents.servicenow_agent.ChatAnthropic")
    @patch("src.agents.servicenow_agent.os.getenv")
    @patch("src.agents.servicenow_agent.get_servicenow_client")
    def test_authentication_error_handling(self, mock_get_client, mock_getenv, mock_chat):
        """Test agent handles authentication errors without credential leakage."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        mock_client = Mock()
        mock_client.query_incidents.side_effect = Exception("Authentication failed: 401")
        mock_get_client.return_value = mock_client

        agent = ServiceNowAgent()

        # Execute
        incidents = agent.get_incidents_for_analysis()

        # Verify error handled, no credential exposure
        assert len(incidents) == 0
        # In production, would also verify no credentials in logs


class TestServiceNowClientSingleton:
    """Test ServiceNow client singleton pattern."""

    @patch("src.agents.servicenow_agent.ServiceNowClient")
    def test_get_servicenow_client_creates_instance(self, mock_client_class):
        """Test that get_servicenow_client creates a singleton instance."""
        # Reset the global client
        import src.agents.servicenow_agent as agent_module
        agent_module._servicenow_client = None

        # Setup mock
        mock_instance = Mock()
        mock_client_class.return_value = mock_instance

        # Execute - first call
        client1 = get_servicenow_client()

        # Verify instance created
        assert client1 == mock_instance
        mock_client_class.assert_called_once()

        # Execute - second call
        client2 = get_servicenow_client()

        # Verify same instance returned (singleton)
        assert client2 == mock_instance
        mock_client_class.assert_called_once()  # Still only called once


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
