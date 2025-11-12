"""Tests for ServiceNow client."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.tools.servicenow_client import ServiceNowClient
from src.models.schemas import ServiceNowIncident, CMDBItem
from src.utils.error_handler import APIError, AuthenticationError


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Mock environment variables."""
    monkeypatch.setenv("SERVICENOW_INSTANCE", "https://dev12345.service-now.com")
    monkeypatch.setenv("SERVICENOW_USERNAME", "admin")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "testpass")


@pytest.fixture
def client(mock_env_vars):
    """Create ServiceNow client with mocked credentials."""
    return ServiceNowClient()


@pytest.fixture
def mock_incident_response():
    """Mock ServiceNow incident response."""
    return {
        "result": [
            {
                "number": "INC0010001",
                "short_description": "Test incident",
                "description": "Test description",
                "priority": "1",
                "state": "New",
                "assigned_to": "admin",
                "sys_created_on": "2024-01-01 10:00:00",
                "sys_updated_on": "2024-01-01 10:00:00",
                "sys_id": "abc123",
            }
        ]
    }


@pytest.fixture
def mock_cmdb_response():
    """Mock ServiceNow CMDB response."""
    return {
        "result": [
            {
                "name": "server-prod-01",
                "sys_class_name": "cmdb_ci_server",
                "sys_id": "xyz789",
                "ip_address": "192.168.1.100",
                "dns_domain": "example.com",
                "operational_status": "Operational",
            }
        ]
    }


class TestServiceNowClient:
    """Test ServiceNow client functionality."""

    def test_client_initialization(self, client):
        """Test client initializes with correct credentials."""
        assert client.instance_url == "https://dev12345.service-now.com"
        assert client.username == "admin"
        assert client.password == "testpass"

    def test_client_missing_credentials(self, monkeypatch):
        """Test client raises error with missing credentials."""
        monkeypatch.delenv("SERVICENOW_INSTANCE", raising=False)
        with pytest.raises(ValueError):
            ServiceNowClient()

    def test_build_url(self, client):
        """Test URL building."""
        url = client._build_url("incident")
        assert url == "https://dev12345.service-now.com/api/now/table/incident"

    @patch("requests.request")
    def test_query_incidents_success(self, mock_request, client, mock_incident_response):
        """Test successful incident query."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_incident_response
        mock_request.return_value = mock_response

        incidents = client.query_incidents(priority="1", limit=10)

        assert len(incidents) == 1
        assert isinstance(incidents[0], ServiceNowIncident)
        assert incidents[0].number == "INC0010001"
        assert incidents[0].priority == "1"

    @patch("requests.request")
    def test_query_incidents_empty(self, mock_request, client):
        """Test incident query with no results."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": []}
        mock_request.return_value = mock_response

        incidents = client.query_incidents()

        assert len(incidents) == 0

    @patch("requests.request")
    def test_get_incident_by_number(self, mock_request, client, mock_incident_response):
        """Test getting specific incident."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_incident_response
        mock_request.return_value = mock_response

        incident = client.get_incident("INC0010001")

        assert incident is not None
        assert incident.number == "INC0010001"

    @patch("requests.request")
    def test_get_incident_not_found(self, mock_request, client):
        """Test getting non-existent incident."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": []}
        mock_request.return_value = mock_response

        incident = client.get_incident("INC9999999")

        assert incident is None

    @patch("requests.request")
    def test_create_incident(self, mock_request, client):
        """Test creating incident."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "result": {
                "number": "INC0010002",
                "short_description": "New incident",
                "description": "Test",
                "priority": "2",
                "state": "New",
                "sys_created_on": "2024-01-01 12:00:00",
                "sys_updated_on": "2024-01-01 12:00:00",
                "sys_id": "def456",
            }
        }
        mock_request.return_value = mock_response

        incident = client.create_incident(
            short_description="New incident", description="Test", priority="2"
        )

        assert incident.number == "INC0010002"
        assert incident.priority == "2"

    @patch("requests.request")
    def test_query_cmdb_success(self, mock_request, client, mock_cmdb_response):
        """Test successful CMDB query."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_cmdb_response
        mock_request.return_value = mock_response

        assets = client.query_cmdb(asset_class="cmdb_ci_server")

        assert len(assets) == 1
        assert isinstance(assets[0], CMDBItem)
        assert assets[0].name == "server-prod-01"
        assert assets[0].ip_address == "192.168.1.100"

    @patch("requests.request")
    def test_get_asset_by_name(self, mock_request, client, mock_cmdb_response):
        """Test getting specific asset."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_cmdb_response
        mock_request.return_value = mock_response

        asset = client.get_asset("server-prod-01")

        assert asset is not None
        assert asset.name == "server-prod-01"

    @patch.object(ServiceNowClient, "_make_request")
    def test_authentication_error(self, mock_make_request, client):
        """Test handling of authentication errors."""
        # Mock _make_request to raise AuthenticationError directly
        mock_make_request.side_effect = AuthenticationError("ServiceNow authentication failed")

        with pytest.raises(AuthenticationError):
            client.query_incidents()

    @patch.object(ServiceNowClient, "_make_request")
    def test_api_error(self, mock_make_request, client):
        """Test handling of API errors."""
        # Mock _make_request to raise APIError directly
        mock_make_request.side_effect = APIError("ServiceNow API error")

        with pytest.raises(APIError):
            client.query_incidents()

    @patch("requests.request")
    def test_connection_test_success(self, mock_request, client):
        """Test successful connection test."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": []}
        mock_request.return_value = mock_response

        result = client.test_connection()

        assert result is True

    @patch("requests.request")
    def test_connection_test_failure(self, mock_request, client):
        """Test failed connection test."""
        mock_request.side_effect = Exception("Connection failed")

        result = client.test_connection()

        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
