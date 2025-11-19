"""Tests for SharePoint Agent."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.agents.sharepoint_agent import SharePointAgent, list_sharepoint_files, search_sharepoint_files

@pytest.fixture
def mock_llm():
    with patch('src.agents.sharepoint_agent.ChatAnthropic') as mock:
        yield mock

@pytest.fixture
def mock_simulator():
    with patch('src.agents.sharepoint_agent.get_sharepoint_simulator') as mock:
        yield mock

def test_agent_initialization(mock_llm):
    """Test that agent initializes correctly."""
    agent = SharePointAgent()
    assert agent.tools is not None
    assert len(agent.tools) > 0
    mock_llm.assert_called_once()

def test_list_files_tool(mock_simulator):
    """Test list_files tool."""
    mock_sim_instance = Mock()
    mock_sim_instance.list_files.return_value = [{"name": "test.pdf"}]
    mock_simulator.return_value = mock_sim_instance
    
    result = list_sharepoint_files.invoke({"path": "docs"})
    
    assert len(result) == 1
    assert result[0]["name"] == "test.pdf"
    mock_sim_instance.list_files.assert_called_with("docs", None, True)

def test_search_files_tool(mock_simulator):
    """Test search_files tool."""
    mock_sim_instance = Mock()
    mock_sim_instance.search_files.return_value = [{"name": "found.pdf"}]
    mock_simulator.return_value = mock_sim_instance
    
    result = search_sharepoint_files.invoke({"pattern": "*.pdf"})
    
    assert len(result) == 1
    assert result[0]["name"] == "found.pdf"
    mock_sim_instance.search_files.assert_called_with(None, "*.pdf")

def test_agent_query(mock_llm):
    """Test agent query execution."""
    agent = SharePointAgent()
    agent.executor = Mock()
    agent.executor.invoke.return_value = {"output": "Found 5 files"}
    
    response = agent.query("List files in documents")
    
    assert response == "Found 5 files"
    agent.executor.invoke.assert_called_with({"input": "List files in documents"})
