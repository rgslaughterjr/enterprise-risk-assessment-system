"""Tests for Entity Extractor Agent."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.agents.entity_extractor_agent import EntityExtractorAgent, extract_all_entities, extract_cves_only

@pytest.fixture
def mock_llm():
    with patch('src.agents.entity_extractor_agent.ChatAnthropic') as mock:
        yield mock

@pytest.fixture
def mock_extractor():
    with patch('src.agents.entity_extractor_agent.get_entity_extractor') as mock:
        yield mock

def test_agent_initialization(mock_llm):
    """Test that agent initializes correctly."""
    agent = EntityExtractorAgent()
    assert agent.tools is not None
    assert len(agent.tools) > 0
    mock_llm.assert_called_once()

def test_extract_all_entities_tool(mock_extractor):
    """Test extract_all_entities tool."""
    mock_ext_instance = Mock()
    mock_ext_instance.extract_entities.return_value = {"cves": [], "assets": []}
    mock_extractor.return_value = mock_ext_instance
    
    result = extract_all_entities.invoke({"text": "Sample text"})
    
    assert "cves" in result
    mock_ext_instance.extract_entities.assert_called_with("Sample text")

def test_extract_cves_only_tool(mock_extractor):
    """Test extract_cves_only tool."""
    mock_ext_instance = Mock()
    mock_ext_instance.extract_cves.return_value = [{"value": "CVE-2023-1234"}]
    mock_extractor.return_value = mock_ext_instance
    
    result = extract_cves_only.invoke({"text": "Found CVE-2023-1234"})
    
    assert len(result) == 1
    assert result[0]["value"] == "CVE-2023-1234"
    mock_ext_instance.extract_cves.assert_called_with("Found CVE-2023-1234")

def test_agent_query(mock_llm):
    """Test agent query execution."""
    agent = EntityExtractorAgent()
    agent.executor = Mock()
    agent.executor.invoke.return_value = {"output": "Extracted 2 entities"}
    
    response = agent.query("Extract entities from this text")
    
    assert response == "Extracted 2 entities"
    agent.executor.invoke.assert_called_with({"input": "Extract entities from this text"})
