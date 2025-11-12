"""Tests for Document Ingestion Agent."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.agents.document_agent import (
    DocumentAgent,
    parse_pdf,
    parse_docx,
    parse_excel,
    extract_cves,
    extract_entities,
    get_document_summary,
    parse_multiple_documents,
    get_document_parser,
)
from src.models.schemas import DocumentAnalysis, ExtractedEntity, DocumentMetadata


@pytest.fixture
def mock_document_analysis():
    """Mock DocumentAnalysis object."""
    return DocumentAnalysis(
        metadata=DocumentMetadata(
            filename="document.pdf",
            file_type="pdf",
            page_count=10,
            author="Test Author",
        ),
        text_content="This is a test document with CVE-2024-12345",
        summary="Test document summary",
        entities=[
            ExtractedEntity(
                entity_type="cve",
                value="CVE-2024-12345",
                context="Critical vulnerability found",
                confidence=0.95,
            ),
            ExtractedEntity(
                entity_type="control",
                value="NIST AC-1",
                context="Access control policy",
                confidence=0.90,
            ),
        ],
    )


@pytest.fixture
def mock_parser():
    """Mock DocumentParser."""
    parser = Mock()
    parser.parse_document = Mock()
    parser.extract_cves_from_document = Mock()
    return parser


class TestDocumentAgentTools:
    """Test document agent tool functions."""

    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_pdf_success(self, mock_get_parser, mock_document_analysis):
        """Test successful PDF parsing."""
        # Setup mock
        mock_parser = Mock()
        mock_parser.parse_document.return_value = mock_document_analysis
        mock_get_parser.return_value = mock_parser

        # Execute
        result = parse_pdf.invoke({"file_path": "/test/document.pdf"})

        # Verify
        assert isinstance(result, dict)
        assert result["metadata"]["filename"] == "document.pdf"
        assert result["metadata"]["file_type"] == "pdf"
        assert "CVE-2024-12345" in result["text_content"]
        assert len(result["entities"]) == 2
        mock_parser.parse_document.assert_called_once_with("/test/document.pdf")

    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_pdf_failure(self, mock_get_parser):
        """Test PDF parsing failure."""
        # Setup mock to return None
        mock_parser = Mock()
        mock_parser.parse_document.return_value = None
        mock_get_parser.return_value = mock_parser

        # Execute
        result = parse_pdf.invoke({"file_path": "/test/missing.pdf"})

        # Verify
        assert "error" in result
        assert "Failed to parse PDF" in result["error"]

    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_pdf_exception(self, mock_get_parser):
        """Test PDF parsing with exception."""
        # Setup mock to raise exception
        mock_parser = Mock()
        mock_parser.parse_document.side_effect = Exception("File not found")
        mock_get_parser.return_value = mock_parser

        # Execute
        result = parse_pdf.invoke({"file_path": "/test/error.pdf"})

        # Verify
        assert "error" in result
        assert "File not found" in result["error"]

    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_docx_success(self, mock_get_parser, mock_document_analysis):
        """Test successful DOCX parsing."""
        # Setup mock
        mock_parser = Mock()
        mock_document_analysis.metadata.file_type = "docx"
        mock_parser.parse_document.return_value = mock_document_analysis
        mock_get_parser.return_value = mock_parser

        # Execute
        result = parse_docx.invoke({"file_path": "/test/document.docx"})

        # Verify
        assert isinstance(result, dict)
        assert result["metadata"]["file_type"] == "docx"
        assert len(result["entities"]) == 2

    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_excel_success(self, mock_get_parser, mock_document_analysis):
        """Test successful Excel parsing."""
        # Setup mock
        mock_parser = Mock()
        mock_document_analysis.metadata.file_type = "xlsx"
        mock_parser.parse_document.return_value = mock_document_analysis
        mock_get_parser.return_value = mock_parser

        # Execute
        result = parse_excel.invoke({"file_path": "/test/spreadsheet.xlsx"})

        # Verify
        assert isinstance(result, dict)
        assert result["metadata"]["file_type"] == "xlsx"
        assert "entities" in result

    @patch("src.agents.document_agent.get_document_parser")
    def test_extract_cves_success(self, mock_get_parser):
        """Test CVE extraction."""
        # Setup mock
        mock_parser = Mock()
        mock_parser.extract_cves_from_document.return_value = [
            "CVE-2024-12345",
            "CVE-2024-67890",
        ]
        mock_get_parser.return_value = mock_parser

        # Execute
        result = extract_cves.invoke({"file_path": "/test/document.pdf"})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 2
        assert "CVE-2024-12345" in result
        assert "CVE-2024-67890" in result

    @patch("src.agents.document_agent.get_document_parser")
    def test_extract_cves_exception(self, mock_get_parser):
        """Test CVE extraction with exception."""
        # Setup mock to raise exception
        mock_parser = Mock()
        mock_parser.extract_cves_from_document.side_effect = Exception("Parse error")
        mock_get_parser.return_value = mock_parser

        # Execute
        result = extract_cves.invoke({"file_path": "/test/error.pdf"})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 0

    @patch("src.agents.document_agent.get_document_parser")
    def test_extract_entities_all_types(self, mock_get_parser, mock_document_analysis):
        """Test entity extraction without filtering."""
        # Setup mock
        mock_parser = Mock()
        mock_parser.parse_document.return_value = mock_document_analysis
        mock_get_parser.return_value = mock_parser

        # Execute
        result = extract_entities.invoke({"file_path": "/test/document.pdf"})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["entity_type"] == "cve"
        assert result[1]["entity_type"] == "control"

    @patch("src.agents.document_agent.get_document_parser")
    def test_extract_entities_filtered(self, mock_get_parser, mock_document_analysis):
        """Test entity extraction with type filtering."""
        # Setup mock
        mock_parser = Mock()
        mock_parser.parse_document.return_value = mock_document_analysis
        mock_get_parser.return_value = mock_parser

        # Execute - filter for CVEs only
        result = extract_entities.invoke({
            "file_path": "/test/document.pdf",
            "entity_types": ["cve"]
        })

        # Verify
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["entity_type"] == "cve"
        assert result[0]["value"] == "CVE-2024-12345"

    @patch("src.agents.document_agent.get_document_parser")
    def test_extract_entities_no_results(self, mock_get_parser):
        """Test entity extraction with no results."""
        # Setup mock to return None
        mock_parser = Mock()
        mock_parser.parse_document.return_value = None
        mock_get_parser.return_value = mock_parser

        # Execute
        result = extract_entities.invoke({"file_path": "/test/empty.pdf"})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 0

    @patch("src.agents.document_agent.get_document_parser")
    def test_get_document_summary_success(self, mock_get_parser, mock_document_analysis):
        """Test document summary extraction."""
        # Setup mock
        mock_parser = Mock()
        mock_parser.parse_document.return_value = mock_document_analysis
        mock_get_parser.return_value = mock_parser

        # Execute
        result = get_document_summary.invoke({"file_path": "/test/document.pdf"})

        # Verify
        assert isinstance(result, str)
        assert result == "Test document summary"

    @patch("src.agents.document_agent.get_document_parser")
    def test_get_document_summary_failure(self, mock_get_parser):
        """Test document summary with parsing failure."""
        # Setup mock to return None
        mock_parser = Mock()
        mock_parser.parse_document.return_value = None
        mock_get_parser.return_value = mock_parser

        # Execute
        result = get_document_summary.invoke({"file_path": "/test/missing.pdf"})

        # Verify
        assert isinstance(result, str)
        assert "Failed to parse document" in result

    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_multiple_documents_success(self, mock_get_parser, mock_document_analysis):
        """Test parsing multiple documents."""
        # Setup mock
        mock_parser = Mock()
        mock_parser.parse_document.return_value = mock_document_analysis
        mock_get_parser.return_value = mock_parser

        # Execute
        file_paths = ["/test/doc1.pdf", "/test/doc2.pdf"]
        result = parse_multiple_documents.invoke({"file_paths": file_paths})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 2
        assert mock_parser.parse_document.call_count == 2

    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_multiple_documents_partial_failure(self, mock_get_parser, mock_document_analysis):
        """Test parsing multiple documents with some failures."""
        # Setup mock - first succeeds, second fails
        mock_parser = Mock()
        mock_parser.parse_document.side_effect = [
            mock_document_analysis,
            Exception("Parse error")
        ]
        mock_get_parser.return_value = mock_parser

        # Execute
        file_paths = ["/test/doc1.pdf", "/test/doc2.pdf"]
        result = parse_multiple_documents.invoke({"file_paths": file_paths})

        # Verify
        assert isinstance(result, list)
        assert len(result) == 2
        assert "metadata" in result[0]  # First succeeded
        assert "error" in result[1]  # Second failed


class TestDocumentAgent:
    """Test DocumentAgent class."""

    @patch("src.agents.document_agent.ChatAnthropic")
    @patch("src.agents.document_agent.os.getenv")
    def test_agent_initialization(self, mock_getenv, mock_chat):
        """Test agent initialization."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = DocumentAgent()

        # Verify
        assert agent.model_name == "claude-3-5-sonnet-20241022"
        assert agent.temperature == 0
        assert len(agent.tools) == 7
        assert agent.llm is not None
        assert agent.executor is not None

    @patch("src.agents.document_agent.ChatAnthropic")
    @patch("src.agents.document_agent.os.getenv")
    def test_agent_initialization_custom_params(self, mock_getenv, mock_chat):
        """Test agent initialization with custom parameters."""
        # Setup
        mock_getenv.return_value = "test-api-key"

        # Execute
        agent = DocumentAgent(
            model="claude-3-opus-20240229",
            temperature=0.5
        )

        # Verify
        assert agent.model_name == "claude-3-opus-20240229"
        assert agent.temperature == 0.5

    @patch("src.agents.document_agent.ChatAnthropic")
    @patch("src.agents.document_agent.os.getenv")
    def test_agent_query_success(self, mock_getenv, mock_chat):
        """Test successful agent query."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = DocumentAgent()

        # Mock executor
        agent.executor = Mock()
        agent.executor.invoke.return_value = {
            "output": "Document parsed successfully"
        }

        # Execute
        result = agent.query("Parse document.pdf")

        # Verify
        assert result == "Document parsed successfully"
        agent.executor.invoke.assert_called_once()

    @patch("src.agents.document_agent.ChatAnthropic")
    @patch("src.agents.document_agent.os.getenv")
    def test_agent_query_exception(self, mock_getenv, mock_chat):
        """Test agent query with exception."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        agent = DocumentAgent()

        # Mock executor to raise exception
        agent.executor = Mock()
        agent.executor.invoke.side_effect = Exception("Processing error")

        # Execute
        result = agent.query("Parse document.pdf")

        # Verify
        assert "Error processing query" in result
        assert "Processing error" in result

    @patch("src.agents.document_agent.ChatAnthropic")
    @patch("src.agents.document_agent.os.getenv")
    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_documents_method(self, mock_get_parser, mock_getenv, mock_chat, mock_document_analysis):
        """Test parse_documents programmatic method."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        mock_parser = Mock()
        mock_parser.parse_document.return_value = mock_document_analysis
        mock_get_parser.return_value = mock_parser

        agent = DocumentAgent()

        # Execute
        file_paths = ["/test/doc1.pdf", "/test/doc2.pdf"]
        results = agent.parse_documents(file_paths)

        # Verify
        assert len(results) == 2
        assert all(isinstance(r, DocumentAnalysis) for r in results)
        assert mock_parser.parse_document.call_count == 2

    @patch("src.agents.document_agent.ChatAnthropic")
    @patch("src.agents.document_agent.os.getenv")
    @patch("src.agents.document_agent.get_document_parser")
    def test_parse_documents_with_errors(self, mock_get_parser, mock_getenv, mock_chat, mock_document_analysis):
        """Test parse_documents with some errors."""
        # Setup
        mock_getenv.return_value = "test-api-key"
        mock_parser = Mock()
        mock_parser.parse_document.side_effect = [
            mock_document_analysis,
            Exception("Parse error"),
            mock_document_analysis
        ]
        mock_get_parser.return_value = mock_parser

        agent = DocumentAgent()

        # Execute
        file_paths = ["/test/doc1.pdf", "/test/doc2.pdf", "/test/doc3.pdf"]
        results = agent.parse_documents(file_paths)

        # Verify - only successful parses returned
        assert len(results) == 2
        assert mock_parser.parse_document.call_count == 3


class TestDocumentParserSingleton:
    """Test document parser singleton pattern."""

    @patch("src.agents.document_agent.DocumentParser")
    def test_get_document_parser_creates_instance(self, mock_parser_class):
        """Test that get_document_parser creates a singleton instance."""
        # Reset the global parser
        import src.agents.document_agent as agent_module
        agent_module._document_parser = None

        # Setup mock
        mock_instance = Mock()
        mock_parser_class.return_value = mock_instance

        # Execute - first call
        parser1 = get_document_parser()

        # Verify instance created
        assert parser1 == mock_instance
        mock_parser_class.assert_called_once()

        # Execute - second call
        parser2 = get_document_parser()

        # Verify same instance returned (singleton)
        assert parser2 == mock_instance
        mock_parser_class.assert_called_once()  # Still only called once


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
