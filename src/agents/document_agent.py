"""Document Ingestion Agent for parsing and analyzing security documents.

This agent processes PDF, DOCX, and XLSX files to extract security findings,
CVEs, controls, assets, and other relevant information.
"""

import os
from typing import List, Dict, Optional, Any, Annotated
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.prompts import ChatPromptTemplate
from langchain_core.tools import tool
import logging

from ..tools.document_parser import DocumentParser
from ..models.schemas import DocumentAnalysis, ExtractedEntity

load_dotenv()
logger = logging.getLogger(__name__)


# ============================================================================
# Initialize Parser
# ============================================================================

_document_parser = None


def get_document_parser() -> DocumentParser:
    """Get or create document parser instance."""
    global _document_parser
    if _document_parser is None:
        _document_parser = DocumentParser()
    return _document_parser


# ============================================================================
# Tool Definitions
# ============================================================================


@tool
def parse_pdf(
    file_path: Annotated[str, "Path to PDF file to parse"]
) -> Dict[str, Any]:
    """Parse a PDF document and extract text and entities.

    Use this tool to extract content from PDF audit reports, vulnerability
    scans, security assessments, or compliance documents.

    Args:
        file_path: Path to PDF file

    Returns:
        Dictionary with document analysis including text, metadata, and entities

    Examples:
        - "Parse the PDF file at /path/to/audit_report.pdf"
        - "Extract findings from vulnerability_scan.pdf"
    """
    try:
        parser = get_document_parser()
        analysis = parser.parse_document(file_path)

        if analysis:
            return analysis.model_dump()
        else:
            return {"error": f"Failed to parse PDF: {file_path}"}

    except Exception as e:
        logger.error(f"Error parsing PDF {file_path}: {e}")
        return {"error": str(e)}


@tool
def parse_docx(
    file_path: Annotated[str, "Path to DOCX file to parse"]
) -> Dict[str, Any]:
    """Parse a Word document and extract text and entities.

    Use this tool to extract content from Word documents containing
    security policies, procedures, or assessment reports.

    Args:
        file_path: Path to DOCX file

    Returns:
        Dictionary with document analysis

    Examples:
        - "Parse the Word document policy.docx"
        - "Extract text from security_assessment.docx"
    """
    try:
        parser = get_document_parser()
        analysis = parser.parse_document(file_path)

        if analysis:
            return analysis.model_dump()
        else:
            return {"error": f"Failed to parse DOCX: {file_path}"}

    except Exception as e:
        logger.error(f"Error parsing DOCX {file_path}: {e}")
        return {"error": str(e)}


@tool
def parse_excel(
    file_path: Annotated[str, "Path to Excel file to parse"]
) -> Dict[str, Any]:
    """Parse an Excel spreadsheet and extract data.

    Use this tool to extract content from Excel files containing
    risk registers, vulnerability lists, or asset inventories.

    Args:
        file_path: Path to Excel file (.xlsx or .xls)

    Returns:
        Dictionary with document analysis

    Examples:
        - "Parse the Excel file risk_register.xlsx"
        - "Extract data from asset_inventory.xlsx"
    """
    try:
        parser = get_document_parser()
        analysis = parser.parse_document(file_path)

        if analysis:
            return analysis.model_dump()
        else:
            return {"error": f"Failed to parse Excel: {file_path}"}

    except Exception as e:
        logger.error(f"Error parsing Excel {file_path}: {e}")
        return {"error": str(e)}


@tool
def extract_cves(
    file_path: Annotated[str, "Path to document file"]
) -> List[str]:
    """Extract CVE identifiers from a document.

    Use this tool to quickly find all CVE references in a vulnerability
    report or security assessment without parsing the entire document.

    Args:
        file_path: Path to document file (PDF, DOCX, or XLSX)

    Returns:
        List of unique CVE identifiers found

    Examples:
        - "Extract CVEs from vulnerability_report.pdf"
        - "Find all CVE IDs in the audit document"
    """
    try:
        parser = get_document_parser()
        cves = parser.extract_cves_from_document(file_path)
        return cves

    except Exception as e:
        logger.error(f"Error extracting CVEs from {file_path}: {e}")
        return []


@tool
def extract_entities(
    file_path: Annotated[str, "Path to document file"],
    entity_types: Annotated[
        Optional[List[str]],
        "Types of entities to extract (cve, control, asset, risk, finding)",
    ] = None,
) -> List[Dict[str, Any]]:
    """Extract specific types of entities from a document.

    Use this tool to find and extract security-related entities like
    CVEs, controls, assets, risks, or findings from documents.

    Args:
        file_path: Path to document file
        entity_types: Types to extract (default: all types)

    Returns:
        List of entity dictionaries

    Examples:
        - "Extract all entities from audit_report.pdf"
        - "Find controls and assets in compliance_doc.docx"
    """
    try:
        parser = get_document_parser()
        analysis = parser.parse_document(file_path)

        if not analysis:
            return []

        entities = analysis.entities

        # Filter by entity type if specified
        if entity_types:
            entities = [
                e for e in entities if e.entity_type in entity_types
            ]

        return [entity.model_dump() for entity in entities]

    except Exception as e:
        logger.error(f"Error extracting entities from {file_path}: {e}")
        return []


@tool
def get_document_summary(
    file_path: Annotated[str, "Path to document file"]
) -> str:
    """Get a summary of a document's content.

    Use this tool to quickly understand what's in a document without
    reading the entire content.

    Args:
        file_path: Path to document file

    Returns:
        Summary string

    Examples:
        - "Summarize the contents of audit_report.pdf"
        - "What's in the vulnerability scan document?"
    """
    try:
        parser = get_document_parser()
        analysis = parser.parse_document(file_path)

        if analysis:
            return analysis.summary
        else:
            return f"Failed to parse document: {file_path}"

    except Exception as e:
        logger.error(f"Error getting summary for {file_path}: {e}")
        return f"Error: {e}"


@tool
def parse_multiple_documents(
    file_paths: Annotated[List[str], "List of document file paths"]
) -> List[Dict[str, Any]]:
    """Parse multiple documents at once.

    Use this tool to batch process multiple security documents and
    extract findings from all of them.

    Args:
        file_paths: List of paths to document files

    Returns:
        List of document analysis dictionaries

    Examples:
        - "Parse all PDF files in the reports directory"
        - "Extract findings from multiple audit reports"
    """
    results = []
    parser = get_document_parser()

    for file_path in file_paths:
        try:
            analysis = parser.parse_document(file_path)
            if analysis:
                results.append(analysis.model_dump())
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            results.append({"file_path": file_path, "error": str(e)})

    return results


# ============================================================================
# Agent Definition
# ============================================================================


class DocumentAgent:
    """Agent for processing and analyzing security documents.

    This agent can parse PDF, DOCX, and XLSX files to extract security
    findings, CVEs, controls, assets, and other relevant information.
    """

    def __init__(
        self, model: str = "claude-3-5-sonnet-20241022", temperature: float = 0
    ):
        """Initialize Document Ingestion Agent.

        Args:
            model: Anthropic model to use
            temperature: Model temperature
        """
        self.model_name = model
        self.temperature = temperature

        # Initialize LLM
        self.llm = ChatAnthropic(
            model=model,
            temperature=temperature,
            api_key=os.getenv("ANTHROPIC_API_KEY"),
        )

        # Define tools
        self.tools = [
            parse_pdf,
            parse_docx,
            parse_excel,
            extract_cves,
            extract_entities,
            get_document_summary,
            parse_multiple_documents,
        ]

        # Create prompt
        self.prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are a document analysis specialist for cybersecurity documents.

Your capabilities:
1. Parse PDF documents (audit reports, vulnerability scans, assessments)
2. Parse Word documents (policies, procedures, reports)
3. Parse Excel spreadsheets (risk registers, asset lists, vulnerability trackers)
4. Extract CVE identifiers from documents
5. Extract security entities (controls, assets, risks, findings)
6. Generate document summaries
7. Batch process multiple documents

Entity types you can extract:
- CVE: Vulnerability identifiers (CVE-YYYY-NNNNN)
- Control: Security controls (NIST AC-1, ISO 27001, etc.)
- Asset: IT assets (servers, databases, applications)
- Risk: Risk statements and assessments
- Finding: Audit findings and observations

When analyzing documents:
- Extract all relevant security information
- Identify CVEs for further vulnerability analysis
- Note controls mentioned for compliance checking
- List affected assets
- Summarize key findings and risks
- Provide context for each extracted entity

For large documents:
- Focus on security-relevant sections
- Prioritize critical findings
- Group similar entities together
- Provide clear summaries

Always specify the exact file path when using tools.
""",
                ),
                ("human", "{input}"),
                ("placeholder", "{agent_scratchpad}"),
            ]
        )

        # Create agent
        self.agent = create_tool_calling_agent(self.llm, self.tools, self.prompt)

        # Create executor
        self.executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=5,
        )

        logger.info(f"Document agent initialized with {len(self.tools)} tools")

    def query(self, user_input: str) -> str:
        """Process document analysis query.

        Args:
            user_input: User's query

        Returns:
            Analysis response
        """
        try:
            result = self.executor.invoke({"input": user_input})
            return result.get("output", "No response generated")

        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return f"Error processing query: {e}"

    def parse_documents(self, file_paths: List[str]) -> List[DocumentAnalysis]:
        """Parse multiple documents (programmatic interface).

        Args:
            file_paths: List of document paths

        Returns:
            List of DocumentAnalysis objects
        """
        results = []
        parser = get_document_parser()

        for file_path in file_paths:
            try:
                analysis = parser.parse_document(file_path)
                if analysis:
                    results.append(analysis)
            except Exception as e:
                logger.error(f"Error parsing {file_path}: {e}")

        return results
