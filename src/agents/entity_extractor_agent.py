"""Entity Extractor Agent for identifying security entities in text.

This agent uses regex and NLP to extract CVEs, controls, assets, risks,
and other security-related entities from text.
"""

import os
from typing import List, Dict, Optional, Any, Annotated
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_classic.prompts import ChatPromptTemplate
from langchain_core.tools import tool
import logging

from ..tools.entity_extractor import EntityExtractor

load_dotenv()
logger = logging.getLogger(__name__)


# ============================================================================
# Initialize Extractor
# ============================================================================

_entity_extractor = None


def get_entity_extractor() -> EntityExtractor:
    """Get or create entity extractor instance."""
    global _entity_extractor
    if _entity_extractor is None:
        _entity_extractor = EntityExtractor()
    return _entity_extractor


# ============================================================================
# Tool Definitions
# ============================================================================


@tool
def extract_all_entities(
    text: Annotated[str, "Text to analyze"]
) -> Dict[str, Any]:
    """Extract all supported entity types from text.

    Use this tool to get a comprehensive list of CVEs, controls, assets,
    risks, and frameworks mentioned in the text.

    Args:
        text: Text to analyze

    Returns:
        Dictionary with extracted entities
    """
    try:
        extractor = get_entity_extractor()
        return extractor.extract_entities(text)
    except Exception as e:
        logger.error(f"Error extracting entities: {e}")
        return {"error": str(e)}


@tool
def extract_cves_only(
    text: Annotated[str, "Text to analyze"]
) -> List[Dict[str, Any]]:
    """Extract only CVE identifiers from text.

    Use this tool when you specifically need to find vulnerabilities.

    Args:
        text: Text to analyze

    Returns:
        List of CVE entities
    """
    try:
        extractor = get_entity_extractor()
        return extractor.extract_cves(text)
    except Exception as e:
        logger.error(f"Error extracting CVEs: {e}")
        return []


@tool
def extract_controls_only(
    text: Annotated[str, "Text to analyze"]
) -> List[Dict[str, Any]]:
    """Extract only security controls from text.

    Use this tool to find NIST, ISO, CIS, or PCI-DSS controls.

    Args:
        text: Text to analyze

    Returns:
        List of control entities
    """
    try:
        extractor = get_entity_extractor()
        return extractor.extract_controls(text)
    except Exception as e:
        logger.error(f"Error extracting controls: {e}")
        return []


@tool
def extract_assets_only(
    text: Annotated[str, "Text to analyze"]
) -> List[Dict[str, Any]]:
    """Extract only asset mentions from text.

    Use this tool to identify servers, databases, applications, etc.

    Args:
        text: Text to analyze

    Returns:
        List of asset entities
    """
    try:
        extractor = get_entity_extractor()
        return extractor.extract_assets(text)
    except Exception as e:
        logger.error(f"Error extracting assets: {e}")
        return []


@tool
def get_extractor_statistics() -> Dict[str, Any]:
    """Get statistics about the entity extractor.

    Use this tool to check supported entity types and configuration.

    Returns:
        Dictionary with extractor statistics
    """
    try:
        extractor = get_entity_extractor()
        return extractor.get_statistics()
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return {"error": str(e)}


# ============================================================================
# Agent Definition
# ============================================================================


class EntityExtractorAgent:
    """Agent for extracting security entities from text.

    This agent specializes in identifying and structuring security-related
    information such as CVEs, controls, assets, and risks.
    """

    def __init__(
        self, model: str = "gemini-1.5-pro", temperature: float = 0
    ):
        """Initialize Entity Extractor Agent.

        Args:
            model: Google Gemini model to use
            temperature: Model temperature
        """
        self.model_name = model
        self.temperature = temperature

        # Initialize LLM
        self.llm = ChatGoogleGenerativeAI(
            model=model,
            temperature=temperature,
            google_api_key=os.getenv("GOOGLE_API_KEY"),
        )

        # Define tools
        self.tools = [
            extract_all_entities,
            extract_cves_only,
            extract_controls_only,
            extract_assets_only,
            get_extractor_statistics,
        ]

        # Create prompt
        self.prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are a security entity extraction specialist.

Your capabilities:
1. Identify and extract CVE identifiers (e.g., CVE-2023-12345)
2. Recognize security controls (NIST, ISO, CIS, PCI-DSS)
3. Detect IT assets (servers, databases, applications)
4. Identify risks, threats, and impacts
5. Recognize security frameworks

When analyzing text:
- Focus on precision and context
- Provide confidence scores for extractions
- Group related entities (e.g., a CVE affecting a specific Asset)
- Filter out false positives
- Structure unstructured text into actionable data

Use the specific extraction tools when you only need one type of entity,
or 'extract_all_entities' for a comprehensive analysis.
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

        logger.info(f"Entity Extractor agent initialized with {len(self.tools)} tools")

    def query(self, user_input: str) -> str:
        """Process entity extraction query.

        Args:
            user_input: User's query

        Returns:
            Agent response
        """
        try:
            result = self.executor.invoke({"input": user_input})
            return result.get("output", "No response generated")

        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return f"Error processing query: {e}"
