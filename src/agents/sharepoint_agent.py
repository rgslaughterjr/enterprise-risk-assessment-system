"""SharePoint Agent for managing and retrieving documents from SharePoint.

This agent simulates SharePoint functionality using a local filesystem, allowing
listing, searching, and retrieving files with version history and metadata.
"""

import sys
from pathlib import Path

# Ensure src is in path for absolute imports
_src_path = str(Path(__file__).parent.parent)
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

import os
from typing import List, Dict, Optional, Any, Annotated
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_classic.prompts import ChatPromptTemplate
from langchain_core.tools import tool
import logging

from tools.sharepoint_simulator import SharePointSimulator

load_dotenv()
logger = logging.getLogger(__name__)


# ============================================================================
# Initialize Simulator
# ============================================================================

_sharepoint_simulator = None


def get_sharepoint_simulator() -> SharePointSimulator:
    """Get or create SharePoint simulator instance."""
    global _sharepoint_simulator
    if _sharepoint_simulator is None:
        # Use environment variable or default to 'documents' folder
        root_path = os.getenv("SHAREPOINT_ROOT_PATH", "documents")
        _sharepoint_simulator = SharePointSimulator(root_path=root_path)
    return _sharepoint_simulator


# ============================================================================
# Tool Definitions
# ============================================================================


@tool
def list_sharepoint_files(
    path: Annotated[Optional[str], "Directory path to list (relative to root)"] = None,
    recursive: Annotated[bool, "Whether to list recursively"] = True,
    max_depth: Annotated[Optional[int], "Maximum recursion depth"] = None
) -> List[Dict[str, Any]]:
    """List files in a SharePoint directory.

    Use this tool to explore the file structure, find available documents,
    or list contents of specific folders.

    Args:
        path: Directory path (default: root)
        recursive: Whether to recurse into subdirectories
        max_depth: Maximum depth for recursion

    Returns:
        List of file information dictionaries
    """
    try:
        simulator = get_sharepoint_simulator()
        return simulator.list_files(path, max_depth, recursive)
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return []


@tool
def search_sharepoint_files(
    pattern: Annotated[str, "Glob pattern to search for (e.g., '*.pdf')"],
    path: Annotated[Optional[str], "Directory to search in"] = None
) -> List[Dict[str, Any]]:
    """Search for files in SharePoint matching a pattern.

    Use this tool to find specific files by name or extension.

    Args:
        pattern: Glob pattern (e.g., "*.pdf", "**/*.docx")
        path: Directory to search in (default: root)

    Returns:
        List of matching file information
    """
    try:
        simulator = get_sharepoint_simulator()
        return simulator.search_files(path, pattern)
    except Exception as e:
        logger.error(f"Error searching files: {e}")
        return []


@tool
def get_file_metadata(
    file_path: Annotated[str, "Path to the file"]
) -> Dict[str, Any]:
    """Get detailed metadata for a file in SharePoint.

    Use this tool to check file size, modification dates, permissions,
    and other attributes.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with file metadata
    """
    try:
        simulator = get_sharepoint_simulator()
        return simulator.get_file_metadata(file_path)
    except Exception as e:
        logger.error(f"Error getting metadata: {e}")
        return {"error": str(e)}


@tool
def get_version_history(
    file_path: Annotated[str, "Path to the file"]
) -> List[Dict[str, Any]]:
    """Get version history for a file in SharePoint.

    Use this tool to see previous versions of a document.

    Args:
        file_path: Path to file

    Returns:
        List of version information
    """
    try:
        simulator = get_sharepoint_simulator()
        return simulator.get_version_history(file_path)
    except Exception as e:
        logger.error(f"Error getting version history: {e}")
        return []


@tool
def get_file_content(
    file_path: Annotated[str, "Path to the file"]
) -> Dict[str, Any]:
    """Get the content of a file from SharePoint.

    Use this tool to read the contents of a text-based file.
    For binary files (PDF, DOCX), use the Document Agent instead.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with content and metadata
    """
    try:
        simulator = get_sharepoint_simulator()
        return simulator.get_file_content(file_path)
    except Exception as e:
        logger.error(f"Error getting content: {e}")
        return {"error": str(e)}


@tool
def get_sharepoint_statistics() -> Dict[str, Any]:
    """Get statistics about the SharePoint environment.

    Use this tool to get an overview of the SharePoint simulator status.

    Returns:
        Dictionary with simulator statistics
    """
    try:
        simulator = get_sharepoint_simulator()
        return simulator.get_statistics()
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return {"error": str(e)}


# ============================================================================
# Agent Definition
# ============================================================================


class SharePointAgent:
    """Agent for interacting with SharePoint (simulated).

    This agent can list, search, and retrieve files from a simulated
    SharePoint environment using the local filesystem.
    """

    def __init__(
        self, model: str = "gemini-2.0-flash", temperature: float = 0
    ):
        """Initialize SharePoint Agent.

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
            list_sharepoint_files,
            search_sharepoint_files,
            get_file_metadata,
            get_version_history,
            get_file_content,
            get_sharepoint_statistics,
        ]

        # Create prompt
        self.prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are a SharePoint administrator and document management specialist.

Your capabilities:
1. Navigate the SharePoint file structure (simulated)
2. Search for files by name or pattern
3. Retrieve file metadata and version history
4. Read file contents (for text files)
5. Manage document access and organization

When assisting users:
- Always verify file existence before attempting operations
- Use search to find files when paths are unknown
- Check version history for document tracking
- Provide clear summaries of file structures
- Handle permission errors gracefully

For binary files (PDF, DOCX, etc.):
- You can list them and get metadata
- You CANNOT read their content directly (delegate to Document Agent)
- You can check their version history

Always specify exact file paths when using tools.
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

        logger.info(f"SharePoint agent initialized with {len(self.tools)} tools")

    def query(self, user_input: str) -> str:
        """Process SharePoint query.

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
