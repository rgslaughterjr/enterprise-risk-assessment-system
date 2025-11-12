"""ServiceNow Query Agent for retrieving incident and asset data.

This agent provides natural language interface to ServiceNow, allowing users to query
incidents, CMDB assets, and security exceptions using conversational queries.
"""

import os
from typing import List, Dict, Optional, Any, Annotated
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_classic.prompts import ChatPromptTemplate
from langchain_core.tools import tool
import logging

from ..tools.servicenow_client import ServiceNowClient
from ..models.schemas import ServiceNowIncident, CMDBItem

load_dotenv()
logger = logging.getLogger(__name__)


# ============================================================================
# Tool Definitions
# ============================================================================

# Initialize ServiceNow client (shared across tools)
_servicenow_client = None


def get_servicenow_client() -> ServiceNowClient:
    """Get or create ServiceNow client instance."""
    global _servicenow_client
    if _servicenow_client is None:
        _servicenow_client = ServiceNowClient()
    return _servicenow_client


@tool
def query_incidents(
    priority: Annotated[Optional[str], "Priority level (1-5). 1 is highest, 5 is lowest"] = None,
    state: Annotated[Optional[str], "Incident state (e.g., 'New', 'In Progress', 'Resolved')"] = None,
    limit: Annotated[int, "Maximum number of incidents to return"] = 50,
) -> List[Dict[str, Any]]:
    """Query incidents from ServiceNow.

    Use this tool to retrieve incidents from ServiceNow based on priority, state, or other criteria.
    Useful for finding security incidents, checking incident status, or getting incident details.

    Args:
        priority: Filter by priority level (1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning)
        state: Filter by state (New, In Progress, On Hold, Resolved, Closed, Cancelled)
        limit: Maximum number of incidents to return (default 50)

    Returns:
        List of incident dictionaries with details including number, description, priority, state, etc.

    Examples:
        - "Find all critical priority incidents"
        - "Show me incidents in progress"
        - "Get the latest 10 security incidents"
    """
    try:
        client = get_servicenow_client()
        incidents = client.query_incidents(priority=priority, state=state, limit=limit)

        # Convert to dictionaries for JSON serialization
        return [incident.model_dump() for incident in incidents]

    except Exception as e:
        logger.error(f"Error querying incidents: {e}")
        return [{"error": str(e)}]


@tool
def get_incident_by_number(
    incident_number: Annotated[str, "Incident number (e.g., INC0010001)"]
) -> Dict[str, Any]:
    """Get a specific incident by its incident number.

    Use this tool to retrieve detailed information about a specific incident when you know its number.

    Args:
        incident_number: The incident number (e.g., INC0010001, INC0010002)

    Returns:
        Dictionary with incident details or error if not found

    Examples:
        - "Get details for incident INC0010001"
        - "Show me incident INC0010005"
    """
    try:
        client = get_servicenow_client()
        incident = client.get_incident(incident_number)

        if incident:
            return incident.model_dump()
        else:
            return {"error": f"Incident {incident_number} not found"}

    except Exception as e:
        logger.error(f"Error getting incident {incident_number}: {e}")
        return {"error": str(e)}


@tool
def query_cmdb(
    asset_class: Annotated[
        Optional[str],
        "Asset class type (e.g., 'cmdb_ci_server', 'cmdb_ci_computer', 'cmdb_ci_network_adapter')",
    ] = None,
    name: Annotated[Optional[str], "Asset name to search for (partial match)"] = None,
    limit: Annotated[int, "Maximum number of assets to return"] = 50,
) -> List[Dict[str, Any]]:
    """Query the Configuration Management Database (CMDB) for assets.

    Use this tool to find servers, computers, network devices, and other IT assets.
    Useful for checking what assets are affected by vulnerabilities or incidents.

    Args:
        asset_class: Type of asset to search (server, computer, network device, etc.)
        name: Asset name to search (supports partial matching)
        limit: Maximum number of assets to return (default 50)

    Returns:
        List of asset dictionaries with details including name, class, IP address, status, etc.

    Examples:
        - "Find all servers in CMDB"
        - "Get assets with 'prod' in the name"
        - "Show me all network adapters"
    """
    try:
        client = get_servicenow_client()
        assets = client.query_cmdb(asset_class=asset_class, name=name, limit=limit)

        # Convert to dictionaries
        return [asset.model_dump() for asset in assets]

    except Exception as e:
        logger.error(f"Error querying CMDB: {e}")
        return [{"error": str(e)}]


@tool
def get_asset_by_name(
    asset_name: Annotated[str, "Exact asset name to retrieve"]
) -> Dict[str, Any]:
    """Get a specific asset from CMDB by its exact name.

    Use this tool when you need detailed information about a specific asset.

    Args:
        asset_name: The exact name of the asset

    Returns:
        Dictionary with asset details or error if not found

    Examples:
        - "Get details for server web-prod-01"
        - "Show me asset database-server-01"
    """
    try:
        client = get_servicenow_client()
        asset = client.get_asset(asset_name)

        if asset:
            return asset.model_dump()
        else:
            return {"error": f"Asset {asset_name} not found"}

    except Exception as e:
        logger.error(f"Error getting asset {asset_name}: {e}")
        return {"error": str(e)}


@tool
def query_security_exceptions(
    state: Annotated[
        Optional[str], "Exception state (e.g., 'Approved', 'Pending', 'Rejected')"
    ] = None,
    limit: Annotated[int, "Maximum number of exceptions to return"] = 50,
) -> List[Dict[str, Any]]:
    """Query security exceptions (risk acceptances) from ServiceNow.

    Use this tool to find approved security exceptions, pending risk acceptances,
    or to check if a specific risk has been accepted.

    Args:
        state: Filter by approval state (Approved, Pending, Rejected)
        limit: Maximum number of exceptions to return (default 50)

    Returns:
        List of security exception dictionaries

    Examples:
        - "Find all approved security exceptions"
        - "Show me pending risk acceptances"
        - "Get security exceptions"
    """
    try:
        client = get_servicenow_client()
        exceptions = client.query_security_exceptions(state=state, limit=limit)
        return exceptions

    except Exception as e:
        logger.error(f"Error querying security exceptions: {e}")
        return [{"error": str(e)}]


@tool
def create_incident(
    short_description: Annotated[str, "Brief description of the incident"],
    description: Annotated[Optional[str], "Detailed description of the incident"] = None,
    priority: Annotated[str, "Priority level (1-5, where 1 is highest)"] = "3",
) -> Dict[str, Any]:
    """Create a new incident in ServiceNow.

    Use this tool to create incidents for security findings, vulnerabilities,
    or other issues that need to be tracked.

    Args:
        short_description: Brief summary of the incident
        description: Detailed description (optional)
        priority: Priority level (1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning)

    Returns:
        Dictionary with created incident details including incident number

    Examples:
        - "Create a critical incident for CVE-2024-12345 found on production server"
        - "Open an incident for failed security patch deployment"
    """
    try:
        client = get_servicenow_client()
        incident = client.create_incident(
            short_description=short_description,
            description=description,
            priority=priority,
        )

        return incident.model_dump()

    except Exception as e:
        logger.error(f"Error creating incident: {e}")
        return {"error": str(e)}


# ============================================================================
# Agent Definition
# ============================================================================

class ServiceNowAgent:
    """Agent for querying ServiceNow using natural language.

    This agent can:
    - Query incidents by priority, state, or other criteria
    - Search CMDB for assets
    - Retrieve security exceptions
    - Create new incidents

    The agent uses LangChain's tool calling to convert natural language queries
    into ServiceNow API calls.
    """

    def __init__(self, model: str = "claude-3-5-sonnet-20241022", temperature: float = 0):
        """Initialize ServiceNow agent.

        Args:
            model: Anthropic model to use
            temperature: Model temperature (0 for deterministic)
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
            query_incidents,
            get_incident_by_number,
            query_cmdb,
            get_asset_by_name,
            query_security_exceptions,
            create_incident,
        ]

        # Create prompt template
        self.prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are a helpful ServiceNow assistant that helps users query incidents,
assets, and security data from ServiceNow.

Your capabilities:
1. Query incidents by priority, state, or other criteria
2. Get specific incidents by number
3. Search CMDB for assets (servers, computers, network devices)
4. Get specific assets by name
5. Query security exceptions and risk acceptances
6. Create new incidents for security findings

When responding:
- Be concise and focus on the most relevant information
- Format incident numbers, asset names, and other identifiers clearly
- If no results are found, explain what was searched
- For large result sets, summarize key findings
- Always include incident numbers and asset names in your responses

Priority levels:
- 1 = Critical
- 2 = High
- 3 = Moderate
- 4 = Low
- 5 = Planning

Common incident states: New, In Progress, On Hold, Resolved, Closed, Cancelled

When creating incidents:
- Use priority 1 for critical security issues
- Use priority 2 for high-severity vulnerabilities
- Use priority 3 for moderate issues
- Include detailed descriptions when available
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

        logger.info(f"ServiceNow agent initialized with {len(self.tools)} tools")

    def query(self, user_input: str) -> str:
        """Process a natural language query about ServiceNow data.

        Args:
            user_input: User's natural language query

        Returns:
            Agent's response

        Examples:
            >>> agent = ServiceNowAgent()
            >>> response = agent.query("Show me all critical priority incidents")
            >>> print(response)
        """
        try:
            result = self.executor.invoke({"input": user_input})
            return result.get("output", "No response generated")

        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return f"Error processing query: {e}"

    def get_incidents_for_analysis(
        self, priority: Optional[str] = None, limit: int = 50
    ) -> List[ServiceNowIncident]:
        """Get incidents directly for analysis (bypasses LLM).

        Useful for programmatic access to incidents without natural language processing.

        Args:
            priority: Filter by priority
            limit: Maximum number of incidents

        Returns:
            List of ServiceNowIncident objects
        """
        try:
            client = get_servicenow_client()
            return client.query_incidents(priority=priority, limit=limit)
        except Exception as e:
            logger.error(f"Error getting incidents: {e}")
            return []

    def get_assets_for_analysis(
        self, asset_class: Optional[str] = None, limit: int = 50
    ) -> List[CMDBItem]:
        """Get CMDB assets directly for analysis (bypasses LLM).

        Args:
            asset_class: Filter by asset class
            limit: Maximum number of assets

        Returns:
            List of CMDBItem objects
        """
        try:
            client = get_servicenow_client()
            return client.query_cmdb(asset_class=asset_class, limit=limit)
        except Exception as e:
            logger.error(f"Error getting assets: {e}")
            return []


# ============================================================================
# Standalone Functions (for use in LangGraph)
# ============================================================================

def servicenow_query_tool(query: str) -> str:
    """Standalone function for ServiceNow queries (usable in LangGraph nodes).

    Args:
        query: Natural language query

    Returns:
        Query response
    """
    agent = ServiceNowAgent()
    return agent.query(query)


def get_servicenow_incidents(priority: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get ServiceNow incidents for LangGraph state.

    Args:
        priority: Filter by priority

    Returns:
        List of incident dictionaries
    """
    agent = ServiceNowAgent()
    incidents = agent.get_incidents_for_analysis(priority=priority)
    return [inc.model_dump() for inc in incidents]


def get_servicenow_assets() -> List[Dict[str, Any]]:
    """Get CMDB assets for LangGraph state.

    Returns:
        List of asset dictionaries
    """
    agent = ServiceNowAgent()
    assets = agent.get_assets_for_analysis()
    return [asset.model_dump() for asset in assets]
