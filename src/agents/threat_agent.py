"""Threat Research Agent for comprehensive threat intelligence analysis.

This agent combines MITRE ATT&CK framework data with AlienVault OTX threat
intelligence to provide complete threat context for vulnerabilities.
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

from tools.mitre_client import MITREClient
from tools.otx_client import OTXClient
from models.schemas import MITRETechnique, ThreatActor, ThreatIntelligence

load_dotenv()
logger = logging.getLogger(__name__)


# ============================================================================
# Initialize Clients
# ============================================================================

_mitre_client = None
_otx_client = None


def get_mitre_client() -> MITREClient:
    """Get or create MITRE client instance."""
    global _mitre_client
    if _mitre_client is None:
        _mitre_client = MITREClient()
    return _mitre_client


def get_otx_client() -> OTXClient:
    """Get or create OTX client instance."""
    global _otx_client
    if _otx_client is None:
        _otx_client = OTXClient()
    return _otx_client


# ============================================================================
# Tool Definitions
# ============================================================================


@tool
def map_cve_to_techniques(
    cve_id: Annotated[str, "CVE identifier"],
    cve_description: Annotated[str, "CVE description text for mapping"],
) -> List[Dict[str, Any]]:
    """Map a CVE to MITRE ATT&CK techniques.

    Use this tool to identify which attack techniques could be used to exploit
    a vulnerability. This helps understand the tactics and procedures an attacker
    might use.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-12345")
        cve_description: Description of the vulnerability for mapping

    Returns:
        List of relevant MITRE ATT&CK technique dictionaries

    Examples:
        - "Map CVE-2024-1234 to ATT&CK techniques"
        - "What attack techniques could exploit this CVE?"
    """
    try:
        client = get_mitre_client()
        techniques = client.map_cve_to_techniques(cve_id, cve_description)

        return [tech.model_dump() for tech in techniques]

    except Exception as e:
        logger.error(f"Error mapping CVE to techniques: {e}")
        return [{"error": str(e)}]


@tool
def get_technique_details(
    technique_id: Annotated[str, "MITRE ATT&CK technique ID (e.g., T1059)"]
) -> Dict[str, Any]:
    """Get details for a MITRE ATT&CK technique.

    Use this tool to get information about a specific attack technique including
    description, tactics, and target platforms.

    Args:
        technique_id: Technique ID (e.g., "T1059", "T1059.001")

    Returns:
        Dictionary with technique details

    Examples:
        - "Get details for technique T1059"
        - "What is T1203?"
    """
    try:
        client = get_mitre_client()
        technique = client.get_technique(technique_id)

        if technique:
            return technique.model_dump()
        else:
            return {"error": f"Technique {technique_id} not found"}

    except Exception as e:
        logger.error(f"Error getting technique details: {e}")
        return {"error": str(e)}


@tool
def search_techniques(
    keyword: Annotated[str, "Keyword to search for in technique names/descriptions"]
) -> List[Dict[str, Any]]:
    """Search MITRE ATT&CK techniques by keyword.

    Use this tool to find attack techniques related to specific concepts
    like "privilege escalation", "command injection", etc.

    Args:
        keyword: Keyword to search for

    Returns:
        List of matching technique dictionaries

    Examples:
        - "Search for privilege escalation techniques"
        - "Find techniques related to command injection"
    """
    try:
        client = get_mitre_client()
        techniques = client.search_techniques(keyword)

        return [tech.model_dump() for tech in techniques]

    except Exception as e:
        logger.error(f"Error searching techniques: {e}")
        return [{"error": str(e)}]


@tool
def research_threat_actor(
    actor_name: Annotated[str, "Threat actor or APT group name"]
) -> Dict[str, Any]:
    """Research a threat actor using MITRE ATT&CK data.

    Use this tool to get information about APT groups, their tactics,
    and known campaigns.

    Args:
        actor_name: Threat actor name (e.g., "APT29", "Lazarus Group")

    Returns:
        Dictionary with threat actor details

    Examples:
        - "Research APT29"
        - "Get information about Lazarus Group"
        - "What do we know about APT28?"
    """
    try:
        client = get_mitre_client()
        group = client.get_group(actor_name)

        if group:
            return {
                "name": group.get("name"),
                "description": group.get("description", ""),
                "aliases": group.get("aliases", []),
                "type": group.get("type"),
            }
        else:
            return {"error": f"Threat actor {actor_name} not found in MITRE ATT&CK"}

    except Exception as e:
        logger.error(f"Error researching threat actor: {e}")
        return {"error": str(e)}


@tool
def get_threat_intelligence(
    cve_id: Annotated[str, "CVE identifier to research in threat intelligence feeds"]
) -> Dict[str, Any]:
    """Get threat intelligence for a CVE from AlienVault OTX.

    Use this tool to find threat intelligence pulses, IOCs, and campaign
    information related to a CVE.

    Args:
        cve_id: CVE identifier

    Returns:
        Dictionary with threat intelligence data

    Examples:
        - "Get threat intelligence for CVE-2024-1234"
        - "Find IOCs for CVE-2024-5678"
    """
    try:
        client = get_otx_client()

        # Search for pulses
        pulses = client.get_cve_pulses(cve_id)

        # Generate narrative
        narrative = client.generate_threat_narrative(cve_id, pulses)

        # Get IOCs if pulses found
        iocs = {}
        if pulses:
            iocs = client.get_iocs_for_cve(cve_id)

        return {
            "cve_id": cve_id,
            "pulse_count": len(pulses),
            "pulses": pulses[:5],  # Limit to first 5 for readability
            "iocs": iocs,
            "narrative": narrative,
        }

    except Exception as e:
        logger.error(f"Error getting threat intelligence: {e}")
        return {"error": str(e), "narrative": f"Error retrieving data for {cve_id}"}


@tool
def get_threat_iocs(
    cve_id: Annotated[str, "CVE identifier"],
) -> Dict[str, List[str]]:
    """Get Indicators of Compromise (IOCs) for a CVE.

    Use this tool to get IPs, domains, hashes, and other IOCs associated
    with exploitation of a CVE.

    Args:
        cve_id: CVE identifier

    Returns:
        Dictionary mapping IOC type to list of indicators

    Examples:
        - "Get IOCs for CVE-2024-1234"
        - "What are the malicious IPs associated with this CVE?"
    """
    try:
        client = get_otx_client()
        iocs = client.get_iocs_for_cve(cve_id)

        total = sum(len(v) for v in iocs.values())
        logger.info(f"Retrieved {total} IOCs for {cve_id}")

        return iocs

    except Exception as e:
        logger.error(f"Error getting IOCs: {e}")
        return {"error": str(e)}


@tool
def generate_threat_narrative(
    cve_id: Annotated[str, "CVE identifier"],
    techniques: Annotated[List[str], "List of MITRE technique IDs"],
    threat_intel: Annotated[str, "Threat intelligence summary"],
) -> str:
    """Generate a comprehensive threat narrative.

    Use this tool to create a human-readable threat assessment combining
    MITRE ATT&CK techniques and threat intelligence.

    Args:
        cve_id: CVE identifier
        techniques: List of relevant technique IDs
        threat_intel: Threat intelligence summary

    Returns:
        Comprehensive threat narrative

    Examples:
        - "Generate threat narrative for CVE-2024-1234"
    """
    try:
        narrative_parts = [
            f"Threat Assessment for {cve_id}",
            "=" * 60,
            "",
        ]

        # MITRE ATT&CK techniques section
        if techniques:
            narrative_parts.append("MITRE ATT&CK Techniques:")
            narrative_parts.append("-" * 30)

            mitre_client = get_mitre_client()
            for tech_id in techniques:
                tech = mitre_client.get_technique(tech_id)
                if tech:
                    narrative_parts.append(
                        f"- {tech.technique_id} ({tech.name}): "
                        f"Tactics: {', '.join(tech.tactics)}"
                    )

            narrative_parts.append("")

        # Threat intelligence section
        if threat_intel and threat_intel.strip():
            narrative_parts.append("Threat Intelligence:")
            narrative_parts.append("-" * 30)
            narrative_parts.append(threat_intel)
            narrative_parts.append("")

        # Summary
        narrative_parts.append("Conclusion:")
        narrative_parts.append("-" * 30)

        if techniques:
            narrative_parts.append(
                f"This vulnerability may be exploited using {len(techniques)} "
                f"documented attack technique(s)."
            )

        narrative = "\n".join(narrative_parts)
        logger.info(f"Generated threat narrative for {cve_id}")

        return narrative

    except Exception as e:
        logger.error(f"Error generating narrative: {e}")
        return f"Error generating threat narrative: {e}"


# ============================================================================
# Agent Definition
# ============================================================================


class ThreatAgent:
    """Agent for comprehensive threat research and intelligence.

    This agent combines MITRE ATT&CK framework data with AlienVault OTX
    threat intelligence to provide complete threat assessments.
    """

    def __init__(
        self, model: str = "gemini-2.0-flash", temperature: float = 0
    ):
        """Initialize Threat Research Agent.

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
            map_cve_to_techniques,
            get_technique_details,
            search_techniques,
            research_threat_actor,
            get_threat_intelligence,
            get_threat_iocs,
            generate_threat_narrative,
        ]

        # Create prompt
        self.prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are a cybersecurity threat intelligence analyst specializing in
threat research and attack analysis.

Your capabilities:
1. Map CVEs to MITRE ATT&CK techniques and tactics
2. Research attack techniques and procedures
3. Analyze threat actor groups and campaigns
4. Gather threat intelligence from AlienVault OTX
5. Extract Indicators of Compromise (IOCs)
6. Generate comprehensive threat narratives

When analyzing threats:
- Always map CVEs to ATT&CK techniques to understand attack vectors
- Check AlienVault OTX for real-world threat intelligence
- Identify IOCs for detection and blocking
- Research known threat actors exploiting similar vulnerabilities
- Provide actionable intelligence for defenders

MITRE ATT&CK Tactics (in order):
1. Initial Access - How attackers get in
2. Execution - How malicious code runs
3. Persistence - How attackers maintain access
4. Privilege Escalation - How attackers gain higher privileges
5. Defense Evasion - How attackers avoid detection
6. Credential Access - How attackers steal credentials
7. Discovery - How attackers explore the environment
8. Lateral Movement - How attackers move through network
9. Collection - How attackers gather data
10. Command and Control - How attackers communicate
11. Exfiltration - How attackers steal data
12. Impact - How attackers cause damage

When generating threat narratives:
- Start with attack techniques and tactics
- Include threat intelligence context
- List IOCs for detection
- Provide defensive recommendations
- Be clear and actionable
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

        logger.info(f"Threat agent initialized with {len(self.tools)} tools")

    def query(self, user_input: str) -> str:
        """Process threat research query.

        Args:
            user_input: User's query

        Returns:
            Threat analysis response
        """
        try:
            result = self.executor.invoke({"input": user_input})
            return result.get("output", "No response generated")

        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return f"Error processing query: {e}"

    def analyze_cve_threat(
        self, cve_id: str, cve_description: str
    ) -> ThreatIntelligence:
        """Analyze threat intelligence for a CVE (programmatic interface).

        Args:
            cve_id: CVE identifier
            cve_description: CVE description

        Returns:
            ThreatIntelligence object
        """
        try:
            # Map to MITRE techniques
            mitre_client = get_mitre_client()
            techniques = mitre_client.map_cve_to_techniques(cve_id, cve_description)

            # Get threat intelligence
            otx_client = get_otx_client()
            pulses = otx_client.get_cve_pulses(cve_id)
            iocs = otx_client.get_iocs_for_cve(cve_id) if pulses else {}
            narrative = otx_client.generate_threat_narrative(cve_id, pulses)

            # Build threat intelligence
            threat_intel = ThreatIntelligence(
                cve_id=cve_id,
                techniques=techniques,
                threat_actors=[],  # Would need additional parsing
                iocs=iocs,
                narrative=narrative,
            )

            logger.info(f"Completed threat analysis for {cve_id}")
            return threat_intel

        except Exception as e:
            logger.error(f"Error analyzing threat for {cve_id}: {e}")
            # Return empty threat intelligence
            return ThreatIntelligence(
                cve_id=cve_id,
                techniques=[],
                threat_actors=[],
                iocs={},
                narrative=f"Error analyzing threat intelligence: {e}",
            )
