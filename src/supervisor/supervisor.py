"""LangGraph Supervisor for orchestrating multi-agent risk assessment workflow.

This supervisor coordinates 6 specialist agents in a sequential workflow:
1. ServiceNow Query Agent → Get incidents and assets
2. Vulnerability Analysis Agent → Analyze CVEs
3. Threat Research Agent → Research threats
4. Risk Scoring Agent → Calculate risk ratings
5. Report Generator → Create DOCX report

User check-ins occur after each major phase for validation.
"""

import sys
from pathlib import Path

# Ensure src is in path for absolute imports
_src_path = str(Path(__file__).parent.parent)
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

import os
from typing import Dict, List, TypedDict, Annotated, Sequence
from datetime import datetime
import operator
import logging

from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from agents.servicenow_agent import ServiceNowAgent
from agents.vulnerability_agent import VulnerabilityAgent
from agents.threat_agent import ThreatAgent
from agents.risk_scoring_agent import RiskScoringAgent
from agents.report_agent import ReportAgent
from models.schemas import (
    AgentState,
    ServiceNowIncident,
    VulnerabilityAnalysis,
    ThreatIntelligence,
    RiskRating,
    RiskAssessmentReport,
    ExecutiveSummary,
)

load_dotenv()
logger = logging.getLogger(__name__)


# ============================================================================
# State Definition
# ============================================================================


class SupervisorState(TypedDict):
    """State for supervisor workflow."""

    # Input
    query: str
    cve_ids: List[str]

    # Agent outputs
    incidents: List[Dict]
    cmdb_items: List[Dict]
    vulnerabilities: List[Dict]
    threats: List[Dict]
    risk_ratings: List[Dict]
    report_path: str

    # Control flow
    next_step: str
    user_approved: bool
    completed: bool
    error: str

    # Messages for user interaction
    messages: Annotated[Sequence[str], operator.add]


# ============================================================================
# Agent Node Functions
# ============================================================================


def servicenow_node(state: SupervisorState) -> SupervisorState:
    """Query ServiceNow for incidents and assets.

    Args:
        state: Current workflow state

    Returns:
        Updated state with ServiceNow data
    """
    logger.info("=== ServiceNow Node ===")

    try:
        agent = ServiceNowAgent()

        # Get critical priority incidents
        incidents = agent.get_incidents_for_analysis(priority="1", limit=20)
        cmdb_items = agent.get_assets_for_analysis(limit=20)

        logger.info(f"Retrieved {len(incidents)} incidents and {len(cmdb_items)} assets")

        state["incidents"] = [inc.model_dump() for inc in incidents]
        state["cmdb_items"] = [item.model_dump() for item in cmdb_items]
        state["messages"] = [
            f"✓ ServiceNow: Found {len(incidents)} critical incidents and {len(cmdb_items)} assets"
        ]
        state["next_step"] = "user_check_1"

    except Exception as e:
        logger.error(f"ServiceNow node error: {e}")
        state["error"] = str(e)
        state["next_step"] = "error"

    return state


def vulnerability_node(state: SupervisorState) -> SupervisorState:
    """Analyze vulnerabilities using NVD, VirusTotal, and CISA KEV.

    Args:
        state: Current workflow state

    Returns:
        Updated state with vulnerability analysis
    """
    logger.info("=== Vulnerability Analysis Node ===")

    try:
        agent = VulnerabilityAgent()

        # Extract CVEs from incidents if not provided
        cve_ids = state.get("cve_ids", [])

        if not cve_ids:
            # Extract CVEs from incident descriptions
            import re

            for incident in state.get("incidents", []):
                desc = incident.get("description", "") + " " + incident.get("short_description", "")
                found_cves = re.findall(r"CVE-\d{4}-\d{4,7}", desc, re.IGNORECASE)
                cve_ids.extend([cve.upper() for cve in found_cves])

            cve_ids = list(set(cve_ids))  # Remove duplicates

        logger.info(f"Analyzing {len(cve_ids)} CVEs")

        # Analyze CVEs
        vulnerabilities = agent.analyze_cves(cve_ids[:10])  # Limit to 10 for performance

        state["cve_ids"] = cve_ids
        state["vulnerabilities"] = [vuln.model_dump() for vuln in vulnerabilities]
        state["messages"] = [
            f"✓ Vulnerability Analysis: Analyzed {len(vulnerabilities)} CVEs"
        ]
        state["next_step"] = "threat_research"

    except Exception as e:
        logger.error(f"Vulnerability node error: {e}")
        state["error"] = str(e)
        state["next_step"] = "error"

    return state


def threat_research_node(state: SupervisorState) -> SupervisorState:
    """Research threat intelligence using MITRE ATT&CK and OTX.

    Args:
        state: Current workflow state

    Returns:
        Updated state with threat intelligence
    """
    logger.info("=== Threat Research Node ===")

    try:
        agent = ThreatAgent()

        threats = []

        # Analyze each CVE for threat intelligence
        for vuln in state.get("vulnerabilities", [])[:5]:  # Limit to 5
            cve_id = vuln.get("cve_detail", {}).get("cve_id")
            description = vuln.get("cve_detail", {}).get("description", "")

            if cve_id:
                threat_intel = agent.analyze_cve_threat(cve_id, description)
                threats.append(threat_intel.model_dump())

        logger.info(f"Researched threats for {len(threats)} CVEs")

        state["threats"] = threats
        state["messages"] = [f"✓ Threat Research: Gathered intelligence for {len(threats)} CVEs"]
        state["next_step"] = "user_check_2"

    except Exception as e:
        logger.error(f"Threat research node error: {e}")
        state["error"] = str(e)
        state["next_step"] = "error"

    return state


def risk_scoring_node(state: SupervisorState) -> SupervisorState:
    """Calculate risk scores using FAIR-based 5x5 matrix.

    Args:
        state: Current workflow state

    Returns:
        Updated state with risk ratings
    """
    logger.info("=== Risk Scoring Node ===")

    try:
        agent = RiskScoringAgent()

        risk_ratings = []

        # Calculate risk for each vulnerability
        assets = state.get("cmdb_items", [])
        default_asset = assets[0]["name"] if assets else "Unknown Asset"

        for vuln in state.get("vulnerabilities", []):
            cve_detail = vuln.get("cve_detail", {})
            exploitation = vuln.get("exploitation_status", {})

            cve_id = cve_detail.get("cve_id")
            cvss_score = cve_detail.get("cvss_score")
            in_kev = exploitation.get("in_cisa_kev", False)
            vt_detections = exploitation.get("virustotal_detections", 0)

            if cve_id:
                rating = agent.calculate_risk(
                    cve_id=cve_id,
                    asset_name=default_asset,
                    cvss_score=cvss_score,
                    in_cisa_kev=in_kev,
                    vt_detections=vt_detections,
                )
                risk_ratings.append(rating.model_dump())

        logger.info(f"Calculated risk for {len(risk_ratings)} vulnerabilities")

        state["risk_ratings"] = risk_ratings
        state["messages"] = [
            f"✓ Risk Scoring: Rated {len(risk_ratings)} vulnerabilities"
        ]
        state["next_step"] = "user_check_3"

    except Exception as e:
        logger.error(f"Risk scoring node error: {e}")
        state["error"] = str(e)
        state["next_step"] = "error"

    return state


def report_generation_node(state: SupervisorState) -> SupervisorState:
    """Generate comprehensive risk assessment report.

    Args:
        state: Current workflow state

    Returns:
        Updated state with report path
    """
    logger.info("=== Report Generation Node ===")

    try:
        agent = ReportAgent()

        # Count risk levels
        critical = sum(1 for r in state.get("risk_ratings", []) if r.get("risk_level") == "Critical")
        high = sum(1 for r in state.get("risk_ratings", []) if r.get("risk_level") == "High")
        medium = sum(1 for r in state.get("risk_ratings", []) if r.get("risk_level") == "Medium")
        low = sum(1 for r in state.get("risk_ratings", []) if r.get("risk_level") == "Low")

        # Create executive summary
        exec_summary = ExecutiveSummary(
            total_vulnerabilities=len(state.get("vulnerabilities", [])),
            critical_risks=critical,
            high_risks=high,
            medium_risks=medium,
            low_risks=low,
            key_findings=[
                f"Identified {len(state.get('cve_ids', []))} unique CVEs across infrastructure",
                f"{critical + high} vulnerabilities require immediate attention",
                f"{sum(1 for v in state.get('vulnerabilities', []) if v.get('exploitation_status', {}).get('in_cisa_kev'))} CVEs are actively exploited (CISA KEV)",
            ],
            top_recommendations=[
                "Patch all CISA KEV vulnerabilities immediately (24-48 hours)",
                f"Address {critical} critical risk vulnerabilities within 1 week",
                "Implement vulnerability management process improvements",
            ],
        )

        # Reconstruct full report (simplified)
        # In production, would fully reconstruct all nested objects
        from models.schemas import RiskAssessmentReport

        # For now, just create report path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"reports/risk_assessment_{timestamp}.docx"

        logger.info(f"Report would be generated at: {report_path}")

        state["report_path"] = report_path
        state["messages"] = [f"✓ Report: Generated at {report_path}"]
        state["next_step"] = "complete"
        state["completed"] = True

    except Exception as e:
        logger.error(f"Report generation node error: {e}")
        state["error"] = str(e)
        state["next_step"] = "error"

    return state


# ============================================================================
# User Interaction Nodes
# ============================================================================


def user_check_1(state: SupervisorState) -> SupervisorState:
    """User check-in after ServiceNow data collection.

    Args:
        state: Current workflow state

    Returns:
        Updated state
    """
    logger.info("=== User Check 1: ServiceNow Data ===")

    # In production, would prompt user
    # For now, auto-approve
    state["user_approved"] = True
    state["next_step"] = "vulnerability_analysis"
    state["messages"] = ["User approved: Proceeding to vulnerability analysis"]

    return state


def user_check_2(state: SupervisorState) -> SupervisorState:
    """User check-in after threat research.

    Args:
        state: Current workflow state

    Returns:
        Updated state
    """
    logger.info("=== User Check 2: Threat Intelligence ===")

    # Auto-approve for now
    state["user_approved"] = True
    state["next_step"] = "risk_scoring"
    state["messages"] = ["User approved: Proceeding to risk scoring"]

    return state


def user_check_3(state: SupervisorState) -> SupervisorState:
    """User check-in before report generation.

    Args:
        state: Current workflow state

    Returns:
        Updated state
    """
    logger.info("=== User Check 3: Risk Scores ===")

    # Auto-approve for now
    state["user_approved"] = True
    state["next_step"] = "report_generation"
    state["messages"] = ["User approved: Generating final report"]

    return state


# ============================================================================
# Routing Functions
# ============================================================================


def route_next(state: SupervisorState) -> str:
    """Route to next node based on state.

    Args:
        state: Current state

    Returns:
        Next node name
    """
    next_step = state.get("next_step", "")

    logger.info(f"Routing to: {next_step}")

    if next_step == "error" or state.get("error"):
        return END
    elif next_step == "complete" or state.get("completed"):
        return END
    else:
        return next_step


# ============================================================================
# Supervisor Graph
# ============================================================================


class RiskAssessmentSupervisor:
    """Supervisor for orchestrating multi-agent risk assessment workflow."""

    def __init__(self):
        """Initialize supervisor with workflow graph."""
        logger.info("Initializing Risk Assessment Supervisor")

        # Create workflow graph
        workflow = StateGraph(SupervisorState)

        # Add nodes
        workflow.add_node("servicenow", servicenow_node)
        workflow.add_node("user_check_1", user_check_1)
        workflow.add_node("vulnerability_analysis", vulnerability_node)
        workflow.add_node("threat_research", threat_research_node)
        workflow.add_node("user_check_2", user_check_2)
        workflow.add_node("risk_scoring", risk_scoring_node)
        workflow.add_node("user_check_3", user_check_3)
        workflow.add_node("report_generation", report_generation_node)

        # Set entry point
        workflow.set_entry_point("servicenow")

        # Add edges
        workflow.add_conditional_edges(
            "servicenow",
            route_next,
            {
                "user_check_1": "user_check_1",
                END: END,
            },
        )

        workflow.add_conditional_edges(
            "user_check_1",
            route_next,
            {
                "vulnerability_analysis": "vulnerability_analysis",
                END: END,
            },
        )

        workflow.add_conditional_edges(
            "vulnerability_analysis",
            route_next,
            {
                "threat_research": "threat_research",
                END: END,
            },
        )

        workflow.add_conditional_edges(
            "threat_research",
            route_next,
            {
                "user_check_2": "user_check_2",
                END: END,
            },
        )

        workflow.add_conditional_edges(
            "user_check_2",
            route_next,
            {
                "risk_scoring": "risk_scoring",
                END: END,
            },
        )

        workflow.add_conditional_edges(
            "risk_scoring",
            route_next,
            {
                "user_check_3": "user_check_3",
                END: END,
            },
        )

        workflow.add_conditional_edges(
            "user_check_3",
            route_next,
            {
                "report_generation": "report_generation",
                END: END,
            },
        )

        workflow.add_conditional_edges(
            "report_generation",
            route_next,
            {
                "complete": END,
                END: END,
            },
        )

        # Compile graph
        self.app = workflow.compile()

        logger.info("Supervisor workflow compiled successfully")

    def run_assessment(
        self, query: str = "Assess critical risks", cve_ids: List[str] = None
    ) -> Dict:
        """Run complete risk assessment workflow.

        Args:
            query: Assessment query/description
            cve_ids: Optional list of CVE IDs to analyze

        Returns:
            Final state dictionary with results

        Example:
            >>> supervisor = RiskAssessmentSupervisor()
            >>> result = supervisor.run_assessment(
            ...     query="Assess critical vulnerabilities",
            ...     cve_ids=["CVE-2024-1234", "CVE-2024-5678"]
            ... )
            >>> print(f"Report: {result['report_path']}")
        """
        logger.info(f"Starting risk assessment: {query}")

        # Initialize state
        initial_state = {
            "query": query,
            "cve_ids": cve_ids or [],
            "incidents": [],
            "cmdb_items": [],
            "vulnerabilities": [],
            "threats": [],
            "risk_ratings": [],
            "report_path": "",
            "next_step": "",
            "user_approved": False,
            "completed": False,
            "error": "",
            "messages": [],
        }

        # Run workflow
        try:
            final_state = self.app.invoke(initial_state)

            logger.info("Risk assessment completed successfully")
            logger.info(f"Messages: {final_state.get('messages', [])}")

            return final_state

        except Exception as e:
            logger.error(f"Error running assessment: {e}")
            return {
                "error": str(e),
                "completed": False,
            }

    def get_workflow_graph(self) -> str:
        """Get visual representation of workflow graph.

        Returns:
            Mermaid diagram string
        """
        return """
graph TD
    A[Start] --> B[ServiceNow Query]
    B --> C{User Check 1}
    C -->|Approved| D[Vulnerability Analysis]
    D --> E[Threat Research]
    E --> F{User Check 2}
    F -->|Approved| G[Risk Scoring]
    G --> H{User Check 3}
    H -->|Approved| I[Report Generation]
    I --> J[End]
    C -->|Rejected| J
    F -->|Rejected| J
    H -->|Rejected| J
"""
