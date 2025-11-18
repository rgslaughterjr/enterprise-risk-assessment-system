"""Threat Scenario Agent for generating probabilistic attack scenarios.

This agent integrates Markov chain threat modeling with the existing threat
intelligence capabilities to generate and rank attack scenarios.
"""

import os
import logging
from typing import List, Dict, Optional, Any
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_classic.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from typing_extensions import Annotated

from ..reasoning.markov_threat_modeler import MarkovThreatModeler, AttackScenario
from ..tools.attack_transition_builder import AttackTransitionBuilder
from ..tools.mitre_client import MITREClient

load_dotenv()
logger = logging.getLogger(__name__)


# ============================================================================
# Global instances
# ============================================================================

_threat_modeler: Optional[MarkovThreatModeler] = None
_mitre_client: Optional[MITREClient] = None


def get_threat_modeler() -> MarkovThreatModeler:
    """Get or create threat modeler instance."""
    global _threat_modeler
    if _threat_modeler is None:
        logger.info("Initializing Markov threat modeler")
        _threat_modeler = MarkovThreatModeler()
    return _threat_modeler


def get_mitre_client() -> MITREClient:
    """Get or create MITRE client instance."""
    global _mitre_client
    if _mitre_client is None:
        _mitre_client = MITREClient()
    return _mitre_client


# ============================================================================
# Tool Definitions
# ============================================================================


@tool
def generate_attack_scenario(
    initial_technique: Annotated[str, "Starting MITRE ATT&CK technique ID"],
    steps: Annotated[int, "Number of steps in scenario (default 10)"] = 10,
) -> Dict[str, Any]:
    """Generate a single attack scenario starting from a technique.

    Use this tool to generate a probabilistic attack path starting from
    an initial technique (e.g., exploitation technique for a CVE).

    Args:
        initial_technique: Starting technique ID (e.g., "T1190")
        steps: Maximum number of steps in the scenario

    Returns:
        Dictionary with scenario details

    Examples:
        - "Generate attack scenario starting from T1190"
        - "What could an attacker do after exploiting T1059?"
    """
    try:
        modeler = get_threat_modeler()
        scenario = modeler.generate_scenario(initial_technique, steps)

        return {
            "techniques": scenario.techniques,
            "probability": scenario.probability,
            "tactics": scenario.tactics,
            "description": scenario.description,
            "num_steps": len(scenario.techniques),
        }

    except Exception as e:
        logger.error(f"Error generating scenario: {e}")
        return {"error": str(e)}


@tool
def generate_multiple_scenarios(
    initial_technique: Annotated[str, "Starting MITRE ATT&CK technique ID"],
    num_scenarios: Annotated[int, "Number of scenarios to generate (default 10)"] = 10,
    steps: Annotated[int, "Maximum steps per scenario (default 10)"] = 10,
) -> Dict[str, Any]:
    """Generate multiple attack scenarios using Monte Carlo sampling.

    Use this tool to generate diverse attack scenarios and identify
    the most likely attack paths.

    Args:
        initial_technique: Starting technique ID
        num_scenarios: Number of scenarios to generate
        steps: Maximum steps per scenario

    Returns:
        Dictionary with top scenarios

    Examples:
        - "Generate 10 attack scenarios from T1190"
        - "What are possible attack paths after initial access?"
    """
    try:
        modeler = get_threat_modeler()
        scenarios = modeler.generate_monte_carlo_scenarios(
            initial_technique, num_scenarios, steps
        )

        # Return top 5 scenarios
        top_scenarios = scenarios[:5]

        return {
            "num_generated": len(scenarios),
            "top_scenarios": [
                {
                    "techniques": s.techniques,
                    "probability": s.probability,
                    "tactics": s.tactics,
                    "num_steps": len(s.techniques),
                }
                for s in top_scenarios
            ],
            "summary": f"Generated {len(scenarios)} unique scenarios. "
            f"Top scenario has {len(top_scenarios[0].techniques)} steps "
            f"with probability {top_scenarios[0].probability:.4f}",
        }

    except Exception as e:
        logger.error(f"Error generating scenarios: {e}")
        return {"error": str(e)}


@tool
def find_attack_path(
    start_technique: Annotated[str, "Starting technique ID"],
    end_technique: Annotated[str, "Target/goal technique ID"],
    max_steps: Annotated[int, "Maximum path length (default 10)"] = 10,
) -> Dict[str, Any]:
    """Find the most likely attack path between two techniques.

    Use this tool to find how an attacker might progress from an initial
    technique to a goal technique (e.g., from initial access to exfiltration).

    Args:
        start_technique: Starting technique ID
        end_technique: Target technique ID
        max_steps: Maximum path length

    Returns:
        Dictionary with path details

    Examples:
        - "Find path from T1190 to T1567 (exfiltration)"
        - "How would attacker go from initial access to credential dumping?"
    """
    try:
        modeler = get_threat_modeler()
        scenario = modeler.find_most_likely_path(
            start_technique, end_technique, max_steps
        )

        if scenario:
            return {
                "found": True,
                "techniques": scenario.techniques,
                "probability": scenario.probability,
                "tactics": scenario.tactics,
                "num_steps": len(scenario.techniques),
                "description": scenario.description,
            }
        else:
            return {
                "found": False,
                "message": f"No path found from {start_technique} to {end_technique} "
                f"within {max_steps} steps",
            }

    except Exception as e:
        logger.error(f"Error finding path: {e}")
        return {"error": str(e)}


@tool
def get_next_likely_techniques(
    current_technique: Annotated[str, "Current technique ID"],
    top_k: Annotated[int, "Number of top techniques to return (default 5)"] = 5,
) -> List[Dict[str, Any]]:
    """Get most likely next techniques after current technique.

    Use this tool to understand what an attacker is likely to do next
    after using a specific technique.

    Args:
        current_technique: Current technique ID
        top_k: Number of top techniques to return

    Returns:
        List of dictionaries with technique details

    Examples:
        - "What techniques commonly follow T1190?"
        - "What would attacker do after gaining initial access?"
    """
    try:
        modeler = get_threat_modeler()
        next_techniques = modeler.get_top_next_techniques(current_technique, top_k)

        return [
            {
                "technique_id": tech_id,
                "probability": prob,
                "name": name,
            }
            for tech_id, prob, name in next_techniques
        ]

    except Exception as e:
        logger.error(f"Error getting next techniques: {e}")
        return [{"error": str(e)}]


@tool
def analyze_technique_reachability(
    technique: Annotated[str, "Starting technique ID"],
    max_steps: Annotated[int, "Maximum steps to explore (default 5)"] = 5,
) -> Dict[str, Any]:
    """Analyze which techniques are reachable from a starting technique.

    Use this tool to understand the full scope of possible attack paths
    from a given technique.

    Args:
        technique: Starting technique ID
        max_steps: Maximum steps to explore

    Returns:
        Dictionary with reachability analysis

    Examples:
        - "What techniques can be reached from T1190?"
        - "Analyze attack surface from initial access technique"
    """
    try:
        modeler = get_threat_modeler()
        reachable = modeler.analyze_technique_reachability(technique, max_steps)

        # Sort by probability
        sorted_reachable = sorted(
            reachable.items(), key=lambda x: x[1], reverse=True
        )

        # Group by probability ranges
        high_prob = [(t, p) for t, p in sorted_reachable if p >= 0.1]
        medium_prob = [(t, p) for t, p in sorted_reachable if 0.01 <= p < 0.1]
        low_prob = [(t, p) for t, p in sorted_reachable if p < 0.01]

        return {
            "total_reachable": len(reachable),
            "high_probability": len(high_prob),
            "medium_probability": len(medium_prob),
            "low_probability": len(low_prob),
            "top_10_reachable": [
                {"technique": t, "probability": p} for t, p in sorted_reachable[:10]
            ],
        }

    except Exception as e:
        logger.error(f"Error analyzing reachability: {e}")
        return {"error": str(e)}


@tool
def calculate_path_probability(
    techniques: Annotated[List[str], "List of technique IDs in order"],
) -> Dict[str, Any]:
    """Calculate the probability of a specific attack path.

    Use this tool to assess how likely a specific sequence of techniques
    is based on historical attack patterns.

    Args:
        techniques: Ordered list of technique IDs

    Returns:
        Dictionary with probability analysis

    Examples:
        - "What is probability of path T1190 -> T1059 -> T1003?"
        - "How likely is this attack sequence?"
    """
    try:
        modeler = get_threat_modeler()
        probability = modeler.calculate_probability(techniques)

        return {
            "path": techniques,
            "probability": probability,
            "num_steps": len(techniques),
            "assessment": _assess_probability(probability),
        }

    except Exception as e:
        logger.error(f"Error calculating probability: {e}")
        return {"error": str(e)}


def _assess_probability(prob: float) -> str:
    """Assess probability level.

    Args:
        prob: Probability value

    Returns:
        Assessment string
    """
    if prob >= 0.1:
        return "Very likely - common attack pattern"
    elif prob >= 0.01:
        return "Likely - plausible attack pattern"
    elif prob >= 0.001:
        return "Possible - less common pattern"
    else:
        return "Unlikely - rare or unrealistic pattern"


@tool
def get_modeler_statistics() -> Dict[str, Any]:
    """Get statistics about the threat modeler.

    Use this tool to understand the size and coverage of the
    threat modeling database.

    Returns:
        Dictionary with statistics
    """
    try:
        modeler = get_threat_modeler()
        return modeler.get_statistics()

    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return {"error": str(e)}


# ============================================================================
# Agent Definition
# ============================================================================


class ThreatScenarioAgent:
    """Agent for generating and analyzing probabilistic attack scenarios.

    This agent combines Markov chain threat modeling with MITRE ATT&CK
    data to generate realistic attack scenarios and analyze attack paths.
    """

    def __init__(
        self,
        model: str = "claude-3-5-sonnet-20241022",
        temperature: float = 0,
    ):
        """Initialize threat scenario agent.

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
            generate_attack_scenario,
            generate_multiple_scenarios,
            find_attack_path,
            get_next_likely_techniques,
            analyze_technique_reachability,
            calculate_path_probability,
            get_modeler_statistics,
        ]

        # Create prompt
        self.prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are a cybersecurity threat modeling expert specializing in
attack scenario generation and analysis.

Your capabilities:
1. Generate probabilistic attack scenarios using Markov chains
2. Analyze attack paths and techniques
3. Assess likelihood of specific attack sequences
4. Map CVEs to potential attack progression paths
5. Identify high-risk attack patterns

You use MITRE ATT&CK framework and Markov chain analysis to model
how attackers progress through systems after initial compromise.

When analyzing threats:
- Start with the initial technique (often from CVE exploitation)
- Generate multiple scenarios to identify likely attack paths
- Focus on high-probability paths for risk assessment
- Consider the full attack chain from initial access to impact
- Provide actionable intelligence for defenders

Attack Scenario Analysis:
- HIGH probability (>0.1): Very common, well-documented patterns
- MEDIUM probability (0.01-0.1): Plausible, realistic patterns
- LOW probability (<0.01): Uncommon or complex patterns

MITRE ATT&CK Tactics (in order):
1. Initial Access - How attackers get in (e.g., T1190)
2. Execution - Running malicious code (e.g., T1059)
3. Persistence - Maintaining access
4. Privilege Escalation - Gaining higher privileges (e.g., T1068)
5. Defense Evasion - Avoiding detection
6. Credential Access - Stealing credentials (e.g., T1003)
7. Discovery - Exploring the environment (e.g., T1083)
8. Lateral Movement - Moving through network (e.g., T1021)
9. Collection - Gathering data
10. Command and Control - Communicating with attacker (e.g., T1071)
11. Exfiltration - Stealing data (e.g., T1567)
12. Impact - Causing damage

Always provide clear, actionable threat intelligence with probability
assessments to help prioritize defensive actions.
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

        logger.info(f"Threat scenario agent initialized with {len(self.tools)} tools")

    def query(self, user_input: str) -> str:
        """Process threat scenario query.

        Args:
            user_input: User's query

        Returns:
            Response with scenario analysis
        """
        try:
            result = self.executor.invoke({"input": user_input})
            return result.get("output", "No response generated")

        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return f"Error processing query: {e}"

    def generate_scenarios(
        self, cve_id: str, initial_technique: str, num_scenarios: int = 10
    ) -> List[Dict[str, Any]]:
        """Generate attack scenarios for a CVE (programmatic interface).

        Args:
            cve_id: CVE identifier
            initial_technique: Initial exploitation technique
            num_scenarios: Number of scenarios to generate

        Returns:
            List of scenario dictionaries
        """
        try:
            modeler = get_threat_modeler()

            scenarios = modeler.generate_monte_carlo_scenarios(
                initial_technique, num_scenarios
            )

            return [
                {
                    "cve_id": cve_id,
                    "techniques": s.techniques,
                    "probability": s.probability,
                    "tactics": s.tactics,
                    "description": s.description,
                }
                for s in scenarios
            ]

        except Exception as e:
            logger.error(f"Error generating scenarios for {cve_id}: {e}")
            return []

    def rank_by_probability(
        self, scenarios: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Rank scenarios by probability.

        Args:
            scenarios: List of scenario dictionaries

        Returns:
            Sorted list of scenarios
        """
        return sorted(scenarios, key=lambda s: s.get("probability", 0), reverse=True)

    def integrate_with_threat_agent(
        self, cve_id: str, cve_description: str
    ) -> Dict[str, Any]:
        """Integrate with existing threat agent for complete analysis.

        Args:
            cve_id: CVE identifier
            cve_description: CVE description

        Returns:
            Complete threat analysis with scenarios
        """
        try:
            # Map CVE to techniques
            mitre_client = get_mitre_client()
            techniques = mitre_client.map_cve_to_techniques(cve_id, cve_description)

            if not techniques:
                logger.warning(f"No techniques mapped for {cve_id}")
                return {
                    "cve_id": cve_id,
                    "scenarios": [],
                    "message": "No MITRE ATT&CK techniques mapped for this CVE",
                }

            # Use first technique as initial technique
            initial_technique = techniques[0].technique_id

            # Generate scenarios
            scenarios = self.generate_scenarios(cve_id, initial_technique, 10)

            # Rank scenarios
            ranked_scenarios = self.rank_by_probability(scenarios)

            return {
                "cve_id": cve_id,
                "initial_techniques": [t.technique_id for t in techniques],
                "scenarios": ranked_scenarios[:5],  # Top 5
                "num_scenarios": len(scenarios),
            }

        except Exception as e:
            logger.error(f"Error integrating with threat agent: {e}")
            return {"error": str(e)}
