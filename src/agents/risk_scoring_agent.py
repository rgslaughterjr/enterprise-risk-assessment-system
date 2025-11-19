"""Risk Scoring Agent using FAIR-based 5x5 risk matrix.

This agent calculates likelihood and impact scores across multiple dimensions
to generate comprehensive risk ratings with detailed justifications.

Risk Matrix (5x5):
- Likelihood (1-5): Based on CVE severity, exploitation, asset exposure, threat capability, controls
- Impact (1-5): Based on asset criticality, data sensitivity, business impact, compliance, operations
- Risk Score (1-25): Likelihood × Impact
- Risk Level: Critical (20-25), High (15-19), Medium (8-14), Low (1-7)
"""

import os
from typing import Dict, Optional, Any, Annotated, List
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_classic.prompts import ChatPromptTemplate
from langchain_core.tools import tool
import logging

from ..models.schemas import (
    LikelihoodScore,
    ImpactScore,
    RiskRating,
    CVEDetail,
    ExploitationStatus,
)

load_dotenv()
logger = logging.getLogger(__name__)


# ============================================================================
# Risk Calculation Functions
# ============================================================================


def calculate_cve_severity_score(cvss_score: Optional[float]) -> int:
    """Convert CVSS score to 1-5 scale.

    Args:
        cvss_score: CVSS base score (0-10)

    Returns:
        Severity score (1-5)
    """
    if cvss_score is None:
        return 3  # Default to moderate

    if cvss_score >= 9.0:
        return 5  # Critical
    elif cvss_score >= 7.0:
        return 4  # High
    elif cvss_score >= 4.0:
        return 3  # Medium
    elif cvss_score >= 0.1:
        return 2  # Low
    else:
        return 1  # None


def calculate_exploitation_score(exploitation_status: ExploitationStatus) -> int:
    """Calculate exploitation likelihood score.

    Args:
        exploitation_status: Exploitation status data

    Returns:
        Exploitation score (1-5)
    """
    score = 1

    # CISA KEV = highest priority
    if exploitation_status.in_cisa_kev:
        return 5

    # VirusTotal detections
    if exploitation_status.virustotal_detections >= 10:
        score = 4
    elif exploitation_status.virustotal_detections >= 5:
        score = 3
    elif exploitation_status.virustotal_detections >= 1:
        score = 2

    # Active exploitation
    if exploitation_status.actively_exploited:
        score = max(score, 4)

    # Public exploit available
    if exploitation_status.exploit_available:
        score = max(score, 3)

    return min(score, 5)


def calculate_asset_exposure_score(
    asset_type: str, internet_facing: bool, authentication_required: bool
) -> int:
    """Calculate asset exposure score.

    Args:
        asset_type: Type of asset (server, workstation, database, etc.)
        internet_facing: Whether asset is internet-facing
        authentication_required: Whether authentication is required

    Returns:
        Exposure score (1-5)
    """
    score = 2  # Default moderate

    # Internet-facing increases exposure
    if internet_facing:
        score += 2

    # No authentication increases exposure
    if not authentication_required:
        score += 1

    # Asset type modifiers
    if "server" in asset_type.lower() or "database" in asset_type.lower():
        score += 1

    return min(score, 5)


def calculate_threat_capability_score(
    threat_actors: List[str], attack_complexity: str
) -> int:
    """Calculate threat actor capability score.

    Args:
        threat_actors: List of known threat actors
        attack_complexity: Attack complexity from CVSS (LOW, MEDIUM, HIGH)

    Returns:
        Threat capability score (1-5)
    """
    score = 2  # Default moderate

    # Known APT groups
    known_apts = ["APT", "LAZARUS", "FANCY BEAR", "COZY BEAR", "CARBANAK"]
    if any(apt in actor.upper() for actor in threat_actors for apt in known_apts):
        score = 5

    # Attack complexity
    if attack_complexity == "LOW":
        score += 1
    elif attack_complexity == "HIGH":
        score -= 1

    return max(1, min(score, 5))


def calculate_control_effectiveness_score(
    controls: List[str], control_coverage: str
) -> int:
    """Calculate existing control effectiveness (inverse score).

    Args:
        controls: List of existing controls
        control_coverage: Coverage level (NONE, PARTIAL, FULL)

    Returns:
        Control effectiveness score (1-5, where 5 = weakest controls)
    """
    if control_coverage.upper() == "FULL":
        return 1  # Strong controls reduce likelihood
    elif control_coverage.upper() == "PARTIAL":
        return 3
    else:
        return 5  # No controls


# ============================================================================
# Tool Definitions
# ============================================================================


@tool
def calculate_likelihood(
    cve_id: Annotated[str, "CVE identifier"],
    cvss_score: Annotated[Optional[float], "CVSS base score (0-10)"],
    in_cisa_kev: Annotated[bool, "Whether CVE is in CISA KEV catalog"],
    vt_detections: Annotated[int, "VirusTotal malicious sample count"],
    asset_type: Annotated[str, "Type of affected asset"] = "server",
    internet_facing: Annotated[bool, "Whether asset is internet-facing"] = False,
    authentication_required: Annotated[bool, "Whether authentication is required"] = True,
    threat_actors: Annotated[List[str], "Known threat actors"] = [],
    attack_complexity: Annotated[str, "Attack complexity (LOW/MEDIUM/HIGH)"] = "MEDIUM",
    control_coverage: Annotated[str, "Control coverage (NONE/PARTIAL/FULL)"] = "PARTIAL",
) -> Dict[str, Any]:
    """Calculate likelihood score across 5 dimensions.

    Dimensions:
    1. CVE Severity (from CVSS score)
    2. Exploitation Status (CISA KEV + VirusTotal)
    3. Asset Exposure (internet-facing, auth requirements)
    4. Threat Actor Capability (known actors, attack complexity)
    5. Control Effectiveness (existing security controls)

    Args:
        cve_id: CVE identifier
        cvss_score: CVSS base score
        in_cisa_kev: Whether in CISA KEV
        vt_detections: VirusTotal detection count
        asset_type: Asset type
        internet_facing: Internet-facing status
        authentication_required: Authentication requirement
        threat_actors: List of threat actors
        attack_complexity: Attack complexity
        control_coverage: Control coverage level

    Returns:
        Dictionary with likelihood score and justification
    """
    # Calculate dimension scores
    cve_severity = calculate_cve_severity_score(cvss_score)

    exploitation_status = ExploitationStatus(
        cve_id=cve_id,
        in_cisa_kev=in_cisa_kev,
        virustotal_detections=vt_detections,
        exploit_available=vt_detections > 0,
        actively_exploited=in_cisa_kev or vt_detections > 0,
    )
    exploitation = calculate_exploitation_score(exploitation_status)

    asset_exposure = calculate_asset_exposure_score(
        asset_type, internet_facing, authentication_required
    )

    threat_capability = calculate_threat_capability_score(
        threat_actors, attack_complexity
    )

    control_effectiveness = calculate_control_effectiveness_score(
        [], control_coverage  # Simplified for now
    )

    # Overall likelihood = average of 5 dimensions
    overall = round(
        (cve_severity + exploitation + asset_exposure + threat_capability + control_effectiveness)
        / 5.0
    )

    # Build justification
    justification_parts = [
        f"CVE Severity: {cve_severity}/5 (CVSS: {cvss_score or 'N/A'})",
        f"Exploitation: {exploitation}/5 (KEV: {in_cisa_kev}, VT: {vt_detections})",
        f"Asset Exposure: {asset_exposure}/5 (Internet-facing: {internet_facing})",
        f"Threat Capability: {threat_capability}/5 (Complexity: {attack_complexity})",
        f"Control Effectiveness: {control_effectiveness}/5 (Coverage: {control_coverage})",
    ]

    likelihood_score = LikelihoodScore(
        cve_severity=cve_severity,
        exploitation_status=exploitation,
        asset_exposure=asset_exposure,
        threat_capability=threat_capability,
        control_effectiveness=control_effectiveness,
        overall_score=overall,
        justification="; ".join(justification_parts),
    )

    return likelihood_score.model_dump()


@tool
def calculate_impact(
    asset_name: Annotated[str, "Asset name"],
    asset_criticality: Annotated[int, "Asset criticality (1-5)"] = 3,
    data_sensitivity: Annotated[int, "Data sensitivity level (1-5)"] = 3,
    business_impact: Annotated[int, "Business process impact (1-5)"] = 3,
    compliance_impact: Annotated[int, "Regulatory impact (1-5)"] = 3,
    operational_impact: Annotated[int, "Operational disruption (1-5)"] = 3,
) -> Dict[str, Any]:
    """Calculate impact score across 5 dimensions.

    Dimensions:
    1. Asset Criticality (business importance)
    2. Data Sensitivity (confidentiality level)
    3. Business Impact (process disruption)
    4. Compliance Impact (regulatory consequences)
    5. Operational Impact (service availability)

    Args:
        asset_name: Name of affected asset
        asset_criticality: How critical is the asset (1=low, 5=critical)
        data_sensitivity: Sensitivity of data (1=public, 5=highly sensitive)
        business_impact: Impact to business processes (1=minimal, 5=severe)
        compliance_impact: Regulatory/compliance impact (1=none, 5=severe)
        operational_impact: Operational disruption (1=minimal, 5=complete outage)

    Returns:
        Dictionary with impact score and justification
    """
    # Overall impact = average of 5 dimensions
    overall = round(
        (
            asset_criticality
            + data_sensitivity
            + business_impact
            + compliance_impact
            + operational_impact
        )
        / 5.0
    )

    # Build justification
    justification_parts = [
        f"Asset Criticality: {asset_criticality}/5",
        f"Data Sensitivity: {data_sensitivity}/5",
        f"Business Impact: {business_impact}/5",
        f"Compliance Impact: {compliance_impact}/5",
        f"Operational Impact: {operational_impact}/5",
    ]

    impact_score = ImpactScore(
        asset_criticality=asset_criticality,
        data_sensitivity=data_sensitivity,
        business_impact=business_impact,
        compliance_impact=compliance_impact,
        operational_impact=operational_impact,
        overall_score=overall,
        justification="; ".join(justification_parts),
    )

    return impact_score.model_dump()


@tool
def generate_risk_rating(
    cve_id: Annotated[str, "CVE identifier"],
    asset_name: Annotated[str, "Asset name"],
    likelihood_score: Annotated[int, "Likelihood score (1-5)"],
    impact_score: Annotated[int, "Impact score (1-5)"],
    likelihood_justification: Annotated[str, "Likelihood justification"],
    impact_justification: Annotated[str, "Impact justification"],
) -> Dict[str, Any]:
    """Generate overall risk rating from likelihood and impact.

    Risk Matrix:
    - Risk Score = Likelihood × Impact (1-25)
    - Critical: 20-25 (patch immediately)
    - High: 15-19 (patch within 1 week)
    - Medium: 8-14 (patch within 30 days)
    - Low: 1-7 (patch within 90 days)

    Args:
        cve_id: CVE identifier
        asset_name: Asset name
        likelihood_score: Likelihood (1-5)
        impact_score: Impact (1-5)
        likelihood_justification: Likelihood reasoning
        impact_justification: Impact reasoning

    Returns:
        Complete risk rating dictionary
    """
    # Calculate risk score
    risk_score = likelihood_score * impact_score

    # Determine risk level
    if risk_score >= 20:
        risk_level = "Critical"
        recommendation = "Patch immediately (within 24-48 hours)"
    elif risk_score >= 15:
        risk_level = "High"
        recommendation = "Patch within 1 week"
    elif risk_score >= 8:
        risk_level = "Medium"
        recommendation = "Patch within 30 days"
    else:
        risk_level = "Low"
        recommendation = "Patch within 90 days or next maintenance window"

    # Build overall justification
    overall_justification = (
        f"Risk Score: {risk_score}/25 ({risk_level})\n\n"
        f"Likelihood Assessment ({likelihood_score}/5):\n{likelihood_justification}\n\n"
        f"Impact Assessment ({impact_score}/5):\n{impact_justification}\n\n"
        f"Recommendation: {recommendation}"
    )

    # Create risk rating
    # Note: We need to reconstruct LikelihoodScore and ImpactScore objects
    # For simplicity, create minimal versions
    likelihood = LikelihoodScore(
        cve_severity=likelihood_score,
        exploitation_status=likelihood_score,
        asset_exposure=likelihood_score,
        threat_capability=likelihood_score,
        control_effectiveness=likelihood_score,
        overall_score=likelihood_score,
        justification=likelihood_justification,
    )

    impact = ImpactScore(
        asset_criticality=impact_score,
        data_sensitivity=impact_score,
        business_impact=impact_score,
        compliance_impact=impact_score,
        operational_impact=impact_score,
        overall_score=impact_score,
        justification=impact_justification,
    )

    risk_rating = RiskRating(
        cve_id=cve_id,
        asset_name=asset_name,
        likelihood=likelihood,
        impact=impact,
        risk_level=risk_level,
        risk_score=risk_score,
        overall_justification=overall_justification,
        recommendations=[recommendation],
    )

    return risk_rating.model_dump()


@tool
def justify_score(
    score_type: Annotated[str, "Type of score (likelihood or impact)"],
    score_value: Annotated[int, "Score value (1-5)"],
    factors: Annotated[Dict[str, Any], "Factors contributing to score"],
) -> str:
    """Generate detailed justification for a risk score.

    Use this tool to explain why a particular likelihood or impact score
    was assigned based on the contributing factors.

    Args:
        score_type: "likelihood" or "impact"
        score_value: The assigned score (1-5)
        factors: Dictionary of factors and their values

    Returns:
        Detailed justification string
    """
    justification_parts = [
        f"{score_type.capitalize()} Score: {score_value}/5",
        "",
        "Contributing Factors:",
    ]

    for factor, value in factors.items():
        justification_parts.append(f"- {factor}: {value}")

    justification_parts.append("")

    # Add interpretation
    if score_value >= 4:
        justification_parts.append(
            f"This {score_type} score is HIGH, indicating significant risk."
        )
    elif score_value >= 3:
        justification_parts.append(
            f"This {score_type} score is MODERATE, indicating medium risk."
        )
    else:
        justification_parts.append(
            f"This {score_type} score is LOW, indicating limited risk."
        )

    return "\n".join(justification_parts)


# ============================================================================
# Agent Definition
# ============================================================================


class RiskScoringAgent:
    """Agent for calculating comprehensive risk scores.

    Uses FAIR-based 5x5 matrix with detailed justifications for
    likelihood and impact assessments.
    """

    def __init__(
        self, model: str = "gemini-1.5-pro", temperature: float = 0
    ):
        """Initialize Risk Scoring Agent.

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
            calculate_likelihood,
            calculate_impact,
            generate_risk_rating,
            justify_score,
        ]

        # Create prompt
        self.prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    """You are a cybersecurity risk analyst specializing in risk assessment.

Your capabilities:
1. Calculate likelihood scores (1-5) across 5 dimensions
2. Calculate impact scores (1-5) across 5 dimensions
3. Generate overall risk ratings (Critical/High/Medium/Low)
4. Provide detailed justifications for all scores

FAIR-based Risk Matrix (5x5):
- Likelihood Dimensions: CVE severity, exploitation status, asset exposure, threat capability, control effectiveness
- Impact Dimensions: Asset criticality, data sensitivity, business impact, compliance impact, operational impact
- Risk Score = Likelihood × Impact (1-25)
- Risk Levels: Critical (20-25), High (15-19), Medium (8-14), Low (1-7)

Scoring Guidelines:
1. CVE Severity: 5=Critical (9.0-10.0), 4=High (7.0-8.9), 3=Medium (4.0-6.9), 2=Low (0.1-3.9), 1=None
2. Exploitation: 5=CISA KEV, 4=10+ samples, 3=5+ samples, 2=1+ samples, 1=None
3. Asset Exposure: 5=Internet-facing no auth, 4=Internet-facing with auth, 3=Internal critical, 2=Internal standard, 1=Isolated
4. Threat Capability: 5=Known APT, 4=Sophisticated actors, 3=Moderate skill, 2=Low skill, 1=None
5. Controls: 5=None, 4=Minimal, 3=Partial, 2=Good, 1=Comprehensive

When calculating risk:
- Always justify each dimension score
- Explain the overall risk level
- Provide clear remediation timeline
- Consider both likelihood AND impact
- CISA KEV vulnerabilities are always high priority
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

        logger.info(f"Risk scoring agent initialized with {len(self.tools)} tools")

    def query(self, user_input: str) -> str:
        """Process risk scoring query.

        Args:
            user_input: User's query

        Returns:
            Risk assessment response
        """
        try:
            result = self.executor.invoke({"input": user_input})
            return result.get("output", "No response generated")

        except Exception as e:
            logger.error(f"Error processing query: {e}")
            return f"Error processing query: {e}"

    def calculate_risk(
        self,
        cve_id: str,
        asset_name: str,
        cvss_score: Optional[float],
        in_cisa_kev: bool,
        vt_detections: int,
        asset_criticality: int = 3,
        data_sensitivity: int = 3,
    ) -> RiskRating:
        """Calculate complete risk rating (programmatic interface).

        Args:
            cve_id: CVE identifier
            asset_name: Asset name
            cvss_score: CVSS score
            in_cisa_kev: Whether in CISA KEV
            vt_detections: VirusTotal detections
            asset_criticality: Asset criticality (1-5)
            data_sensitivity: Data sensitivity (1-5)

        Returns:
            RiskRating object
        """
        try:
            # Calculate likelihood
            cve_severity = calculate_cve_severity_score(cvss_score)
            exploitation_status = ExploitationStatus(
                cve_id=cve_id,
                in_cisa_kev=in_cisa_kev,
                virustotal_detections=vt_detections,
                exploit_available=vt_detections > 0,
                actively_exploited=in_cisa_kev or vt_detections > 0,
            )
            exploitation = calculate_exploitation_score(exploitation_status)

            # Simplified asset exposure, threat capability, controls
            asset_exposure = 3
            threat_capability = 3
            control_effectiveness = 3

            likelihood_overall = round(
                (cve_severity + exploitation + asset_exposure + threat_capability + control_effectiveness)
                / 5.0
            )

            likelihood = LikelihoodScore(
                cve_severity=cve_severity,
                exploitation_status=exploitation,
                asset_exposure=asset_exposure,
                threat_capability=threat_capability,
                control_effectiveness=control_effectiveness,
                overall_score=likelihood_overall,
                justification=f"CVE: {cve_severity}/5, Exploitation: {exploitation}/5",
            )

            # Calculate impact
            impact_overall = round((asset_criticality + data_sensitivity + 3 + 3 + 3) / 5.0)

            impact = ImpactScore(
                asset_criticality=asset_criticality,
                data_sensitivity=data_sensitivity,
                business_impact=3,
                compliance_impact=3,
                operational_impact=3,
                overall_score=impact_overall,
                justification=f"Asset Criticality: {asset_criticality}/5, Data Sensitivity: {data_sensitivity}/5",
            )

            # Calculate risk score
            risk_score = likelihood_overall * impact_overall

            if risk_score >= 20:
                risk_level = "Critical"
            elif risk_score >= 15:
                risk_level = "High"
            elif risk_score >= 8:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            risk_rating = RiskRating(
                cve_id=cve_id,
                asset_name=asset_name,
                likelihood=likelihood,
                impact=impact,
                risk_level=risk_level,
                risk_score=risk_score,
                overall_justification=f"Risk Score: {risk_score}/25 ({risk_level})",
                recommendations=[f"Remediate based on {risk_level} priority"],
            )

            logger.info(f"Calculated risk for {cve_id}: {risk_level} ({risk_score}/25)")
            return risk_rating

        except Exception as e:
            logger.error(f"Error calculating risk: {e}")
            # Return default low risk rating
            return RiskRating(
                cve_id=cve_id,
                asset_name=asset_name,
                likelihood=LikelihoodScore(
                    cve_severity=1,
                    exploitation_status=1,
                    asset_exposure=1,
                    threat_capability=1,
                    control_effectiveness=1,
                    overall_score=1,
                    justification="Error calculating likelihood",
                ),
                impact=ImpactScore(
                    asset_criticality=1,
                    data_sensitivity=1,
                    business_impact=1,
                    compliance_impact=1,
                    operational_impact=1,
                    overall_score=1,
                    justification="Error calculating impact",
                ),
                risk_level="Low",
                risk_score=1,
                overall_justification=f"Error: {e}",
                recommendations=["Review manually"],
            )
