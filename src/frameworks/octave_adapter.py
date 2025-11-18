"""OCTAVE Allegro Risk Assessment Framework Adapter.

Implements the OCTAVE (Operationally Critical Threat, Asset, and Vulnerability
Evaluation) Allegro methodology for organizational risk assessment.

OCTAVE Allegro is a streamlined risk assessment approach focusing on:
- Critical information assets
- Organizational impact assessment
- Threat scenarios and vulnerabilities
- Risk prioritization and mitigation
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AssetCriticality(Enum):
    """Asset criticality levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ImpactArea(Enum):
    """Areas of organizational impact."""
    REPUTATION = "reputation"
    FINANCIAL = "financial"
    PRODUCTIVITY = "productivity"
    SAFETY = "safety"
    FINES_LEGAL = "fines_legal"


class OCTAVEAdapter:
    """Adapter for OCTAVE Allegro risk assessment methodology.

    Implements the three-phase OCTAVE Allegro process:
    1. Establish Drivers - Organizational drivers and risk criteria
    2. Profile Assets - Critical information asset identification
    3. Identify Threats - Threat scenarios and vulnerability analysis
    """

    # Impact scoring scales (1-5)
    IMPACT_SCALES = {
        ImpactArea.REPUTATION: {
            1: "Minimal damage to reputation",
            2: "Minor negative publicity",
            3: "Significant negative publicity",
            4: "Major loss of customer confidence",
            5: "Catastrophic reputation damage",
        },
        ImpactArea.FINANCIAL: {
            1: "< $10,000 loss",
            2: "$10,000 - $100,000 loss",
            3: "$100,000 - $1M loss",
            4: "$1M - $10M loss",
            5: "> $10M loss",
        },
        ImpactArea.PRODUCTIVITY: {
            1: "< 1 hour disruption",
            2: "1-8 hours disruption",
            3: "1-3 days disruption",
            4: "3-7 days disruption",
            5: "> 7 days disruption",
        },
        ImpactArea.SAFETY: {
            1: "No safety impact",
            2: "Minor safety concerns",
            3: "Moderate safety risk",
            4: "Serious safety risk",
            5: "Life-threatening risk",
        },
        ImpactArea.FINES_LEGAL: {
            1: "No legal/regulatory impact",
            2: "Minor compliance issues",
            3: "Regulatory warnings",
            4: "Significant fines/penalties",
            5: "Criminal liability",
        },
    }

    def __init__(self):
        """Initialize OCTAVE Allegro adapter."""
        logger.info("OCTAVE Allegro adapter initialized")

    def assess_risk(
        self,
        cve: Optional[Dict[str, Any]] = None,
        asset: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Perform OCTAVE Allegro risk assessment.

        Args:
            cve: CVE vulnerability data
            asset: Asset information
            context: Additional context (organizational drivers, impact criteria)

        Returns:
            Comprehensive OCTAVE risk assessment
        """
        logger.info("Executing OCTAVE Allegro risk assessment")

        context = context or {}

        # Phase 1: Establish Drivers
        drivers = self._establish_drivers(context)

        # Phase 2: Profile Assets
        asset_profile = self._profile_assets(asset, context)

        # Phase 3: Identify Threats
        threat_scenarios = self._identify_threats(cve, asset, context)

        # Calculate risk scores
        risk_scores = self._calculate_risk_scores(
            asset_profile, threat_scenarios, drivers
        )

        # Overall risk rating
        overall_score = risk_scores["overall_risk_score"]

        assessment = {
            "framework": "OCTAVE Allegro",
            "overall_score": overall_score,
            "risk_level": self._score_to_risk_level(overall_score),
            "phases": {
                "establish_drivers": drivers,
                "profile_assets": asset_profile,
                "identify_threats": threat_scenarios,
            },
            "risk_analysis": risk_scores,
            "recommendations": self._generate_recommendations(
                overall_score, asset_profile, threat_scenarios
            ),
            "confidence": 0.82,
            "assessed_at": datetime.utcnow().isoformat(),
        }

        return assessment

    def _establish_drivers(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 1: Establish organizational drivers and risk criteria.

        Args:
            context: Organizational context

        Returns:
            Driver analysis results
        """
        logger.debug("Phase 1: Establishing organizational drivers")

        # Organizational drivers
        drivers = {
            "business_objectives": context.get(
                "business_objectives",
                ["Maintain operations", "Protect customer data", "Ensure compliance"]
            ),
            "risk_tolerance": context.get("risk_tolerance", "medium"),
            "compliance_requirements": context.get(
                "compliance_requirements",
                ["GDPR", "SOC2", "HIPAA"]
            ),
            "critical_success_factors": context.get(
                "critical_success_factors",
                ["System availability", "Data integrity", "Customer trust"]
            ),
        }

        # Risk measurement criteria
        impact_areas = context.get("impact_areas", [
            ImpactArea.REPUTATION.value,
            ImpactArea.FINANCIAL.value,
            ImpactArea.PRODUCTIVITY.value,
        ])

        drivers["impact_areas"] = impact_areas
        drivers["impact_thresholds"] = self._define_impact_thresholds(
            context.get("risk_tolerance", "medium")
        )

        return drivers

    def _profile_assets(
        self,
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Phase 2: Profile critical information assets.

        Args:
            asset: Asset information
            context: Additional context

        Returns:
            Asset profile with criticality assessment
        """
        logger.debug("Phase 2: Profiling information assets")

        if not asset:
            asset = {"name": "Unknown Asset", "type": "information_system"}

        # Asset identification
        asset_id = asset.get("id", "ASSET-UNKNOWN")
        asset_name = asset.get("name", "Unknown Asset")
        asset_type = asset.get("type", "information_system")

        # Asset criticality assessment
        criticality = self._assess_asset_criticality(asset, context)

        # Security requirements
        security_requirements = self._determine_security_requirements(
            criticality, asset
        )

        # Asset containers (where asset is stored/processed)
        containers = asset.get("containers", ["Servers", "Databases", "Cloud"])

        profile = {
            "asset_id": asset_id,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "criticality": criticality,
            "criticality_score": self._criticality_to_score(criticality),
            "security_requirements": security_requirements,
            "containers": containers,
            "owners": asset.get("owners", ["IT Department"]),
            "description": asset.get("description", "Critical business asset"),
        }

        return profile

    def _identify_threats(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Phase 3: Identify threat scenarios and vulnerabilities.

        Args:
            cve: CVE vulnerability data
            asset: Asset data
            context: Context data

        Returns:
            Threat scenario analysis
        """
        logger.debug("Phase 3: Identifying threat scenarios")

        # Generate threat scenarios
        scenarios = []

        # Scenario 1: Technical vulnerability exploitation (from CVE)
        if cve:
            scenario = self._create_vulnerability_scenario(cve, asset)
            scenarios.append(scenario)

        # Scenario 2: Insider threat
        insider_scenario = {
            "scenario_id": "THREAT-INSIDER-001",
            "title": "Malicious or negligent insider",
            "description": "Internal actor compromises or mishandles asset",
            "threat_actor": "Insider (employee/contractor)",
            "threat_motive": "Financial gain, revenge, or negligence",
            "access_required": "Authorized access",
            "probability": context.get("insider_threat_probability", "medium"),
        }
        scenarios.append(insider_scenario)

        # Scenario 3: External attack
        external_scenario = {
            "scenario_id": "THREAT-EXTERNAL-001",
            "title": "External cyber attack",
            "description": "External threat actor targets asset",
            "threat_actor": "External attacker (hacker, APT)",
            "threat_motive": "Data theft, disruption, or ransom",
            "access_required": "Remote network access",
            "probability": context.get("external_threat_probability", "medium"),
        }
        scenarios.append(external_scenario)

        # Overall threat landscape
        threat_analysis = {
            "scenarios": scenarios,
            "total_scenarios": len(scenarios),
            "highest_probability": self._get_highest_probability(scenarios),
            "vulnerability_count": 1 if cve else 0,
            "threat_actors": list(set(s["threat_actor"] for s in scenarios)),
        }

        return threat_analysis

    def _calculate_risk_scores(
        self,
        asset_profile: Dict[str, Any],
        threat_scenarios: Dict[str, Any],
        drivers: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Calculate risk scores based on OCTAVE methodology.

        Args:
            asset_profile: Asset profile from Phase 2
            threat_scenarios: Threat scenarios from Phase 3
            drivers: Organizational drivers from Phase 1

        Returns:
            Risk scoring results
        """
        logger.debug("Calculating OCTAVE risk scores")

        # Base criticality score
        criticality_score = asset_profile["criticality_score"]

        # Impact assessment across multiple areas
        impact_scores = {}
        for area in drivers["impact_areas"]:
            # Base impact from asset criticality
            base_impact = criticality_score / 2  # Scale to 0-5

            # Adjust based on threat scenarios
            if threat_scenarios["vulnerability_count"] > 0:
                base_impact += 1.0

            if threat_scenarios["highest_probability"] in ["high", "critical"]:
                base_impact += 0.5

            impact_scores[area] = min(base_impact, 5.0)

        # Probability assessment
        probability_score = self._calculate_probability(threat_scenarios)

        # Risk score = Impact × Probability
        # Using average impact across all areas
        avg_impact = sum(impact_scores.values()) / len(impact_scores) if impact_scores else 3.0

        # Scale to 0-10
        risk_score = (avg_impact * probability_score) / 5.0 * 10.0

        return {
            "overall_risk_score": round(risk_score, 2),
            "impact_scores": {k: round(v, 2) for k, v in impact_scores.items()},
            "average_impact": round(avg_impact, 2),
            "probability_score": round(probability_score, 2),
            "asset_criticality_contribution": round(criticality_score * 0.3, 2),
            "threat_contribution": round(probability_score * 0.7, 2),
        }

    def _assess_asset_criticality(
        self,
        asset: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """Assess asset criticality level.

        Args:
            asset: Asset data
            context: Context data

        Returns:
            Criticality level (low/medium/high/critical)
        """
        # Check if explicitly provided
        if "criticality" in asset:
            return asset["criticality"]

        if "asset_criticality" in context:
            return context["asset_criticality"]

        # Infer from asset type
        asset_type = asset.get("type", "").lower()

        if any(term in asset_type for term in ["critical", "production", "customer"]):
            return AssetCriticality.HIGH.value
        elif any(term in asset_type for term in ["development", "test", "staging"]):
            return AssetCriticality.MEDIUM.value
        else:
            return AssetCriticality.MEDIUM.value

    def _criticality_to_score(self, criticality: str) -> float:
        """Convert criticality level to numeric score (0-10).

        Args:
            criticality: Criticality level string

        Returns:
            Numeric score
        """
        mapping = {
            AssetCriticality.LOW.value: 2.5,
            AssetCriticality.MEDIUM.value: 5.0,
            AssetCriticality.HIGH.value: 7.5,
            AssetCriticality.CRITICAL.value: 10.0,
        }
        return mapping.get(criticality.lower(), 5.0)

    def _determine_security_requirements(
        self,
        criticality: str,
        asset: Dict[str, Any],
    ) -> Dict[str, str]:
        """Determine security requirements based on criticality.

        Args:
            criticality: Asset criticality level
            asset: Asset data

        Returns:
            Security requirements (confidentiality, integrity, availability)
        """
        crit_level = criticality.lower()

        if crit_level in [AssetCriticality.HIGH.value, AssetCriticality.CRITICAL.value]:
            return {
                "confidentiality": "High",
                "integrity": "High",
                "availability": "High",
            }
        elif crit_level == AssetCriticality.MEDIUM.value:
            return {
                "confidentiality": "Medium",
                "integrity": "High",
                "availability": "Medium",
            }
        else:
            return {
                "confidentiality": "Low",
                "integrity": "Medium",
                "availability": "Low",
            }

    def _define_impact_thresholds(self, risk_tolerance: str) -> Dict[str, int]:
        """Define impact thresholds based on risk tolerance.

        Args:
            risk_tolerance: Organization's risk tolerance (low/medium/high)

        Returns:
            Impact threshold values
        """
        if risk_tolerance == "low":
            return {"acceptable": 2, "unacceptable": 3}
        elif risk_tolerance == "high":
            return {"acceptable": 4, "unacceptable": 5}
        else:  # medium
            return {"acceptable": 3, "unacceptable": 4}

    def _create_vulnerability_scenario(
        self,
        cve: Dict[str, Any],
        asset: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Create threat scenario from CVE vulnerability.

        Args:
            cve: CVE data
            asset: Asset data

        Returns:
            Threat scenario dictionary
        """
        cve_id = cve.get("id", "CVE-UNKNOWN")
        cvss_score = float(cve.get("cvss_score", 5.0))

        # Map CVSS to probability
        if cvss_score >= 9.0:
            probability = "critical"
        elif cvss_score >= 7.0:
            probability = "high"
        elif cvss_score >= 4.0:
            probability = "medium"
        else:
            probability = "low"

        scenario = {
            "scenario_id": f"THREAT-{cve_id}",
            "title": f"Exploitation of {cve_id}",
            "description": cve.get("description", "Vulnerability exploitation"),
            "threat_actor": "External attacker",
            "threat_motive": "System compromise or data breach",
            "access_required": "Network access to vulnerable component",
            "probability": probability,
            "cvss_score": cvss_score,
        }

        return scenario

    def _get_highest_probability(self, scenarios: List[Dict[str, Any]]) -> str:
        """Get the highest probability level from scenarios.

        Args:
            scenarios: List of threat scenarios

        Returns:
            Highest probability level
        """
        probability_order = ["low", "medium", "high", "critical"]

        probabilities = [s.get("probability", "low") for s in scenarios]

        for level in reversed(probability_order):
            if level in probabilities:
                return level

        return "medium"

    def _calculate_probability(self, threat_scenarios: Dict[str, Any]) -> float:
        """Calculate overall probability score (0-5).

        Args:
            threat_scenarios: Threat scenario analysis

        Returns:
            Probability score
        """
        highest_prob = threat_scenarios["highest_probability"]

        mapping = {
            "low": 1.5,
            "medium": 3.0,
            "high": 4.0,
            "critical": 5.0,
        }

        return mapping.get(highest_prob, 3.0)

    def _generate_recommendations(
        self,
        overall_score: float,
        asset_profile: Dict[str, Any],
        threat_scenarios: Dict[str, Any],
    ) -> List[str]:
        """Generate risk mitigation recommendations.

        Args:
            overall_score: Overall risk score
            asset_profile: Asset profile
            threat_scenarios: Threat scenarios

        Returns:
            List of recommendations
        """
        recommendations = []

        if overall_score >= 7.0:
            recommendations.append("Immediate mitigation required - High risk identified")
            recommendations.append("Implement compensating controls")

        if asset_profile["criticality"] in ["high", "critical"]:
            recommendations.append("Enhanced monitoring for critical asset")
            recommendations.append("Regular security assessments")

        if threat_scenarios["vulnerability_count"] > 0:
            recommendations.append("Patch identified vulnerabilities immediately")

        recommendations.append("Review and update incident response procedures")
        recommendations.append("Conduct regular threat scenario exercises")

        return recommendations

    def _score_to_risk_level(self, score: float) -> str:
        """Convert numeric score to risk level.

        Args:
            score: Risk score (0-10)

        Returns:
            Risk level string
        """
        if score >= 8.0:
            return "Critical"
        elif score >= 6.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
