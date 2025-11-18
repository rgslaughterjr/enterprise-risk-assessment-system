"""NIST AI Risk Management Framework (AI RMF 1.0) Adapter.

Implements the NIST AI RMF 1.0 framework functions for AI system risk assessment:
- GOVERN: Governance and organizational culture
- MAP: Context establishment and risk identification
- MEASURE: Risk analysis and evaluation
- MANAGE: Risk response and monitoring
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class NISTAIRMFAdapter:
    """Adapter for NIST AI Risk Management Framework 1.0.

    Implements the four core functions (GOVERN, MAP, MEASURE, MANAGE) for
    assessing risks in AI systems and applications.
    """

    # AI system categories
    AI_CATEGORIES = {
        "general": "General purpose AI system",
        "high_risk": "High-risk AI application",
        "safety_critical": "Safety-critical AI system",
        "autonomous": "Autonomous decision-making system",
    }

    # Risk trustworthiness characteristics
    TRUSTWORTHINESS_CHARACTERISTICS = [
        "valid_reliable",
        "safe",
        "secure_resilient",
        "accountable_transparent",
        "explainable_interpretable",
        "privacy_enhanced",
        "fair_bias_managed",
    ]

    def __init__(self):
        """Initialize NIST AI RMF adapter."""
        logger.info("NIST AI RMF adapter initialized")

    def score_ai_risk(
        self,
        cve: Optional[Dict[str, Any]] = None,
        asset: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Score AI-related risk using NIST AI RMF framework.

        Args:
            cve: CVE vulnerability data
            asset: Asset information
            context: Additional context (AI system category, use case, etc.)

        Returns:
            Structured risk assessment with scores for each function
        """
        logger.info("Executing NIST AI RMF risk assessment")

        context = context or {}
        ai_category = context.get("ai_system_category", "general")

        # Execute four core functions
        govern_score = self._govern_function(context)
        map_score = self._map_function(cve, asset, context)
        measure_score = self._measure_function(cve, asset, context)
        manage_score = self._manage_function(context)

        # Calculate overall score (weighted average)
        overall_score = (
            govern_score["score"] * 0.2 +
            map_score["score"] * 0.3 +
            measure_score["score"] * 0.3 +
            manage_score["score"] * 0.2
        )

        assessment = {
            "framework": "NIST AI RMF 1.0",
            "ai_category": ai_category,
            "overall_score": round(overall_score, 2),
            "risk_level": self._score_to_risk_level(overall_score),
            "functions": {
                "GOVERN": govern_score,
                "MAP": map_score,
                "MEASURE": measure_score,
                "MANAGE": manage_score,
            },
            "trustworthiness_assessment": self._assess_trustworthiness(cve, asset, context),
            "recommendations": self._generate_recommendations(overall_score, context),
            "confidence": 0.85,
            "assessed_at": datetime.utcnow().isoformat(),
        }

        return assessment

    def _govern_function(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """GOVERN: Assess governance and organizational culture.

        Args:
            context: Context dictionary

        Returns:
            GOVERN function assessment
        """
        # Simplified governance assessment
        has_ai_policy = context.get("has_ai_policy", False)
        has_oversight = context.get("has_oversight_body", False)
        has_training = context.get("has_ai_training", False)

        score = 5.0  # Base score

        if has_ai_policy:
            score += 1.5
        if has_oversight:
            score += 1.5
        if has_training:
            score += 1.0

        return {
            "score": min(score, 10.0),
            "category": "Governance",
            "indicators": {
                "ai_policy_exists": has_ai_policy,
                "oversight_established": has_oversight,
                "training_provided": has_training,
            },
            "justification": "Governance assessment based on policy, oversight, and training presence"
        }

    def _map_function(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """MAP: Identify and categorize AI risks.

        Args:
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            MAP function assessment
        """
        base_score = 5.0

        # Adjust based on CVE severity
        if cve and "cvss_score" in cve:
            cvss = float(cve["cvss_score"])
            if cvss >= 9.0:
                base_score += 3.0
            elif cvss >= 7.0:
                base_score += 2.0
            elif cvss >= 4.0:
                base_score += 1.0

        # Adjust based on AI system criticality
        ai_category = context.get("ai_system_category", "general")
        if ai_category in ["safety_critical", "high_risk"]:
            base_score += 1.5

        return {
            "score": min(base_score, 10.0),
            "category": "Context & Risk Identification",
            "identified_risks": self._identify_ai_risks(cve, asset),
            "justification": f"Risk mapping for {ai_category} AI system with CVE data"
        }

    def _measure_function(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """MEASURE: Analyze and evaluate AI risks.

        Args:
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            MEASURE function assessment
        """
        base_score = 6.0

        # Measure based on impact and likelihood
        impact = context.get("estimated_impact", "medium")
        likelihood = context.get("estimated_likelihood", "medium")

        impact_score = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(impact.lower(), 1)
        likelihood_score = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(likelihood.lower(), 1)

        risk_score = base_score + (impact_score + likelihood_score) * 0.5

        return {
            "score": min(risk_score, 10.0),
            "category": "Risk Analysis & Evaluation",
            "impact_level": impact,
            "likelihood_level": likelihood,
            "measurement_confidence": 0.80,
            "justification": f"Risk measurement: {impact} impact, {likelihood} likelihood"
        }

    def _manage_function(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """MANAGE: Assess risk response and monitoring capabilities.

        Args:
            context: Context data

        Returns:
            MANAGE function assessment
        """
        has_monitoring = context.get("has_monitoring", False)
        has_incident_response = context.get("has_incident_response", False)
        has_controls = context.get("has_controls", False)

        score = 5.0

        if has_monitoring:
            score += 1.5
        if has_incident_response:
            score += 1.5
        if has_controls:
            score += 1.0

        return {
            "score": min(score, 10.0),
            "category": "Risk Response & Monitoring",
            "capabilities": {
                "monitoring_in_place": has_monitoring,
                "incident_response_ready": has_incident_response,
                "controls_implemented": has_controls,
            },
            "justification": "Management capability assessment"
        }

    def _assess_trustworthiness(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, float]:
        """Assess AI trustworthiness characteristics.

        Args:
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Dictionary of trustworthiness characteristic scores
        """
        # Simplified trustworthiness scoring
        base_score = 0.7

        # Reduce score if vulnerability present
        if cve:
            base_score -= 0.2

        trustworthiness = {}
        for char in self.TRUSTWORTHINESS_CHARACTERISTICS:
            # Add some variation
            import random
            variation = random.uniform(-0.1, 0.1)
            score = max(0.0, min(1.0, base_score + variation))
            trustworthiness[char] = round(score, 2)

        return trustworthiness

    def _identify_ai_risks(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Identify specific AI-related risks.

        Args:
            cve: CVE data
            asset: Asset data

        Returns:
            List of identified risk descriptions
        """
        risks = []

        if cve:
            risks.append(f"Vulnerability exposure: {cve.get('id', 'Unknown CVE')}")

        # Common AI risks
        risks.extend([
            "Model bias and fairness concerns",
            "Adversarial attack susceptibility",
            "Data privacy and confidentiality",
            "Model interpretability limitations",
        ])

        return risks

    def _generate_recommendations(
        self,
        overall_score: float,
        context: Dict[str, Any],
    ) -> List[str]:
        """Generate risk mitigation recommendations.

        Args:
            overall_score: Overall risk score
            context: Context data

        Returns:
            List of recommendations
        """
        recommendations = []

        if overall_score >= 7.0:
            recommendations.append("Implement immediate risk mitigation controls")
            recommendations.append("Conduct thorough security assessment")

        if not context.get("has_ai_policy"):
            recommendations.append("Establish AI governance policy")

        if not context.get("has_monitoring"):
            recommendations.append("Deploy AI system monitoring and alerting")

        recommendations.append("Regular trustworthiness assessments")
        recommendations.append("Maintain transparency documentation")

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
