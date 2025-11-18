"""ISO 31000:2018 Risk Management Framework Adapter.

Implements the ISO 31000:2018 international standard for risk management,
including risk identification, analysis, evaluation, and treatment planning.

ISO 31000 provides principles and guidelines for effective risk management
applicable to any organization regardless of size, activity, or sector.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class LikelihoodLevel(Enum):
    """Likelihood levels for 5x5 risk matrix."""
    RARE = 1
    UNLIKELY = 2
    POSSIBLE = 3
    LIKELY = 4
    ALMOST_CERTAIN = 5


class ConsequenceLevel(Enum):
    """Consequence levels for 5x5 risk matrix."""
    INSIGNIFICANT = 1
    MINOR = 2
    MODERATE = 3
    MAJOR = 4
    CATASTROPHIC = 5


class RiskTreatment(Enum):
    """Risk treatment options."""
    AVOID = "avoid"
    REDUCE = "reduce"
    SHARE = "share"
    ACCEPT = "accept"


class ISO31000Adapter:
    """Adapter for ISO 31000:2018 Risk Management Framework.

    Implements the ISO 31000 risk assessment process:
    1. Risk Identification - Identify sources and events
    2. Risk Analysis - Determine likelihood and consequences
    3. Risk Evaluation - Compare against criteria
    4. Risk Treatment - Identify treatment options
    """

    # 5x5 Risk Matrix: Likelihood × Consequence = Risk Rating
    # Risk ratings: 1-4 = Low, 5-9 = Medium, 10-15 = High, 16-25 = Critical
    RISK_MATRIX = {
        (1, 1): 1, (1, 2): 2, (1, 3): 3, (1, 4): 4, (1, 5): 5,
        (2, 1): 2, (2, 2): 4, (2, 3): 6, (2, 4): 8, (2, 5): 10,
        (3, 1): 3, (3, 2): 6, (3, 3): 9, (3, 4): 12, (3, 5): 15,
        (4, 1): 4, (4, 2): 8, (4, 3): 12, (4, 4): 16, (4, 5): 20,
        (5, 1): 5, (5, 2): 10, (5, 3): 15, (5, 4): 20, (5, 5): 25,
    }

    # Likelihood descriptors
    LIKELIHOOD_DESCRIPTORS = {
        LikelihoodLevel.RARE: "May occur only in exceptional circumstances (< 5% per year)",
        LikelihoodLevel.UNLIKELY: "Could occur at some time (5-25% per year)",
        LikelihoodLevel.POSSIBLE: "Might occur at some time (25-50% per year)",
        LikelihoodLevel.LIKELY: "Will probably occur (50-75% per year)",
        LikelihoodLevel.ALMOST_CERTAIN: "Expected to occur (> 75% per year)",
    }

    # Consequence descriptors (financial impact)
    CONSEQUENCE_DESCRIPTORS = {
        ConsequenceLevel.INSIGNIFICANT: "< $10K impact, minimal disruption",
        ConsequenceLevel.MINOR: "$10K-$100K impact, minor disruption",
        ConsequenceLevel.MODERATE: "$100K-$1M impact, moderate disruption",
        ConsequenceLevel.MAJOR: "$1M-$10M impact, major disruption",
        ConsequenceLevel.CATASTROPHIC: "> $10M impact, catastrophic disruption",
    }

    def __init__(self, risk_appetite: str = "moderate"):
        """Initialize ISO 31000 adapter.

        Args:
            risk_appetite: Organization's risk appetite (conservative/moderate/aggressive)
        """
        self.risk_appetite = risk_appetite
        logger.info(f"ISO 31000 adapter initialized (risk appetite: {risk_appetite})")

    def assess_risk(
        self,
        cve: Optional[Dict[str, Any]] = None,
        asset: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Perform ISO 31000 risk assessment.

        Args:
            cve: CVE vulnerability data
            asset: Asset information
            context: Additional context (controls, exposure, etc.)

        Returns:
            Comprehensive ISO 31000 risk assessment
        """
        logger.info("Executing ISO 31000 risk assessment")

        context = context or {}

        # Step 1: Risk Identification
        risk_identification = self._identify_risk(cve, asset, context)

        # Step 2: Risk Analysis
        risk_analysis = self._analyze_risk(cve, asset, context)

        # Step 3: Risk Evaluation
        risk_evaluation = self._evaluate_risk(risk_analysis, context)

        # Step 4: Risk Treatment
        risk_treatment = self._determine_treatment(risk_evaluation, context)

        # Calculate scores
        inherent_risk = risk_analysis["inherent_risk_rating"]
        residual_risk = risk_analysis.get("residual_risk_rating", inherent_risk)

        # Scale to 0-10 for consistency with other frameworks
        overall_score = self._matrix_to_score(inherent_risk)

        assessment = {
            "framework": "ISO 31000:2018",
            "overall_score": overall_score,
            "risk_level": self._rating_to_level(inherent_risk),
            "risk_identification": risk_identification,
            "risk_analysis": risk_analysis,
            "risk_evaluation": risk_evaluation,
            "risk_treatment": risk_treatment,
            "risk_matrix": {
                "likelihood": risk_analysis["likelihood_level"],
                "consequence": risk_analysis["consequence_level"],
                "inherent_rating": inherent_risk,
                "residual_rating": residual_risk,
            },
            "recommendations": self._generate_recommendations(risk_evaluation, risk_treatment),
            "confidence": 0.85,
            "assessed_at": datetime.utcnow().isoformat(),
        }

        return assessment

    def _identify_risk(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Step 1: Identify risk sources, events, and causes.

        Args:
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Risk identification results
        """
        logger.debug("ISO 31000 Step 1: Risk Identification")

        # Risk event
        if cve:
            risk_event = f"Exploitation of {cve.get('id', 'vulnerability')}"
            risk_source = "Technical vulnerability"
            risk_description = cve.get("description", "Security vulnerability")
        else:
            risk_event = "Security incident or breach"
            risk_source = "General security threat"
            risk_description = "Potential security compromise"

        # Asset at risk
        asset_name = asset.get("name", "Unknown Asset") if asset else "Information System"

        # Risk causes
        causes = []
        if cve:
            causes.append("Unpatched software vulnerability")
            causes.append("Insufficient security controls")

        causes.extend([
            "Inadequate access controls",
            "Lack of monitoring and detection",
            "Insufficient incident response capability",
        ])

        # Risk consequences
        consequences = [
            "Loss of confidentiality",
            "Loss of integrity",
            "Loss of availability",
            "Regulatory non-compliance",
            "Reputational damage",
        ]

        identification = {
            "risk_event": risk_event,
            "risk_source": risk_source,
            "risk_description": risk_description,
            "affected_asset": asset_name,
            "risk_causes": causes,
            "potential_consequences": consequences,
            "risk_owner": asset.get("owner", "IT Security") if asset else "IT Security",
        }

        return identification

    def _analyze_risk(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Step 2: Analyze likelihood and consequences.

        Args:
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Risk analysis with likelihood and consequence ratings
        """
        logger.debug("ISO 31000 Step 2: Risk Analysis")

        # Determine likelihood
        likelihood = self._assess_likelihood(cve, asset, context)

        # Determine consequence
        consequence = self._assess_consequence(cve, asset, context)

        # Calculate inherent risk rating (5x5 matrix)
        inherent_rating = self.RISK_MATRIX[(likelihood, consequence)]

        # Calculate residual risk (after existing controls)
        residual_rating = self._calculate_residual_risk(
            likelihood, consequence, context
        )

        analysis = {
            "likelihood_level": likelihood,
            "likelihood_descriptor": self.LIKELIHOOD_DESCRIPTORS[LikelihoodLevel(likelihood)],
            "consequence_level": consequence,
            "consequence_descriptor": self.CONSEQUENCE_DESCRIPTORS[ConsequenceLevel(consequence)],
            "inherent_risk_rating": inherent_rating,
            "residual_risk_rating": residual_rating,
            "risk_reduction": inherent_rating - residual_rating,
            "control_effectiveness": self._calculate_control_effectiveness(
                inherent_rating, residual_rating
            ),
        }

        return analysis

    def _evaluate_risk(
        self,
        risk_analysis: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Step 3: Evaluate risk against acceptance criteria.

        Args:
            risk_analysis: Results from risk analysis
            context: Context data

        Returns:
            Risk evaluation results
        """
        logger.debug("ISO 31000 Step 3: Risk Evaluation")

        residual_rating = risk_analysis["residual_risk_rating"]

        # Determine acceptance threshold based on risk appetite
        acceptance_threshold = self._get_acceptance_threshold()

        # Evaluate if risk is acceptable
        is_acceptable = residual_rating <= acceptance_threshold

        # Priority for treatment
        priority = self._determine_priority(residual_rating)

        evaluation = {
            "residual_risk_rating": residual_rating,
            "risk_level": self._rating_to_level(residual_rating),
            "acceptance_threshold": acceptance_threshold,
            "is_acceptable": is_acceptable,
            "requires_treatment": not is_acceptable,
            "priority": priority,
            "risk_appetite": self.risk_appetite,
        }

        return evaluation

    def _determine_treatment(
        self,
        risk_evaluation: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Step 4: Determine risk treatment options.

        Args:
            risk_evaluation: Risk evaluation results
            context: Context data

        Returns:
            Risk treatment plan
        """
        logger.debug("ISO 31000 Step 4: Risk Treatment")

        residual_rating = risk_evaluation["residual_risk_rating"]
        is_acceptable = risk_evaluation["is_acceptable"]

        if is_acceptable:
            primary_option = RiskTreatment.ACCEPT
        elif residual_rating >= 16:
            # Critical/High risks - avoid or reduce
            primary_option = RiskTreatment.REDUCE
        elif residual_rating >= 10:
            # Medium-High risks - reduce or share
            primary_option = RiskTreatment.REDUCE
        else:
            # Low-Medium risks - reduce or accept
            primary_option = RiskTreatment.ACCEPT

        # Generate treatment options
        treatment_options = self._generate_treatment_options(residual_rating, context)

        treatment = {
            "primary_treatment": primary_option.value,
            "treatment_options": treatment_options,
            "requires_action": not is_acceptable,
            "treatment_priority": risk_evaluation["priority"],
            "cost_benefit_required": residual_rating >= 10,
        }

        return treatment

    def _assess_likelihood(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> int:
        """Assess likelihood level (1-5).

        Args:
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Likelihood level (1-5)
        """
        # Start with base likelihood
        base_likelihood = 3  # Possible

        # Adjust based on CVE severity
        if cve and "cvss_score" in cve:
            cvss = float(cve["cvss_score"])
            if cvss >= 9.0:
                base_likelihood = 5  # Almost certain
            elif cvss >= 7.0:
                base_likelihood = 4  # Likely
            elif cvss >= 4.0:
                base_likelihood = 3  # Possible

        # Adjust based on exposure
        exposure = context.get("exposure", "medium")
        if exposure == "high":
            base_likelihood = min(base_likelihood + 1, 5)
        elif exposure == "low":
            base_likelihood = max(base_likelihood - 1, 1)

        # Adjust based on threat landscape
        threat_level = context.get("threat_level", "medium")
        if threat_level == "high":
            base_likelihood = min(base_likelihood + 1, 5)

        return base_likelihood

    def _assess_consequence(
        self,
        cve: Optional[Dict[str, Any]],
        asset: Optional[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> int:
        """Assess consequence level (1-5).

        Args:
            cve: CVE data
            asset: Asset data
            context: Context data

        Returns:
            Consequence level (1-5)
        """
        # Start with base consequence
        base_consequence = 3  # Moderate

        # Adjust based on asset criticality
        if asset:
            criticality = asset.get("criticality", "medium").lower()
            if criticality in ["critical", "high"]:
                base_consequence = 4  # Major
            elif criticality == "low":
                base_consequence = 2  # Minor

        # Adjust based on impact estimate
        impact = context.get("estimated_impact", "medium")
        if impact in ["critical", "high"]:
            base_consequence = min(base_consequence + 1, 5)
        elif impact == "low":
            base_consequence = max(base_consequence - 1, 1)

        # Adjust based on data sensitivity
        data_sensitivity = context.get("data_sensitivity", "medium")
        if data_sensitivity == "high":
            base_consequence = min(base_consequence + 1, 5)

        return base_consequence

    def _calculate_residual_risk(
        self,
        likelihood: int,
        consequence: int,
        context: Dict[str, Any],
    ) -> int:
        """Calculate residual risk after existing controls.

        Args:
            likelihood: Inherent likelihood
            consequence: Inherent consequence
            context: Context with control information

        Returns:
            Residual risk rating
        """
        # Check for existing controls
        has_controls = context.get("has_controls", False)

        if not has_controls:
            # No controls - residual = inherent
            return self.RISK_MATRIX[(likelihood, consequence)]

        # With controls, reduce likelihood and/or consequence
        control_effectiveness = context.get("control_effectiveness", "medium")

        if control_effectiveness == "high":
            # Reduce both by 1 level
            reduced_likelihood = max(likelihood - 1, 1)
            reduced_consequence = max(consequence - 1, 1)
        elif control_effectiveness == "medium":
            # Reduce likelihood by 1
            reduced_likelihood = max(likelihood - 1, 1)
            reduced_consequence = consequence
        else:
            # Low effectiveness - minimal reduction
            reduced_likelihood = likelihood
            reduced_consequence = consequence

        return self.RISK_MATRIX[(reduced_likelihood, reduced_consequence)]

    def _calculate_control_effectiveness(
        self,
        inherent_rating: int,
        residual_rating: int,
    ) -> float:
        """Calculate control effectiveness percentage.

        Args:
            inherent_rating: Inherent risk rating
            residual_rating: Residual risk rating

        Returns:
            Control effectiveness (0-1)
        """
        if inherent_rating == 0:
            return 0.0

        reduction = (inherent_rating - residual_rating) / inherent_rating
        return max(0.0, min(reduction, 1.0))

    def _get_acceptance_threshold(self) -> int:
        """Get risk acceptance threshold based on risk appetite.

        Returns:
            Maximum acceptable risk rating
        """
        thresholds = {
            "conservative": 4,   # Only Low risks acceptable
            "moderate": 9,       # Low and some Medium risks acceptable
            "aggressive": 15,    # Low, Medium, and some High risks acceptable
        }

        return thresholds.get(self.risk_appetite, 9)

    def _determine_priority(self, risk_rating: int) -> str:
        """Determine treatment priority based on risk rating.

        Args:
            risk_rating: Risk rating from matrix

        Returns:
            Priority level (Critical/High/Medium/Low)
        """
        if risk_rating >= 16:
            return "Critical"
        elif risk_rating >= 10:
            return "High"
        elif risk_rating >= 5:
            return "Medium"
        else:
            return "Low"

    def _generate_treatment_options(
        self,
        risk_rating: int,
        context: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """Generate specific risk treatment options.

        Args:
            risk_rating: Risk rating
            context: Context data

        Returns:
            List of treatment options
        """
        options = []

        # REDUCE option
        options.append({
            "treatment": RiskTreatment.REDUCE.value,
            "description": "Implement additional security controls",
            "examples": "Patch vulnerabilities, enhance monitoring, strengthen access controls",
        })

        # SHARE option
        if risk_rating >= 10:
            options.append({
                "treatment": RiskTreatment.SHARE.value,
                "description": "Transfer risk through insurance or outsourcing",
                "examples": "Cyber insurance, managed security services",
            })

        # AVOID option
        if risk_rating >= 16:
            options.append({
                "treatment": RiskTreatment.AVOID.value,
                "description": "Eliminate risk by discontinuing activity",
                "examples": "Decommission vulnerable system, discontinue service",
            })

        # ACCEPT option
        if risk_rating <= 9:
            options.append({
                "treatment": RiskTreatment.ACCEPT.value,
                "description": "Accept risk within appetite",
                "examples": "Document acceptance, monitor for changes",
            })

        return options

    def _generate_recommendations(
        self,
        risk_evaluation: Dict[str, Any],
        risk_treatment: Dict[str, Any],
    ) -> List[str]:
        """Generate recommendations based on evaluation.

        Args:
            risk_evaluation: Risk evaluation results
            risk_treatment: Risk treatment plan

        Returns:
            List of recommendations
        """
        recommendations = []

        if not risk_evaluation["is_acceptable"]:
            recommendations.append(
                f"Risk exceeds acceptance threshold - {risk_treatment['primary_treatment']} required"
            )

        if risk_evaluation["priority"] in ["Critical", "High"]:
            recommendations.append("Immediate action required for high-priority risk")

        if risk_treatment["cost_benefit_required"]:
            recommendations.append("Conduct cost-benefit analysis for treatment options")

        recommendations.extend([
            "Document risk treatment decisions",
            "Establish monitoring and review schedule",
            "Assign risk owner accountability",
        ])

        return recommendations

    def _matrix_to_score(self, rating: int) -> float:
        """Convert 5x5 matrix rating to 0-10 score.

        Args:
            rating: Matrix rating (1-25)

        Returns:
            Score (0-10)
        """
        # Scale 1-25 to 0-10
        return round((rating / 25.0) * 10.0, 2)

    def _rating_to_level(self, rating: int) -> str:
        """Convert matrix rating to risk level.

        Args:
            rating: Matrix rating (1-25)

        Returns:
            Risk level string
        """
        if rating >= 16:
            return "Critical"
        elif rating >= 10:
            return "High"
        elif rating >= 5:
            return "Medium"
        else:
            return "Low"
