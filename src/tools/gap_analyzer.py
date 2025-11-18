"""Gap analyzer for identifying and prioritizing security control gaps.

This module analyzes control coverage gaps, prioritizes remediation based on
risk criteria, and generates actionable recommendations.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

import numpy as np

logger = logging.getLogger(__name__)


class GapAnalyzer:
    """Analyzes security control gaps and generates recommendations.

    Provides gap analysis capabilities including:
    - Coverage gap identification
    - Risk-based prioritization
    - Residual risk calculation
    - Remediation recommendations
    - Compliance gap analysis
    """

    # Priority levels
    PRIORITY_CRITICAL = "Critical"
    PRIORITY_HIGH = "High"
    PRIORITY_MEDIUM = "Medium"
    PRIORITY_LOW = "Low"

    # Gap categories
    CATEGORY_MISSING_CONTROL = "Missing Control"
    CATEGORY_PARTIAL_IMPLEMENTATION = "Partial Implementation"
    CATEGORY_INEFFECTIVE_CONTROL = "Ineffective Control"
    CATEGORY_OUTDATED_CONTROL = "Outdated Control"

    def __init__(self):
        """Initialize gap analyzer."""
        logger.info("Gap analyzer initialized")

    def analyze_gaps(
        self,
        risks: List[Dict[str, Any]],
        controls: List[Dict[str, Any]],
        control_mappings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Analyze control gaps across all risks.

        Args:
            risks: List of risk dictionaries
            controls: List of control dictionaries
            control_mappings: Optional control-risk mappings (will compute if not provided)

        Returns:
            Comprehensive gap analysis report

        Example:
            >>> analyzer = GapAnalyzer()
            >>> analysis = analyzer.analyze_gaps(risks, controls)
        """
        logger.info(f"Analyzing gaps for {len(risks)} risks and {len(controls)} controls")

        # Build control-risk mapping if not provided
        if control_mappings is None:
            from src.tools.control_risk_matcher import ControlRiskMatcher
            matcher = ControlRiskMatcher()
            control_mappings = matcher.match_controls_to_risks(controls, risks)

        # Group controls by risk
        risk_controls = self._group_controls_by_risk(control_mappings, controls)

        # Analyze each risk
        gaps = []
        covered_risks = []

        for risk in risks:
            risk_id = risk.get("id", "UNKNOWN")
            mitigating_controls = risk_controls.get(risk_id, [])

            gap_analysis = self._analyze_risk_gap(risk, mitigating_controls)

            if gap_analysis["has_gap"]:
                gaps.append(gap_analysis)
            else:
                covered_risks.append(gap_analysis)

        # Calculate summary statistics
        summary = self._calculate_summary_stats(risks, controls, gaps, covered_risks)

        # Generate recommendations
        recommendations = self._generate_recommendations(gaps)

        analysis_report = {
            "analysis_date": datetime.utcnow().isoformat(),
            "summary": summary,
            "gaps": gaps,
            "covered_risks": covered_risks,
            "recommendations": recommendations,
        }

        logger.info(f"Gap analysis complete: {len(gaps)} gaps identified")
        return analysis_report

    def _group_controls_by_risk(
        self,
        mappings: List[Dict[str, Any]],
        controls: List[Dict[str, Any]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group controls by the risks they mitigate.

        Args:
            mappings: Control-risk mappings
            controls: List of controls

        Returns:
            Dictionary mapping risk IDs to lists of controls
        """
        risk_controls = defaultdict(list)
        control_by_id = {c.get("id"): c for c in controls}

        for mapping in mappings:
            risk_id = mapping.get("risk_id")
            control_id = mapping.get("control_id")

            if risk_id and control_id and control_id in control_by_id:
                risk_controls[risk_id].append(control_by_id[control_id])

        return dict(risk_controls)

    def _analyze_risk_gap(
        self,
        risk: Dict[str, Any],
        controls: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Analyze gaps for a single risk.

        Args:
            risk: Risk dictionary
            controls: List of controls that mitigate this risk

        Returns:
            Gap analysis dictionary
        """
        risk_id = risk.get("id", "UNKNOWN")
        risk_level = (risk.get("risk_level") or risk.get("severity", "Medium")).upper()

        # Calculate coverage metrics
        coverage_score = self._calculate_coverage_score(risk, controls)
        residual_risk = self._calculate_residual_risk(risk, controls, coverage_score)

        # Determine gap category
        gap_category = self._determine_gap_category(controls, coverage_score)

        # Check if there's a gap (coverage < 0.7)
        has_gap = coverage_score < 0.7

        gap_analysis = {
            "risk_id": risk_id,
            "risk_name": risk.get("title") or risk.get("name", ""),
            "risk_level": risk_level,
            "risk_description": risk.get("description", ""),
            "coverage_score": round(coverage_score, 2),
            "residual_risk": residual_risk,
            "has_gap": has_gap,
            "gap_category": gap_category if has_gap else None,
            "control_count": len(controls),
            "controls": [
                {
                    "id": c.get("id"),
                    "name": c.get("title") or c.get("name"),
                    "status": c.get("implementation_status"),
                    "effectiveness": c.get("effectiveness_score"),
                }
                for c in controls
            ],
        }

        return gap_analysis

    def _calculate_coverage_score(
        self,
        risk: Dict[str, Any],
        controls: List[Dict[str, Any]],
    ) -> float:
        """Calculate coverage score for a risk.

        Args:
            risk: Risk dictionary
            controls: Mitigating controls

        Returns:
            Coverage score (0.0 to 1.0)
        """
        if not controls:
            return 0.0

        score = 0.0

        # Base score from control count (diminishing returns)
        control_count_factor = min(len(controls) / 5.0, 0.5)
        score += control_count_factor

        # Implementation status factor
        implemented_count = sum(
            1 for c in controls
            if c.get("implementation_status") == "Implemented"
        )

        partial_count = sum(
            1 for c in controls
            if c.get("implementation_status") == "Partially Implemented"
        )

        if controls:
            implementation_factor = (implemented_count + partial_count * 0.5) / len(controls) * 0.3
            score += implementation_factor

        # Effectiveness factor
        effectiveness_scores = []
        for control in controls:
            eff = control.get("effectiveness_score")
            if eff is not None:
                try:
                    eff_float = float(eff)
                    if eff_float > 1.0:
                        eff_float /= 100.0
                    effectiveness_scores.append(eff_float)
                except (ValueError, TypeError):
                    continue

        if effectiveness_scores:
            avg_effectiveness = sum(effectiveness_scores) / len(effectiveness_scores)
            score += avg_effectiveness * 0.2

        return min(score, 1.0)

    def _calculate_residual_risk(
        self,
        risk: Dict[str, Any],
        controls: List[Dict[str, Any]],
        coverage_score: float,
    ) -> str:
        """Calculate residual risk after applying controls.

        Args:
            risk: Risk dictionary
            controls: Mitigating controls
            coverage_score: Coverage score

        Returns:
            Residual risk level
        """
        risk_level = (risk.get("risk_level") or risk.get("severity", "Medium")).upper()

        # Map to numeric values
        risk_values = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "MINIMAL": 1,
        }

        base_risk = risk_values.get(risk_level, 3)

        # Reduce by coverage
        residual_value = base_risk * (1 - coverage_score)

        # Map back to level
        if residual_value >= 4.5:
            return "Critical"
        elif residual_value >= 3.5:
            return "High"
        elif residual_value >= 2.0:
            return "Medium"
        elif residual_value >= 1.0:
            return "Low"
        else:
            return "Minimal"

    def _determine_gap_category(
        self,
        controls: List[Dict[str, Any]],
        coverage_score: float,
    ) -> str:
        """Determine the category of control gap.

        Args:
            controls: Mitigating controls
            coverage_score: Coverage score

        Returns:
            Gap category
        """
        if not controls:
            return self.CATEGORY_MISSING_CONTROL

        # Check implementation status
        statuses = [c.get("implementation_status") for c in controls]

        if all(s == "Not Implemented" or not s for s in statuses):
            return self.CATEGORY_MISSING_CONTROL

        if any(s == "Partially Implemented" for s in statuses):
            return self.CATEGORY_PARTIAL_IMPLEMENTATION

        # Check effectiveness
        low_effectiveness = sum(
            1 for c in controls
            if self._is_low_effectiveness(c)
        )

        if low_effectiveness > 0:
            return self.CATEGORY_INEFFECTIVE_CONTROL

        return self.CATEGORY_PARTIAL_IMPLEMENTATION

    def _is_low_effectiveness(self, control: Dict[str, Any]) -> bool:
        """Check if control has low effectiveness.

        Args:
            control: Control dictionary

        Returns:
            True if effectiveness is low
        """
        eff = control.get("effectiveness_score")
        if eff is None:
            return False

        try:
            eff_float = float(eff)
            if eff_float > 1.0:
                eff_float /= 100.0
            return eff_float < 0.5
        except (ValueError, TypeError):
            return False

    def prioritize_gaps(
        self,
        gaps: List[Dict[str, Any]],
        criteria: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Prioritize gaps based on multiple criteria.

        Args:
            gaps: List of gap dictionaries
            criteria: List of prioritization criteria (default: ['risk_level', 'coverage_score'])

        Returns:
            Prioritized list of gaps with priority assignments

        Example:
            >>> analyzer = GapAnalyzer()
            >>> prioritized = analyzer.prioritize_gaps(gaps, criteria=['risk_level', 'exploitability'])
        """
        if criteria is None:
            criteria = ["risk_level", "coverage_score"]

        logger.info(f"Prioritizing {len(gaps)} gaps using criteria: {criteria}")

        prioritized_gaps = []

        for gap in gaps:
            priority = self._calculate_priority(gap, criteria)

            gap_with_priority = gap.copy()
            gap_with_priority["priority"] = priority
            gap_with_priority["priority_score"] = self._priority_to_score(priority)

            prioritized_gaps.append(gap_with_priority)

        # Sort by priority score (higher = more urgent)
        prioritized_gaps.sort(key=lambda x: x["priority_score"], reverse=True)

        logger.info(f"Prioritization complete")
        return prioritized_gaps

    def _calculate_priority(
        self,
        gap: Dict[str, Any],
        criteria: List[str],
    ) -> str:
        """Calculate priority level for a gap.

        Args:
            gap: Gap dictionary
            criteria: Prioritization criteria

        Returns:
            Priority level
        """
        score = 0
        max_score = len(criteria) * 3

        for criterion in criteria:
            if criterion == "risk_level":
                risk_level = gap.get("risk_level", "Medium").upper()
                if risk_level in ["CRITICAL"]:
                    score += 3
                elif risk_level == "HIGH":
                    score += 2
                elif risk_level == "MEDIUM":
                    score += 1

            elif criterion == "coverage_score":
                coverage = gap.get("coverage_score", 0.5)
                if coverage < 0.2:
                    score += 3
                elif coverage < 0.4:
                    score += 2
                elif coverage < 0.6:
                    score += 1

            elif criterion == "exploitability":
                # Would check threat intelligence data in production
                # For now, use residual risk as proxy
                residual = gap.get("residual_risk", "Medium").upper()
                if residual in ["CRITICAL", "HIGH"]:
                    score += 2
                elif residual == "MEDIUM":
                    score += 1

        # Map score to priority level
        if score >= max_score * 0.75:
            return self.PRIORITY_CRITICAL
        elif score >= max_score * 0.5:
            return self.PRIORITY_HIGH
        elif score >= max_score * 0.25:
            return self.PRIORITY_MEDIUM
        else:
            return self.PRIORITY_LOW

    def _priority_to_score(self, priority: str) -> int:
        """Convert priority level to numeric score.

        Args:
            priority: Priority level

        Returns:
            Numeric score
        """
        priorities = {
            self.PRIORITY_CRITICAL: 4,
            self.PRIORITY_HIGH: 3,
            self.PRIORITY_MEDIUM: 2,
            self.PRIORITY_LOW: 1,
        }
        return priorities.get(priority, 1)

    def generate_recommendations(self, gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate recommendations for addressing gaps.

        Args:
            gaps: List of gap dictionaries (should be prioritized)

        Returns:
            List of recommendation dictionaries

        Example:
            >>> analyzer = GapAnalyzer()
            >>> recommendations = analyzer.generate_recommendations(prioritized_gaps)
        """
        logger.info(f"Generating recommendations for {len(gaps)} gaps")

        recommendations = []

        for gap in gaps:
            risk_id = gap.get("risk_id")
            risk_name = gap.get("risk_name")
            gap_category = gap.get("gap_category")
            priority = gap.get("priority", self.PRIORITY_MEDIUM)
            coverage = gap.get("coverage_score", 0)

            # Generate recommendation based on gap category
            recommendation = self._generate_recommendation_for_gap(
                risk_id, risk_name, gap_category, priority, coverage, gap
            )

            recommendations.append(recommendation)

        logger.info(f"Generated {len(recommendations)} recommendations")
        return recommendations

    def _generate_recommendation_for_gap(
        self,
        risk_id: str,
        risk_name: str,
        gap_category: str,
        priority: str,
        coverage: float,
        gap: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate recommendation for a specific gap.

        Args:
            risk_id: Risk ID
            risk_name: Risk name
            gap_category: Gap category
            priority: Priority level
            coverage: Current coverage score
            gap: Full gap dictionary

        Returns:
            Recommendation dictionary
        """
        # Generate recommendation based on category
        if gap_category == self.CATEGORY_MISSING_CONTROL:
            action = "Implement new security control"
            details = f"No controls currently in place for {risk_name}. Identify and implement appropriate controls from relevant frameworks (NIST, CIS, ISO)."

        elif gap_category == self.CATEGORY_PARTIAL_IMPLEMENTATION:
            action = "Complete control implementation"
            details = f"Existing controls for {risk_name} are partially implemented. Complete implementation and validation of these controls."

        elif gap_category == self.CATEGORY_INEFFECTIVE_CONTROL:
            action = "Improve control effectiveness"
            details = f"Controls for {risk_name} are ineffective (low effectiveness scores). Review and enhance existing controls or replace with more effective alternatives."

        elif gap_category == self.CATEGORY_OUTDATED_CONTROL:
            action = "Update or replace controls"
            details = f"Controls for {risk_name} may be outdated. Review against current best practices and update accordingly."

        else:
            action = "Review control coverage"
            details = f"Control coverage for {risk_name} is below threshold ({coverage:.0%}). Additional controls may be needed."

        # Calculate effort and timeline based on priority
        effort, timeline = self._estimate_effort_timeline(priority, gap)

        recommendation = {
            "risk_id": risk_id,
            "risk_name": risk_name,
            "priority": priority,
            "gap_category": gap_category,
            "action": action,
            "details": details,
            "estimated_effort": effort,
            "recommended_timeline": timeline,
            "current_coverage": round(coverage, 2),
            "created_at": datetime.utcnow().isoformat(),
        }

        return recommendation

    def _estimate_effort_timeline(
        self,
        priority: str,
        gap: Dict[str, Any],
    ) -> Tuple[str, str]:
        """Estimate effort and timeline for remediation.

        Args:
            priority: Priority level
            gap: Gap dictionary

        Returns:
            Tuple of (effort, timeline)
        """
        # Effort estimates
        if gap.get("gap_category") == self.CATEGORY_MISSING_CONTROL:
            effort = "High"
        elif gap.get("gap_category") == self.CATEGORY_PARTIAL_IMPLEMENTATION:
            effort = "Medium"
        else:
            effort = "Low"

        # Timeline based on priority
        if priority == self.PRIORITY_CRITICAL:
            timeline = "Immediate (1-2 weeks)"
        elif priority == self.PRIORITY_HIGH:
            timeline = "Short-term (1 month)"
        elif priority == self.PRIORITY_MEDIUM:
            timeline = "Medium-term (3 months)"
        else:
            timeline = "Long-term (6 months)"

        return effort, timeline

    def _calculate_summary_stats(
        self,
        risks: List[Dict[str, Any]],
        controls: List[Dict[str, Any]],
        gaps: List[Dict[str, Any]],
        covered_risks: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Calculate summary statistics for gap analysis.

        Args:
            risks: All risks
            controls: All controls
            gaps: Identified gaps
            covered_risks: Adequately covered risks

        Returns:
            Summary statistics dictionary
        """
        total_risks = len(risks)
        total_controls = len(controls)
        gap_count = len(gaps)
        covered_count = len(covered_risks)

        coverage_rate = (covered_count / total_risks * 100) if total_risks > 0 else 0

        # Calculate average coverage
        all_coverage_scores = [g.get("coverage_score", 0) for g in gaps + covered_risks]
        avg_coverage = sum(all_coverage_scores) / len(all_coverage_scores) if all_coverage_scores else 0

        summary = {
            "total_risks": total_risks,
            "total_controls": total_controls,
            "gaps_identified": gap_count,
            "adequately_covered": covered_count,
            "coverage_rate": round(coverage_rate, 1),
            "average_coverage_score": round(avg_coverage, 2),
        }

        return summary

    def _generate_recommendations(
        self,
        gaps: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Generate recommendations from gaps.

        Args:
            gaps: List of gaps

        Returns:
            List of recommendations
        """
        # Prioritize gaps first
        prioritized = self.prioritize_gaps(gaps)

        # Generate recommendations
        return self.generate_recommendations(prioritized)
