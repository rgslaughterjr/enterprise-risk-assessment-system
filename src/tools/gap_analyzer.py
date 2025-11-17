"""
Gap Analyzer

Analyzes gaps between risks and controls, identifies uncovered risks,
and generates remediation recommendations.
"""

from typing import Dict, List
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class GapAnalyzer:
    """Analyze security control gaps."""

    PRIORITY_LEVELS = {
        'Critical': 1,
        'High': 2,
        'Medium': 3,
        'Low': 4
    }

    def __init__(self):
        """Initialize gap analyzer."""
        logger.info("Initialized GapAnalyzer")

    def analyze_gaps(self, risks: List[Dict], controls: List[Dict],
                    risk_control_mapping: Dict) -> Dict:
        """
        Perform comprehensive gap analysis.

        Args:
            risks: List of identified risks
            controls: List of security controls
            risk_control_mapping: Mapping from risk_id to applicable controls

        Returns:
            Gap analysis report with recommendations
        """
        logger.info(f"Analyzing gaps for {len(risks)} risks and {len(controls)} controls...")

        # Identify uncovered risks
        uncovered_risks = self._find_uncovered_risks(risks, risk_control_mapping)

        # Identify partially covered risks
        partially_covered = self._find_partially_covered_risks(risks, risk_control_mapping)

        # Identify redundant controls
        redundant = self.identify_redundant_controls(controls, risk_control_mapping)

        # Generate recommendations
        recommendations = self.generate_recommendations(uncovered_risks, partially_covered)

        # Calculate gap score
        gap_score = self._calculate_gap_score(risks, uncovered_risks, partially_covered)

        return {
            'gap_score': gap_score,
            'uncovered_risks': uncovered_risks,
            'partially_covered_risks': partially_covered,
            'redundant_controls': redundant,
            'recommendations': recommendations,
            'summary': {
                'total_risks': len(risks),
                'uncovered_count': len(uncovered_risks),
                'partially_covered_count': len(partially_covered),
                'fully_covered_count': len(risks) - len(uncovered_risks) - len(partially_covered),
                'redundant_controls_count': len(redundant)
            }
        }

    def _find_uncovered_risks(self, risks: List[Dict],
                             risk_control_mapping: Dict) -> List[Dict]:
        """Find risks with no applicable controls."""
        uncovered = []
        for risk in risks:
            risk_id = risk['risk_id']
            if not risk_control_mapping.get(risk_id):
                uncovered.append(risk)

        # Sort by severity
        uncovered.sort(key=lambda r: self.PRIORITY_LEVELS.get(r.get('severity', 'Low'), 4))
        return uncovered

    def _find_partially_covered_risks(self, risks: List[Dict],
                                     risk_control_mapping: Dict) -> List[Dict]:
        """Find risks with incomplete control coverage."""
        partially_covered = []
        for risk in risks:
            risk_id = risk['risk_id']
            controls = risk_control_mapping.get(risk_id, [])

            if controls:
                # Check if all controls are fully implemented
                implemented = [c for c in controls if c.get('implementation_status') == 'implemented']
                if len(implemented) < len(controls) or len(implemented) < 2:
                    # Consider it partially covered if not all controls are implemented
                    # or if there are fewer than 2 implemented controls
                    risk_copy = risk.copy()
                    risk_copy['implemented_controls'] = len(implemented)
                    risk_copy['total_controls'] = len(controls)
                    partially_covered.append(risk_copy)

        partially_covered.sort(key=lambda r: self.PRIORITY_LEVELS.get(r.get('severity', 'Low'), 4))
        return partially_covered

    def identify_redundant_controls(self, controls: List[Dict],
                                   risk_control_mapping: Dict) -> List[Dict]:
        """Identify controls that don't map to any risk."""
        # Build set of used control IDs
        used_control_ids = set()
        for matched_controls in risk_control_mapping.values():
            for control in matched_controls:
                used_control_ids.add(control.get('control_id'))

        # Find unused controls
        redundant = []
        for control in controls:
            if control.get('control_id') not in used_control_ids:
                redundant.append(control)

        return redundant

    def generate_recommendations(self, uncovered_risks: List[Dict],
                                partially_covered: List[Dict]) -> List[Dict]:
        """Generate remediation recommendations."""
        recommendations = []

        # Recommendations for uncovered risks
        for risk in uncovered_risks[:10]:  # Top 10 critical gaps
            recommendations.append({
                'priority': self._get_priority_level(risk.get('severity', 'Medium')),
                'risk_id': risk['risk_id'],
                'risk_description': risk.get('description', ''),
                'severity': risk.get('severity', 'Medium'),
                'recommendation_type': 'IMPLEMENT_CONTROL',
                'recommendation': self._generate_control_recommendation(risk),
                'estimated_effort': self._estimate_effort(risk),
                'frameworks': self._suggest_frameworks(risk)
            })

        # Recommendations for partially covered risks
        for risk in partially_covered[:10]:
            recommendations.append({
                'priority': self._get_priority_level(risk.get('severity', 'Medium')),
                'risk_id': risk['risk_id'],
                'risk_description': risk.get('description', ''),
                'severity': risk.get('severity', 'Medium'),
                'recommendation_type': 'STRENGTHEN_CONTROL',
                'recommendation': f"Strengthen existing controls for {risk.get('description', '')}. "
                                f"Currently {risk.get('implemented_controls', 0)} of "
                                f"{risk.get('total_controls', 0)} controls implemented.",
                'estimated_effort': 'Medium',
                'frameworks': []
            })

        # Sort by priority
        recommendations.sort(key=lambda r: r['priority'])
        return recommendations

    def _generate_control_recommendation(self, risk: Dict) -> str:
        """Generate specific control recommendation for a risk."""
        desc = risk.get('description', '').lower()

        # Pattern-based recommendations
        if 'authentication' in desc or 'credential' in desc:
            return "Implement multi-factor authentication (MFA) and strong password policies. " \
                   "Consider NIST IA-2, CIS 4.5, ISO 27001 A.9.4.2"

        elif 'access control' in desc or 'unauthorized access' in desc:
            return "Deploy role-based access control (RBAC) and least privilege principles. " \
                   "Consider NIST AC-6, CIS 4.3, ISO 27001 A.9.2"

        elif 'encryption' in desc or 'data breach' in desc:
            return "Implement encryption for data at rest and in transit. " \
                   "Consider NIST SC-28, SC-8, ISO 27001 A.10.1"

        elif 'malware' in desc or 'virus' in desc:
            return "Deploy endpoint detection and response (EDR) and anti-malware solutions. " \
                   "Consider CIS 8.1, NIST SI-3, ISO 27001 A.12.2"

        elif 'logging' in desc or 'monitoring' in desc:
            return "Implement centralized logging and security monitoring (SIEM). " \
                   "Consider NIST AU-6, CIS 6.2, ISO 27001 A.12.4"

        elif 'vulnerability' in desc or 'patch' in desc:
            return "Establish vulnerability management and patch management programs. " \
                   "Consider CIS 3.1, 3.4, NIST SI-2, ISO 27001 A.12.6"

        else:
            return f"Implement appropriate security controls to mitigate: {risk.get('description', '')}"

    def _get_priority_level(self, severity: str) -> int:
        """Convert severity to priority number."""
        return self.PRIORITY_LEVELS.get(severity, 4)

    def _estimate_effort(self, risk: Dict) -> str:
        """Estimate implementation effort."""
        severity = risk.get('severity', 'Medium')
        if severity == 'Critical':
            return 'High'
        elif severity == 'High':
            return 'Medium'
        else:
            return 'Low'

    def _suggest_frameworks(self, risk: Dict) -> List[str]:
        """Suggest applicable frameworks."""
        desc = risk.get('description', '').lower()
        frameworks = []

        # Always suggest NIST for comprehensive coverage
        frameworks.append('NIST 800-53')

        if 'critical infrastructure' in desc or 'enterprise' in desc:
            frameworks.append('CIS Controls')

        if 'compliance' in desc or 'audit' in desc:
            frameworks.append('ISO 27001')

        return frameworks

    def _calculate_gap_score(self, risks: List[Dict],
                            uncovered: List[Dict],
                            partially_covered: List[Dict]) -> int:
        """
        Calculate overall gap score (0-100).
        Lower is better (fewer gaps).
        """
        if not risks:
            return 0

        # Weight by severity
        severity_weights = {'Critical': 3, 'High': 2, 'Medium': 1, 'Low': 0.5}

        total_risk_weight = sum(severity_weights.get(r.get('severity', 'Medium'), 1) for r in risks)
        uncovered_weight = sum(severity_weights.get(r.get('severity', 'Medium'), 1) for r in uncovered)
        partial_weight = sum(severity_weights.get(r.get('severity', 'Medium'), 1) * 0.5 for r in partially_covered)

        gap_weight = uncovered_weight + partial_weight

        if total_risk_weight == 0:
            return 0

        gap_score = int((gap_weight / total_risk_weight) * 100)
        return min(gap_score, 100)
