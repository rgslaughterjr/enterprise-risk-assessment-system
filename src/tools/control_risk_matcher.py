"""
Control-Risk Matcher

Maps security controls to identified risks and calculates coverage scores.
"""

from typing import Dict, List, Tuple
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class ControlRiskMatcher:
    """Match controls to risks and calculate coverage."""

    # Keyword mappings for control-to-risk matching
    CONTROL_KEYWORDS = {
        'access-control': ['unauthorized access', 'privilege escalation', 'account compromise'],
        'authentication': ['credential theft', 'brute force', 'password attacks'],
        'encryption': ['data breach', 'eavesdropping', 'data interception'],
        'logging': ['undetected intrusion', 'forensic', 'audit trail'],
        'patching': ['vulnerability exploitation', 'malware', 'zero-day'],
        'backup': ['data loss', 'ransomware', 'disaster recovery'],
        'firewall': ['network intrusion', 'ddos', 'port scanning'],
        'antivirus': ['malware', 'ransomware', 'trojan'],
        'mfa': ['account takeover', 'credential stuffing', 'phishing'],
        'segmentation': ['lateral movement', 'privilege escalation', 'insider threat'],
    }

    def __init__(self):
        """Initialize matcher."""
        logger.info("Initialized ControlRiskMatcher")

    def match_controls_to_risks(self, controls: List[Dict],
                                risks: List[Dict]) -> Dict:
        """
        Match controls to risks.

        Args:
            controls: List of security controls
            risks: List of identified risks

        Returns:
            Dictionary with matching results and coverage metrics
        """
        logger.info(f"Matching {len(controls)} controls to {len(risks)} risks...")

        # Build control index by framework and keywords
        control_index = self._index_controls(controls)

        # Match each risk to applicable controls
        risk_control_map = {}
        for risk in risks:
            matched_controls = self._find_controls_for_risk(risk, control_index, controls)
            risk_control_map[risk['risk_id']] = matched_controls

        # Calculate coverage metrics
        coverage = self._calculate_coverage(risks, risk_control_map, controls)

        return {
            'risk_control_mapping': risk_control_map,
            'coverage_metrics': coverage,
            'total_controls': len(controls),
            'total_risks': len(risks),
            'risks_with_controls': len([r for r in risk_control_map.values() if r]),
            'risks_without_controls': len([r for r in risk_control_map.values() if not r])
        }

    def _index_controls(self, controls: List[Dict]) -> Dict:
        """Build searchable index of controls."""
        index = {
            'by_id': {},
            'by_framework': defaultdict(list),
            'by_keyword': defaultdict(list)
        }

        for i, control in enumerate(controls):
            control_id = control.get('control_id', '')
            framework = control.get('framework', '')

            index['by_id'][control_id] = i
            index['by_framework'][framework].append(i)

            # Extract keywords from title and description
            text = (control.get('title', '') + ' ' + control.get('description', '')).lower()
            for keyword in self.CONTROL_KEYWORDS.keys():
                if keyword in text or keyword.replace('-', ' ') in text:
                    index['by_keyword'][keyword].append(i)

        return index

    def _find_controls_for_risk(self, risk: Dict, control_index: Dict,
                               controls: List[Dict]) -> List[Dict]:
        """Find controls that mitigate a specific risk."""
        matched_controls = []
        risk_desc = risk.get('description', '').lower()
        risk_cve = risk.get('cve_id', '')

        # Match by keywords
        for keyword, risk_keywords in self.CONTROL_KEYWORDS.items():
            for risk_kw in risk_keywords:
                if risk_kw in risk_desc:
                    # Found relevant keyword - add these controls
                    for ctrl_idx in control_index['by_keyword'].get(keyword, []):
                        control = controls[ctrl_idx].copy()
                        control['match_reason'] = f'Keyword: {keyword} -> {risk_kw}'
                        control['match_score'] = 0.7
                        if control not in matched_controls:
                            matched_controls.append(control)

        # Boost score for implemented controls
        for control in matched_controls:
            if control.get('implementation_status') == 'implemented':
                control['match_score'] = min(control.get('match_score', 0.7) + 0.2, 1.0)

        # Sort by match score
        matched_controls.sort(key=lambda x: x.get('match_score', 0), reverse=True)

        return matched_controls[:10]  # Top 10 matches

    def _calculate_coverage(self, risks: List[Dict],
                           risk_control_map: Dict,
                           controls: List[Dict]) -> Dict:
        """Calculate coverage metrics."""
        # Overall coverage score
        total_risks = len(risks)
        risks_with_controls = sum(1 for r in risk_control_map.values() if r)
        coverage_pct = (risks_with_controls / total_risks * 100) if total_risks > 0 else 0

        # Coverage by risk severity
        by_severity = defaultdict(lambda: {'total': 0, 'covered': 0})
        for risk in risks:
            severity = risk.get('severity', 'Medium')
            by_severity[severity]['total'] += 1
            if risk_control_map.get(risk['risk_id']):
                by_severity[severity]['covered'] += 1

        # Calculate percentages
        severity_coverage = {}
        for severity, counts in by_severity.items():
            pct = (counts['covered'] / counts['total'] * 100) if counts['total'] > 0 else 0
            severity_coverage[severity] = {
                'total_risks': counts['total'],
                'covered_risks': counts['covered'],
                'coverage_percentage': round(pct, 1)
            }

        # Control utilization (how many controls are actually used)
        used_control_ids = set()
        for matched_list in risk_control_map.values():
            for control in matched_list:
                used_control_ids.add(control.get('control_id'))

        utilization_pct = (len(used_control_ids) / len(controls) * 100) if controls else 0

        return {
            'overall_coverage_percentage': round(coverage_pct, 1),
            'by_severity': severity_coverage,
            'control_utilization_percentage': round(utilization_pct, 1),
            'total_controls_used': len(used_control_ids),
            'unused_controls': len(controls) - len(used_control_ids)
        }
