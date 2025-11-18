"""Control-to-Risk matcher for security control coverage analysis.

This module maps security controls to risks they mitigate and calculates
coverage scores to identify gaps in risk mitigation.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict
from datetime import datetime

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)


class ControlRiskMatcher:
    """Matches security controls to risks and calculates coverage scores.

    Uses multiple matching strategies:
    1. Explicit mappings (control metadata)
    2. Framework category matching
    3. Text similarity matching (TF-IDF + cosine similarity)
    4. Keyword-based heuristics
    """

    def __init__(
        self,
        use_llm: bool = False,
        similarity_threshold: float = 0.3,
    ):
        """Initialize control-risk matcher.

        Args:
            use_llm: If True, use LLM for matching (mocked by default for testing)
            similarity_threshold: Minimum similarity score for text-based matching
        """
        self.use_llm = use_llm
        self.similarity_threshold = similarity_threshold

        # TF-IDF vectorizer for text similarity
        self.vectorizer = TfidfVectorizer(
            max_features=300,
            stop_words="english",
            ngram_range=(1, 2),
            min_df=1,
        )

        # Control category to risk category mappings
        self.category_mappings = {
            "Access Control": ["Unauthorized Access", "Privilege Escalation", "Authentication Bypass"],
            "Audit and Accountability": ["Audit Trail Gaps", "Non-repudiation", "Compliance Violations"],
            "Configuration Management": ["Misconfiguration", "Configuration Drift", "Unauthorized Changes"],
            "Contingency Planning": ["Business Continuity", "Disaster Recovery", "Service Disruption"],
            "Identification and Authentication": ["Identity Theft", "Credential Compromise", "Authentication Bypass"],
            "Incident Response": ["Incident Detection Delays", "Inadequate Response", "Breach Impact"],
            "Maintenance": ["System Downtime", "Maintenance Windows", "Unauthorized Maintenance"],
            "Media Protection": ["Data Leakage", "Media Loss", "Improper Disposal"],
            "Vulnerability Management": ["Unpatched Vulnerabilities", "Zero-day Exploits", "CVE Exposure"],
            "Malware Defenses": ["Malware Infection", "Ransomware", "Trojan Deployment"],
            "Data Protection": ["Data Breach", "Data Loss", "Data Leakage", "Privacy Violations"],
            "Network Security": ["Network Intrusion", "DDoS", "Man-in-the-Middle", "Network Segmentation"],
            "Physical Controls": ["Physical Breach", "Unauthorized Physical Access", "Facility Security"],
            "Organizational Controls": ["Policy Violations", "Governance Gaps", "Compliance Failures"],
            "System and Communications Protection": ["Communication Interception", "Data in Transit", "Encryption Weaknesses"],
        }

        logger.info(f"ControlRiskMatcher initialized (use_llm={use_llm}, threshold={similarity_threshold})")

    def match_controls_to_risks(
        self,
        controls: List[Dict[str, Any]],
        risks: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Match controls to risks they mitigate.

        Args:
            controls: List of control dictionaries
            risks: List of risk dictionaries

        Returns:
            List of control-risk mapping dictionaries

        Example:
            >>> matcher = ControlRiskMatcher()
            >>> mappings = matcher.match_controls_to_risks(controls, risks)
        """
        logger.info(f"Matching {len(controls)} controls to {len(risks)} risks")

        if not controls or not risks:
            logger.warning("Empty controls or risks list provided")
            return []

        mappings = []

        for control in controls:
            control_id = control.get("id", "UNKNOWN")

            # Find matching risks using multiple strategies
            matched_risks = self._find_matching_risks(control, risks)

            for risk, score, method in matched_risks:
                mapping = {
                    "control_id": control_id,
                    "control_name": control.get("title") or control.get("name", ""),
                    "control_framework": control.get("framework", ""),
                    "control_category": control.get("category", ""),
                    "risk_id": risk.get("id", "UNKNOWN"),
                    "risk_name": risk.get("title") or risk.get("name", ""),
                    "risk_level": risk.get("risk_level") or risk.get("severity", "Unknown"),
                    "match_score": score,
                    "match_method": method,
                    "mapped_at": datetime.utcnow().isoformat(),
                }
                mappings.append(mapping)

        logger.info(f"Created {len(mappings)} control-risk mappings")
        return mappings

    def _find_matching_risks(
        self,
        control: Dict[str, Any],
        risks: List[Dict[str, Any]],
    ) -> List[Tuple[Dict[str, Any], float, str]]:
        """Find risks that match a control.

        Args:
            control: Control dictionary
            risks: List of risk dictionaries

        Returns:
            List of (risk, score, method) tuples
        """
        matched_risks = []

        # Strategy 1: Explicit mappings in control metadata
        explicit_matches = self._match_by_explicit_mapping(control, risks)
        matched_risks.extend(explicit_matches)

        # Strategy 2: Category-based matching
        category_matches = self._match_by_category(control, risks)
        matched_risks.extend(category_matches)

        # Strategy 3: Text similarity matching
        similarity_matches = self._match_by_text_similarity(control, risks)
        matched_risks.extend(similarity_matches)

        # Strategy 4: Keyword heuristics
        keyword_matches = self._match_by_keywords(control, risks)
        matched_risks.extend(keyword_matches)

        # Deduplicate and keep highest scores
        risk_scores = {}
        risk_methods = {}

        for risk, score, method in matched_risks:
            risk_id = risk.get("id", "UNKNOWN")
            if risk_id not in risk_scores or score > risk_scores[risk_id]:
                risk_scores[risk_id] = score
                risk_methods[risk_id] = method

        # Build final list
        final_matches = []
        risk_by_id = {r.get("id", "UNKNOWN"): r for r in risks}

        for risk_id, score in risk_scores.items():
            if risk_id in risk_by_id:
                final_matches.append((risk_by_id[risk_id], score, risk_methods[risk_id]))

        # Sort by score descending
        final_matches.sort(key=lambda x: x[1], reverse=True)

        return final_matches

    def _match_by_explicit_mapping(
        self,
        control: Dict[str, Any],
        risks: List[Dict[str, Any]],
    ) -> List[Tuple[Dict[str, Any], float, str]]:
        """Match using explicit risk IDs in control metadata.

        Args:
            control: Control dictionary
            risks: List of risk dictionaries

        Returns:
            List of (risk, score, method) tuples
        """
        matches = []

        # Check if control has explicit risk mappings
        mapped_risks = control.get("mapped_risks", []) or control.get("risk_ids", [])

        if not mapped_risks:
            return matches

        risk_by_id = {r.get("id"): r for r in risks if r.get("id")}

        for risk_id in mapped_risks:
            if risk_id in risk_by_id:
                matches.append((risk_by_id[risk_id], 1.0, "explicit_mapping"))

        return matches

    def _match_by_category(
        self,
        control: Dict[str, Any],
        risks: List[Dict[str, Any]],
    ) -> List[Tuple[Dict[str, Any], float, str]]:
        """Match using control category to risk category mappings.

        Args:
            control: Control dictionary
            risks: List of risk dictionaries

        Returns:
            List of (risk, score, method) tuples
        """
        matches = []

        control_category = control.get("category", "")
        if not control_category:
            return matches

        # Get expected risk categories for this control category
        expected_risk_categories = self.category_mappings.get(control_category, [])

        if not expected_risk_categories:
            return matches

        for risk in risks:
            risk_name = risk.get("title") or risk.get("name", "")
            risk_description = risk.get("description", "")
            risk_category = risk.get("category", "")

            # Check if risk matches expected categories
            risk_text = f"{risk_name} {risk_description} {risk_category}".lower()

            for expected_category in expected_risk_categories:
                if expected_category.lower() in risk_text:
                    # Score based on match strength
                    score = 0.8 if expected_category.lower() in risk_name.lower() else 0.6
                    matches.append((risk, score, "category_mapping"))
                    break

        return matches

    def _match_by_text_similarity(
        self,
        control: Dict[str, Any],
        risks: List[Dict[str, Any]],
    ) -> List[Tuple[Dict[str, Any], float, str]]:
        """Match using TF-IDF text similarity.

        Args:
            control: Control dictionary
            risks: List of risk dictionaries

        Returns:
            List of (risk, score, method) tuples
        """
        matches = []

        if not risks:
            return matches

        # Prepare control text
        control_text = self._prepare_control_text(control)

        # Prepare risk texts
        risk_texts = [self._prepare_risk_text(r) for r in risks]

        # Add control text as first item
        all_texts = [control_text] + risk_texts

        try:
            # Vectorize
            tfidf_matrix = self.vectorizer.fit_transform(all_texts)

            # Compute similarity between control and all risks
            similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])[0]

            # Build matches above threshold
            for i, score in enumerate(similarities):
                if score >= self.similarity_threshold:
                    matches.append((risks[i], float(score), "text_similarity"))

        except Exception as e:
            logger.error(f"Error computing text similarity: {str(e)}")

        return matches

    def _match_by_keywords(
        self,
        control: Dict[str, Any],
        risks: List[Dict[str, Any]],
    ) -> List[Tuple[Dict[str, Any], float, str]]:
        """Match using keyword heuristics.

        Args:
            control: Control dictionary
            risks: List of risk dictionaries

        Returns:
            List of (risk, score, method) tuples
        """
        matches = []

        control_text = self._prepare_control_text(control).lower()

        # Extract keywords from control
        keywords = self._extract_keywords(control_text)

        if not keywords:
            return matches

        for risk in risks:
            risk_text = self._prepare_risk_text(risk).lower()

            # Count keyword matches
            matched_keywords = sum(1 for kw in keywords if kw in risk_text)

            if matched_keywords > 0:
                # Score based on proportion of keywords matched
                score = min(matched_keywords / len(keywords), 0.7)  # Cap at 0.7
                matches.append((risk, score, "keyword_heuristic"))

        return matches

    def _prepare_control_text(self, control: Dict[str, Any]) -> str:
        """Prepare control text for matching.

        Args:
            control: Control dictionary

        Returns:
            Combined text
        """
        parts = []

        parts.append(control.get("title", ""))
        parts.append(control.get("name", ""))
        parts.append(control.get("description", ""))
        parts.append(control.get("category", ""))

        return " ".join(p for p in parts if p)

    def _prepare_risk_text(self, risk: Dict[str, Any]) -> str:
        """Prepare risk text for matching.

        Args:
            risk: Risk dictionary

        Returns:
            Combined text
        """
        parts = []

        parts.append(risk.get("title", ""))
        parts.append(risk.get("name", ""))
        parts.append(risk.get("description", ""))
        parts.append(risk.get("category", ""))
        parts.append(risk.get("threat", ""))

        return " ".join(p for p in parts if p)

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract important keywords from text.

        Args:
            text: Input text

        Returns:
            List of keywords
        """
        # Simple keyword extraction (could be enhanced with NLP)
        keywords = []

        # Security-related keywords
        security_terms = [
            "access", "authentication", "authorization", "encryption", "malware",
            "vulnerability", "patch", "firewall", "intrusion", "breach", "attack",
            "credential", "password", "privilege", "audit", "logging", "monitoring",
            "backup", "recovery", "incident", "response", "configuration", "compliance",
        ]

        for term in security_terms:
            if term in text:
                keywords.append(term)

        return keywords

    def calculate_coverage_score(
        self,
        risk: Dict[str, Any],
        controls: List[Dict[str, Any]],
    ) -> float:
        """Calculate how well a risk is covered by controls.

        Args:
            risk: Risk dictionary
            controls: List of control dictionaries that mitigate this risk

        Returns:
            Coverage score (0.0 to 1.0)

        Example:
            >>> matcher = ControlRiskMatcher()
            >>> score = matcher.calculate_coverage_score(risk, mitigating_controls)
        """
        if not controls:
            return 0.0

        # Calculate coverage based on:
        # 1. Number of controls
        # 2. Control effectiveness scores
        # 3. Implementation status

        total_score = 0.0
        max_score = 1.0

        # Base score from control count (diminishing returns)
        control_count_score = min(len(controls) * 0.2, 0.6)
        total_score += control_count_score

        # Effectiveness scores
        effectiveness_scores = []
        for control in controls:
            effectiveness = control.get("effectiveness_score")
            if effectiveness is not None:
                try:
                    score = float(effectiveness)
                    # Normalize to 0-1 if needed
                    if score > 1.0:
                        score = score / 100.0
                    effectiveness_scores.append(score)
                except (ValueError, TypeError):
                    continue

        if effectiveness_scores:
            avg_effectiveness = sum(effectiveness_scores) / len(effectiveness_scores)
            total_score += avg_effectiveness * 0.3

        # Implementation status bonus
        implemented_count = sum(
            1 for c in controls
            if c.get("implementation_status") == "Implemented"
        )

        if implemented_count > 0:
            implementation_score = min(implemented_count / len(controls), 1.0) * 0.1
            total_score += implementation_score

        # Normalize to 0-1 range
        coverage = min(total_score, max_score)

        logger.debug(f"Coverage score for risk {risk.get('id')}: {coverage:.2f}")
        return coverage

    def identify_control_gaps(
        self,
        risks: List[Dict[str, Any]],
        controls: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify risks with insufficient control coverage.

        Args:
            risks: List of risk dictionaries
            controls: List of control dictionaries

        Returns:
            List of gap dictionaries with risk and coverage information

        Example:
            >>> matcher = ControlRiskMatcher()
            >>> gaps = matcher.identify_control_gaps(all_risks, all_controls)
        """
        logger.info(f"Identifying control gaps for {len(risks)} risks")

        # Match controls to risks
        mappings = self.match_controls_to_risks(controls, risks)

        # Group mappings by risk
        risk_controls = defaultdict(list)
        for mapping in mappings:
            risk_id = mapping["risk_id"]
            # Find the control
            control = next((c for c in controls if c.get("id") == mapping["control_id"]), None)
            if control:
                risk_controls[risk_id].append(control)

        # Calculate coverage for each risk
        gaps = []

        for risk in risks:
            risk_id = risk.get("id", "UNKNOWN")
            mitigating_controls = risk_controls.get(risk_id, [])

            coverage_score = self.calculate_coverage_score(risk, mitigating_controls)

            # Consider it a gap if coverage < 0.5
            if coverage_score < 0.5:
                gap = {
                    "risk_id": risk_id,
                    "risk_name": risk.get("title") or risk.get("name", ""),
                    "risk_level": risk.get("risk_level") or risk.get("severity", "Unknown"),
                    "coverage_score": coverage_score,
                    "control_count": len(mitigating_controls),
                    "gap_severity": self._calculate_gap_severity(risk, coverage_score),
                    "mitigating_controls": [c.get("id") for c in mitigating_controls],
                    "identified_at": datetime.utcnow().isoformat(),
                }
                gaps.append(gap)

        # Sort by gap severity
        gaps.sort(key=lambda x: (
            self._severity_priority(x["gap_severity"]),
            -x["coverage_score"]
        ))

        logger.info(f"Identified {len(gaps)} control gaps")
        return gaps

    def _calculate_gap_severity(self, risk: Dict[str, Any], coverage_score: float) -> str:
        """Calculate gap severity based on risk level and coverage.

        Args:
            risk: Risk dictionary
            coverage_score: Coverage score (0-1)

        Returns:
            Severity level: Critical, High, Medium, Low
        """
        risk_level = (risk.get("risk_level") or risk.get("severity", "Medium")).upper()

        # High risk + low coverage = Critical gap
        if risk_level in ["CRITICAL", "HIGH"] and coverage_score < 0.3:
            return "Critical"
        elif risk_level in ["CRITICAL", "HIGH"] and coverage_score < 0.5:
            return "High"
        elif risk_level == "MEDIUM" and coverage_score < 0.3:
            return "High"
        elif risk_level == "MEDIUM" and coverage_score < 0.5:
            return "Medium"
        else:
            return "Low"

    def _severity_priority(self, severity: str) -> int:
        """Get priority value for severity (lower = higher priority).

        Args:
            severity: Severity level

        Returns:
            Priority value
        """
        priorities = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
        }
        return priorities.get(severity, 4)
