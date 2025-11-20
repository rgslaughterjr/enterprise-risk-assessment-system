"""NIST Cybersecurity Framework (CSF) 2.0 Compliance Checker.

This module implements compliance checking against NIST CSF 2.0 framework.
The CSF provides a policy framework of computer security guidance.

Reference: https://www.nist.gov/cyberframework
"""

import os
import sys
from typing import List, Dict
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.models.schemas import NISTCSFCategory, NISTCSFAssessment


class NISTCSFChecker:
    """NIST Cybersecurity Framework 2.0 compliance checker."""
    
    # NIST CSF 2.0 Categories by Function
    IDENTIFY_CATEGORIES = {
        "ID.AM": "Asset Management",
        "ID.BE": "Business Environment",
        "ID.GV": "Governance",
        "ID.RA": "Risk Assessment",
        "ID.RM": "Risk Management Strategy",
        "ID.SC": "Supply Chain Risk Management",
    }
    
    PROTECT_CATEGORIES = {
        "PR.AA": "Identity Management, Authentication and Access Control",
        "PR.AT": "Awareness and Training",
        "PR.DS": "Data Security",
        "PR.IP": "Information Protection Processes and Procedures",
        "PR.MA": "Maintenance",
        "PR.PT": "Protective Technology",
    }
    
    DETECT_CATEGORIES = {
        "DE.AE": "Anomalies and Events",
        "DE.CM": "Security Continuous Monitoring",
        "DE.DP": "Detection Processes",
    }
    
    RESPOND_CATEGORIES = {
        "RS.AN": "Analysis",
        "RS.CO": "Communications",
        "RS.MA": "Mitigation",
        "RS.RP": "Response Planning",
    }
    
    RECOVER_CATEGORIES = {
        "RC.CO": "Communications",
        "RC.IM": "Improvements",
        "RC.RP": "Recovery Planning",
    }
    
    GOVERN_CATEGORIES = {
        "GV.OC": "Organizational Context",
        "GV.RM": "Risk Management Strategy",
        "GV.RR": "Roles, Responsibilities, and Authorities",
        "GV.PO": "Policy",
        "GV.OV": "Oversight",
        "GV.SC": "Cybersecurity Supply Chain Risk Management",
    }
    
    def __init__(self, agent_name: str = "system"):
        """Initialize NIST CSF checker.
        
        Args:
            agent_name: Name of the agent being assessed
        """
        self.agent_name = agent_name
    
    def assess_identify_function(self) -> NISTCSFAssessment:
        """Assess IDENTIFY function compliance."""
        categories = []
        
        for category_id, category_name in self.IDENTIFY_CATEGORIES.items():
            tier, implemented, total = self._assess_category(category_id, "IDENTIFY")
            
            category = NISTCSFCategory(
                category_id=category_id,
                category_name=category_name,
                function="IDENTIFY",
                implementation_tier=tier,
                controls_implemented=implemented,
                controls_total=total,
                maturity_level=self._get_maturity_level(tier)
            )
            categories.append(category)
        
        return self._create_function_assessment("IDENTIFY", categories)
    
    def assess_protect_function(self) -> NISTCSFAssessment:
        """Assess PROTECT function compliance."""
        categories = []
        
        for category_id, category_name in self.PROTECT_CATEGORIES.items():
            tier, implemented, total = self._assess_category(category_id, "PROTECT")
            
            category = NISTCSFCategory(
                category_id=category_id,
                category_name=category_name,
                function="PROTECT",
                implementation_tier=tier,
                controls_implemented=implemented,
                controls_total=total,
                maturity_level=self._get_maturity_level(tier)
            )
            categories.append(category)
        
        return self._create_function_assessment("PROTECT", categories)
    
    def assess_detect_function(self) -> NISTCSFAssessment:
        """Assess DETECT function compliance."""
        categories = []
        
        for category_id, category_name in self.DETECT_CATEGORIES.items():
            tier, implemented, total = self._assess_category(category_id, "DETECT")
            
            category = NISTCSFCategory(
                category_id=category_id,
                category_name=category_name,
                function="DETECT",
                implementation_tier=tier,
                controls_implemented=implemented,
                controls_total=total,
                maturity_level=self._get_maturity_level(tier)
            )
            categories.append(category)
        
        return self._create_function_assessment("DETECT", categories)
    
    def assess_respond_function(self) -> NISTCSFAssessment:
        """Assess RESPOND function compliance."""
        categories = []
        
        for category_id, category_name in self.RESPOND_CATEGORIES.items():
            tier, implemented, total = self._assess_category(category_id, "RESPOND")
            
            category = NISTCSFCategory(
                category_id=category_id,
                category_name=category_name,
                function="RESPOND",
                implementation_tier=tier,
                controls_implemented=implemented,
                controls_total=total,
                maturity_level=self._get_maturity_level(tier)
            )
            categories.append(category)
        
        return self._create_function_assessment("RESPOND", categories)
    
    def assess_recover_function(self) -> NISTCSFAssessment:
        """Assess RECOVER function compliance."""
        categories = []
        
        for category_id, category_name in self.RECOVER_CATEGORIES.items():
            tier, implemented, total = self._assess_category(category_id, "RECOVER")
            
            category = NISTCSFCategory(
                category_id=category_id,
                category_name=category_name,
                function="RECOVER",
                implementation_tier=tier,
                controls_implemented=implemented,
                controls_total=total,
                maturity_level=self._get_maturity_level(tier)
            )
            categories.append(category)
        
        return self._create_function_assessment("RECOVER", categories)
    
    def assess_govern_function(self) -> NISTCSFAssessment:
        """Assess GOVERN function compliance."""
        categories = []
        
        for category_id, category_name in self.GOVERN_CATEGORIES.items():
            tier, implemented, total = self._assess_category(category_id, "GOVERN")
            
            category = NISTCSFCategory(
                category_id=category_id,
                category_name=category_name,
                function="GOVERN",
                implementation_tier=tier,
                controls_implemented=implemented,
                controls_total=total,
                maturity_level=self._get_maturity_level(tier)
            )
            categories.append(category)
        
        return self._create_function_assessment("GOVERN", categories)
    
    def assess_all_functions(self) -> List[NISTCSFAssessment]:
        """Assess all NIST CSF 2.0 functions."""
        return [
            self.assess_identify_function(),
            self.assess_protect_function(),
            self.assess_detect_function(),
            self.assess_respond_function(),
            self.assess_recover_function(),
            self.assess_govern_function()
        ]
    
    # Private helper methods
    
    def _assess_category(self, category_id: str, function: str) -> tuple:
        """Assess a specific category.
        
        Returns:
            Tuple of (implementation_tier, controls_implemented, controls_total)
        """
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        
        # Simplified assessment logic
        # In production, this would involve detailed control-by-control assessment
        
        if category_id.startswith("ID."):
            # IDENTIFY categories
            if category_id == "ID.AM":
                # Asset Management
                has_docs = os.path.exists(os.path.join(project_root, "README.md"))
                return (2 if has_docs else 1, 3 if has_docs else 1, 5)
            elif category_id == "ID.GV":
                # Governance
                has_governance = os.path.exists(os.path.join(project_root, "docs"))
                return (2 if has_governance else 1, 4 if has_governance else 2, 6)
            elif category_id == "ID.RA":
                # Risk Assessment
                return (3, 5, 6)  # System has risk assessment capabilities
            else:
                return (2, 3, 5)
        
        elif category_id.startswith("PR."):
            # PROTECT categories
            if category_id == "PR.AA":
                # Access Control
                has_env = os.path.exists(os.path.join(project_root, ".env"))
                return (2 if has_env else 1, 3 if has_env else 1, 5)
            elif category_id == "PR.DS":
                # Data Security
                has_env = os.path.exists(os.path.join(project_root, ".env"))
                return (2 if has_env else 1, 4 if has_env else 2, 6)
            else:
                return (2, 3, 5)
        
        elif category_id.startswith("DE."):
            # DETECT categories
            has_monitoring = True  # System has monitoring agents
            return (3 if has_monitoring else 2, 4 if has_monitoring else 2, 5)
        
        elif category_id.startswith("RS."):
            # RESPOND categories
            has_incident_response = True  # System has incident response capabilities
            return (2 if has_incident_response else 1, 3 if has_incident_response else 1, 5)
        
        elif category_id.startswith("RC."):
            # RECOVER categories
            return (2, 2, 4)  # Basic recovery capabilities
        
        elif category_id.startswith("GV."):
            # GOVERN categories
            has_governance = os.path.exists(os.path.join(project_root, "README.md"))
            return (2 if has_governance else 1, 4 if has_governance else 2, 6)
        
        return (1, 1, 5)  # Default: minimal implementation
    
    def _get_maturity_level(self, tier: int) -> str:
        """Get maturity level from implementation tier."""
        maturity_map = {
            1: "initial",
            2: "managed",
            3: "defined",
            4: "quantitatively_managed"
        }
        return maturity_map.get(tier, "initial")
    
    def _create_function_assessment(self, function: str, categories: List[NISTCSFCategory]) -> NISTCSFAssessment:
        """Create assessment for a function."""
        total_implemented = sum(c.controls_implemented for c in categories)
        total_controls = sum(c.controls_total for c in categories)
        compliance_score = (total_implemented / total_controls * 100) if total_controls > 0 else 0
        
        avg_tier = sum(c.implementation_tier for c in categories) / len(categories) if categories else 1
        implementation_tier = round(avg_tier)
        
        gaps = self._identify_function_gaps(function, categories)
        recommendations = self._get_function_recommendations(function, categories)
        
        return NISTCSFAssessment(
            function=function,
            categories=categories,
            compliance_score=compliance_score,
            implementation_tier=implementation_tier,
            gaps=gaps,
            recommendations=recommendations
        )
    
    def _identify_function_gaps(self, function: str, categories: List[NISTCSFCategory]) -> List[str]:
        """Identify gaps in function implementation."""
        gaps = []
        
        low_tier_categories = [c for c in categories if c.implementation_tier < 2]
        if low_tier_categories:
            gaps.append(f"{len(low_tier_categories)} categories at Tier 1 (Partial) in {function}")
        
        for category in categories:
            if category.controls_implemented < category.controls_total:
                missing = category.controls_total - category.controls_implemented
                gaps.append(f"{category.category_id}: {missing} controls not implemented")
        
        return gaps
    
    def _get_function_recommendations(self, function: str, categories: List[NISTCSFCategory]) -> List[str]:
        """Get recommendations for function improvement."""
        recommendations = []
        
        low_tier = [c for c in categories if c.implementation_tier < 3]
        if low_tier:
            recommendations.append(f"Advance {function} categories to Tier 3 (Repeatable)")
        
        recommendations.append(f"Implement missing controls in {function} function")
        recommendations.append(f"Document {function} processes and procedures")
        recommendations.append(f"Establish metrics for {function} effectiveness")
        
        return recommendations
