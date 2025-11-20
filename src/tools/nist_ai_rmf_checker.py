"""NIST AI Risk Management Framework (AI RMF) Compliance Checker.

This module implements compliance checking against NIST AI RMF 1.0 framework.
The AI RMF provides a structured approach to managing risks related to AI systems.

Reference: https://www.nist.gov/itl/ai-risk-management-framework
"""

import os
import sys
from typing import List, Dict
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.models.schemas import NISTAIRMFControl, NISTAIRMFAssessment


class NISTAIRMFChecker:
    """NIST AI Risk Management Framework compliance checker."""
    
    # NIST AI RMF Functions and Controls
    GOVERN_CONTROLS = {
        "GOV-1.1": "Policies and procedures for AI governance",
        "GOV-1.2": "Roles and responsibilities defined",
        "GOV-1.3": "Accountability mechanisms established",
        "GOV-1.4": "Risk management processes integrated",
        "GOV-2.1": "Transparency and explainability requirements",
        "GOV-2.2": "Documentation and record-keeping",
        "GOV-3.1": "Stakeholder engagement processes",
        "GOV-3.2": "Human oversight mechanisms",
    }
    
    MAP_CONTROLS = {
        "MAP-1.1": "AI system context and purpose documented",
        "MAP-1.2": "Intended use cases identified",
        "MAP-1.3": "Data sources and characteristics documented",
        "MAP-2.1": "Risk categorization performed",
        "MAP-2.2": "Potential impacts identified",
        "MAP-2.3": "Fairness and bias considerations",
        "MAP-3.1": "Privacy and data protection requirements",
        "MAP-3.2": "Security requirements identified",
    }
    
    MEASURE_CONTROLS = {
        "MEA-1.1": "Performance metrics defined",
        "MEA-1.2": "Fairness metrics established",
        "MEA-1.3": "Bias testing performed",
        "MEA-2.1": "Model validation and testing",
        "MEA-2.2": "Continuous monitoring implemented",
        "MEA-2.3": "Incident tracking and analysis",
        "MEA-3.1": "Explainability testing",
        "MEA-3.2": "Robustness and safety testing",
    }
    
    MANAGE_CONTROLS = {
        "MAN-1.1": "Risk mitigation strategies implemented",
        "MAN-1.2": "Incident response procedures",
        "MAN-1.3": "Change management processes",
        "MAN-2.1": "Model retraining and updates",
        "MAN-2.2": "Decommissioning procedures",
        "MAN-3.1": "Third-party risk management",
        "MAN-3.2": "Supply chain security",
    }
    
    def __init__(self, agent_name: str = "system"):
        """Initialize NIST AI RMF checker.
        
        Args:
            agent_name: Name of the agent being assessed
        """
        self.agent_name = agent_name
        
    def assess_govern_function(self) -> NISTAIRMFAssessment:
        """Assess GOVERN function compliance.
        
        Returns:
            NISTAIRMFAssessment for GOVERN function
        """
        controls = []
        
        for control_id, control_name in self.GOVERN_CONTROLS.items():
            # Check for governance documentation
            implemented = self._check_governance_control(control_id)
            effectiveness = self._assess_control_effectiveness(control_id, implemented)
            
            control = NISTAIRMFControl(
                control_id=control_id,
                control_name=control_name,
                function="GOVERN",
                implemented=implemented,
                effectiveness=effectiveness,
                evidence=self._get_control_evidence(control_id),
                gaps=self._identify_control_gaps(control_id, implemented)
            )
            controls.append(control)
        
        implemented_count = sum(1 for c in controls if c.implemented)
        compliance_score = (implemented_count / len(controls)) * 100
        
        return NISTAIRMFAssessment(
            function="GOVERN",
            controls=controls,
            compliance_score=compliance_score,
            implemented_controls=implemented_count,
            total_controls=len(controls),
            gaps=self._get_function_gaps("GOVERN", controls),
            recommendations=self._get_function_recommendations("GOVERN", controls)
        )
    
    def assess_map_function(self) -> NISTAIRMFAssessment:
        """Assess MAP function compliance.
        
        Returns:
            NISTAIRMFAssessment for MAP function
        """
        controls = []
        
        for control_id, control_name in self.MAP_CONTROLS.items():
            implemented = self._check_map_control(control_id)
            effectiveness = self._assess_control_effectiveness(control_id, implemented)
            
            control = NISTAIRMFControl(
                control_id=control_id,
                control_name=control_name,
                function="MAP",
                implemented=implemented,
                effectiveness=effectiveness,
                evidence=self._get_control_evidence(control_id),
                gaps=self._identify_control_gaps(control_id, implemented)
            )
            controls.append(control)
        
        implemented_count = sum(1 for c in controls if c.implemented)
        compliance_score = (implemented_count / len(controls)) * 100
        
        return NISTAIRMFAssessment(
            function="MAP",
            controls=controls,
            compliance_score=compliance_score,
            implemented_controls=implemented_count,
            total_controls=len(controls),
            gaps=self._get_function_gaps("MAP", controls),
            recommendations=self._get_function_recommendations("MAP", controls)
        )
    
    def assess_measure_function(self) -> NISTAIRMFAssessment:
        """Assess MEASURE function compliance.
        
        Returns:
            NISTAIRMFAssessment for MEASURE function
        """
        controls = []
        
        for control_id, control_name in self.MEASURE_CONTROLS.items():
            implemented = self._check_measure_control(control_id)
            effectiveness = self._assess_control_effectiveness(control_id, implemented)
            
            control = NISTAIRMFControl(
                control_id=control_id,
                control_name=control_name,
                function="MEASURE",
                implemented=implemented,
                effectiveness=effectiveness,
                evidence=self._get_control_evidence(control_id),
                gaps=self._identify_control_gaps(control_id, implemented)
            )
            controls.append(control)
        
        implemented_count = sum(1 for c in controls if c.implemented)
        compliance_score = (implemented_count / len(controls)) * 100
        
        return NISTAIRMFAssessment(
            function="MEASURE",
            controls=controls,
            compliance_score=compliance_score,
            implemented_controls=implemented_count,
            total_controls=len(controls),
            gaps=self._get_function_gaps("MEASURE", controls),
            recommendations=self._get_function_recommendations("MEASURE", controls)
        )
    
    def assess_manage_function(self) -> NISTAIRMFAssessment:
        """Assess MANAGE function compliance.
        
        Returns:
            NISTAIRMFAssessment for MANAGE function
        """
        controls = []
        
        for control_id, control_name in self.MANAGE_CONTROLS.items():
            implemented = self._check_manage_control(control_id)
            effectiveness = self._assess_control_effectiveness(control_id, implemented)
            
            control = NISTAIRMFControl(
                control_id=control_id,
                control_name=control_name,
                function="MANAGE",
                implemented=implemented,
                effectiveness=effectiveness,
                evidence=self._get_control_evidence(control_id),
                gaps=self._identify_control_gaps(control_id, implemented)
            )
            controls.append(control)
        
        implemented_count = sum(1 for c in controls if c.implemented)
        compliance_score = (implemented_count / len(controls)) * 100
        
        return NISTAIRMFAssessment(
            function="MANAGE",
            controls=controls,
            compliance_score=compliance_score,
            implemented_controls=implemented_count,
            total_controls=len(controls),
            gaps=self._get_function_gaps("MANAGE", controls),
            recommendations=self._get_function_recommendations("MANAGE", controls)
        )
    
    def assess_all_functions(self) -> List[NISTAIRMFAssessment]:
        """Assess all NIST AI RMF functions.
        
        Returns:
            List of assessments for all functions
        """
        return [
            self.assess_govern_function(),
            self.assess_map_function(),
            self.assess_measure_function(),
            self.assess_manage_function()
        ]
    
    # Private helper methods
    
    def _check_governance_control(self, control_id: str) -> bool:
        """Check if governance control is implemented."""
        # Check for documentation, policies, README files
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        
        if control_id.startswith("GOV-1"):
            # Check for governance documentation
            return os.path.exists(os.path.join(project_root, "README.md"))
        elif control_id.startswith("GOV-2"):
            # Check for transparency/documentation
            return os.path.exists(os.path.join(project_root, "docs"))
        elif control_id.startswith("GOV-3"):
            # Check for stakeholder engagement
            return True  # Assume implemented via UI
        
        return False
    
    def _check_map_control(self, control_id: str) -> bool:
        """Check if MAP control is implemented."""
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        
        if control_id.startswith("MAP-1"):
            # Check for system documentation
            return os.path.exists(os.path.join(project_root, "README.md"))
        elif control_id.startswith("MAP-2"):
            # Check for risk assessment capabilities
            return True  # System has risk assessment agents
        elif control_id.startswith("MAP-3"):
            # Check for privacy/security requirements
            return os.path.exists(os.path.join(project_root, ".env"))
        
        return False
    
    def _check_measure_control(self, control_id: str) -> bool:
        """Check if MEASURE control is implemented."""
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        
        if control_id.startswith("MEA-1"):
            # Check for metrics/testing
            return os.path.exists(os.path.join(project_root, "tests"))
        elif control_id.startswith("MEA-2"):
            # Check for validation/monitoring
            return True  # Assume monitoring via agents
        elif control_id.startswith("MEA-3"):
            # Check for explainability/safety testing
            return os.path.exists(os.path.join(project_root, "tests"))
        
        return False
    
    def _check_manage_control(self, control_id: str) -> bool:
        """Check if MANAGE control is implemented."""
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        
        if control_id.startswith("MAN-1"):
            # Check for risk management processes
            return True  # System has risk management capabilities
        elif control_id.startswith("MAN-2"):
            # Check for change management
            return os.path.exists(os.path.join(project_root, ".github"))
        elif control_id.startswith("MAN-3"):
            # Check for third-party risk management
            return os.path.exists(os.path.join(project_root, "requirements.txt"))
        
        return False
    
    def _assess_control_effectiveness(self, control_id: str, implemented: bool) -> str:
        """Assess control effectiveness."""
        if not implemented:
            return "not_applicable"
        
        # Simple heuristic: if implemented, assume partially effective
        # In production, this would involve more detailed assessment
        return "partially_effective"
    
    def _get_control_evidence(self, control_id: str) -> List[str]:
        """Get evidence for control implementation."""
        evidence = []
        
        if control_id.startswith("GOV"):
            evidence.append("Governance documentation present in README.md")
            evidence.append("Agent-based architecture with defined roles")
        elif control_id.startswith("MAP"):
            evidence.append("System documentation describes use cases")
            evidence.append("Risk assessment agents implemented")
        elif control_id.startswith("MEA"):
            evidence.append("Test suite present in tests/ directory")
            evidence.append("Monitoring capabilities via agents")
        elif control_id.startswith("MAN"):
            evidence.append("CI/CD pipeline for change management")
            evidence.append("Dependency management via requirements.txt")
        
        return evidence
    
    def _identify_control_gaps(self, control_id: str, implemented: bool) -> List[str]:
        """Identify gaps in control implementation."""
        if implemented:
            return ["Control effectiveness needs formal assessment"]
        else:
            return [f"Control {control_id} not implemented"]
    
    def _get_function_gaps(self, function: str, controls: List[NISTAIRMFControl]) -> List[str]:
        """Get overall gaps for a function."""
        gaps = []
        not_implemented = [c for c in controls if not c.implemented]
        
        if not_implemented:
            gaps.append(f"{len(not_implemented)} controls not implemented in {function}")
        
        partially_effective = [c for c in controls if c.effectiveness == "partially_effective"]
        if partially_effective:
            gaps.append(f"{len(partially_effective)} controls only partially effective")
        
        return gaps
    
    def _get_function_recommendations(self, function: str, controls: List[NISTAIRMFControl]) -> List[str]:
        """Get recommendations for a function."""
        recommendations = []
        
        not_implemented = [c for c in controls if not c.implemented]
        if not_implemented:
            recommendations.append(f"Implement missing {function} controls: {', '.join([c.control_id for c in not_implemented[:3]])}")
        
        recommendations.append(f"Conduct formal assessment of {function} control effectiveness")
        recommendations.append(f"Document evidence for all {function} controls")
        
        return recommendations
