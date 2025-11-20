"""AI Agent Security & Diagnostics Agent.

Performs comprehensive security assessments and NIST compliance checks on AI agents.
"""

import os
import sys
import uuid
from typing import List, Dict, Optional
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.prompts import PromptTemplate
from langchain.tools import Tool

from src.models.schemas import (
    DiagnosticReport, CertificationReport, SecurityTest,
    NISTAIRMFAssessment, NISTCSFAssessment, VulnerabilityFinding
)
from src.tools.nist_ai_rmf_checker import NISTAIRMFChecker
from src.tools.nist_csf_checker import NISTCSFChecker
from src.tools.agent_security_scanner import AgentSecurityScanner


class AgentSecurityDiagnosticsAgent:
    """Agent for security diagnostics and NIST compliance assessment."""
    
    def __init__(self, model_name: str = "gemini-2.0-flash"):
        """Initialize the agent."""
        self.llm = ChatGoogleGenerativeAI(model=model_name, temperature=0.1)
        self.ai_rmf_checker = NISTAIRMFChecker()
        self.csf_checker = NISTCSFChecker()
        self.security_scanner = AgentSecurityScanner()
        
    def run_self_diagnostics(self) -> DiagnosticReport:
        """Run comprehensive self-diagnostics."""
        report_id = f"DIAG-{uuid.uuid4().hex[:8]}"
        
        # Run security tests
        security_tests = self.security_scanner.run_all_tests()
        security_score = self.security_scanner.calculate_security_score(security_tests)
        
        # Run NIST AI RMF assessment
        ai_rmf_assessments = self.ai_rmf_checker.assess_all_functions()
        
        # Run NIST CSF assessment
        csf_assessments = self.csf_checker.assess_all_functions()
        
        # Calculate overall score
        ai_rmf_avg = sum(a.compliance_score for a in ai_rmf_assessments) / len(ai_rmf_assessments)
        csf_avg = sum(a.compliance_score for a in csf_assessments) / len(csf_assessments)
        overall_score = (security_score + ai_rmf_avg + csf_avg) / 3
        
        # Determine risk level
        risk_level = self._calculate_risk_level(overall_score, security_tests)
        
        # Count vulnerabilities
        critical_vulns = sum(1 for t in security_tests if t.severity == "critical" and t.status == "fail")
        high_vulns = sum(1 for t in security_tests if t.severity == "high" and t.status == "fail")
        
        # Generate recommendations
        recommendations = self._generate_recommendations(security_tests, ai_rmf_assessments, csf_assessments)
        
        return DiagnosticReport(
            report_id=report_id,
            timestamp=datetime.now(),
            agent_name="Enterprise Risk Assessment System",
            agent_version="1.0.0",
            security_tests=security_tests,
            security_score=security_score,
            nist_ai_rmf_assessments=ai_rmf_assessments,
            nist_csf_assessments=csf_assessments,
            vulnerabilities=[],
            critical_vulnerabilities=critical_vulns,
            high_vulnerabilities=high_vulns,
            overall_score=overall_score,
            risk_level=risk_level,
            recommendations=recommendations
        )
    
    def assess_agent(self, agent_name: str) -> DiagnosticReport:
        """Assess another agent in the system."""
        # Similar to self-diagnostics but for specific agent
        scanner = AgentSecurityScanner(agent_name=agent_name)
        security_tests = scanner.run_all_tests()
        security_score = scanner.calculate_security_score(security_tests)
        
        ai_rmf_checker = NISTAIRMFChecker(agent_name=agent_name)
        ai_rmf_assessments = ai_rmf_checker.assess_all_functions()
        
        csf_checker = NISTCSFChecker(agent_name=agent_name)
        csf_assessments = csf_checker.assess_all_functions()
        
        ai_rmf_avg = sum(a.compliance_score for a in ai_rmf_assessments) / len(ai_rmf_assessments)
        csf_avg = sum(a.compliance_score for a in csf_assessments) / len(csf_assessments)
        overall_score = (security_score + ai_rmf_avg + csf_avg) / 3
        
        risk_level = self._calculate_risk_level(overall_score, security_tests)
        
        return DiagnosticReport(
            report_id=f"DIAG-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(),
            agent_name=agent_name,
            security_tests=security_tests,
            security_score=security_score,
            nist_ai_rmf_assessments=ai_rmf_assessments,
            nist_csf_assessments=csf_assessments,
            vulnerabilities=[],
            critical_vulnerabilities=0,
            high_vulnerabilities=0,
            overall_score=overall_score,
            risk_level=risk_level,
            recommendations=self._generate_recommendations(security_tests, ai_rmf_assessments, csf_assessments)
        )
    
    def generate_certification_report(self, diagnostic_report: DiagnosticReport) -> CertificationReport:
        """Generate production certification report."""
        # Determine certification status
        production_ready = diagnostic_report.overall_score >= 70 and diagnostic_report.critical_vulnerabilities == 0
        
        if diagnostic_report.overall_score >= 80:
            cert_status = "certified"
        elif diagnostic_report.overall_score >= 60:
            cert_status = "conditional"
        else:
            cert_status = "not_certified"
        
        # Calculate component scores
        ai_rmf_score = sum(a.compliance_score for a in diagnostic_report.nist_ai_rmf_assessments) / len(diagnostic_report.nist_ai_rmf_assessments)
        csf_score = sum(a.compliance_score for a in diagnostic_report.nist_csf_assessments) / len(diagnostic_report.nist_csf_assessments)
        
        # Collect findings by severity
        critical_findings = [t.test_name for t in diagnostic_report.security_tests if t.severity == "critical" and t.status == "fail"]
        high_findings = [t.test_name for t in diagnostic_report.security_tests if t.severity == "high" and t.status in ["fail", "warning"]]
        medium_findings = [t.test_name for t in diagnostic_report.security_tests if t.severity == "medium" and t.status in ["fail", "warning"]]
        
        return CertificationReport(
            report_id=f"CERT-{uuid.uuid4().hex[:8]}",
            agent_name=diagnostic_report.agent_name,
            assessment_date=datetime.now(),
            assessor="AI Security Diagnostics Agent",
            production_ready=production_ready,
            certification_status=cert_status,
            risk_level=diagnostic_report.risk_level,
            security_score=diagnostic_report.security_score,
            nist_ai_rmf_score=ai_rmf_score,
            nist_csf_score=csf_score,
            overall_compliance_score=diagnostic_report.overall_score,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            remediation_plan=diagnostic_report.recommendations[:5],
            estimated_remediation_time="2-4 weeks" if not production_ready else "N/A"
        )
    
    def _calculate_risk_level(self, overall_score: float, security_tests: List[SecurityTest]) -> str:
        """Calculate overall risk level."""
        critical_fails = sum(1 for t in security_tests if t.severity == "critical" and t.status == "fail")
        
        if critical_fails > 0 or overall_score < 40:
            return "critical"
        elif overall_score < 60:
            return "high"
        elif overall_score < 80:
            return "medium"
        else:
            return "low"
    
    def _generate_recommendations(self, security_tests, ai_rmf_assessments, csf_assessments) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        # Critical security issues first
        critical_tests = [t for t in security_tests if t.severity == "critical" and t.status == "fail"]
        for test in critical_tests[:3]:
            recommendations.extend(test.recommendations[:1])
        
        # High priority gaps
        for assessment in ai_rmf_assessments:
            if assessment.compliance_score < 60:
                recommendations.extend(assessment.recommendations[:1])
        
        for assessment in csf_assessments:
            if assessment.compliance_score < 60:
                recommendations.extend(assessment.recommendations[:1])
        
        return list(set(recommendations))[:10]  # Top 10 unique recommendations
