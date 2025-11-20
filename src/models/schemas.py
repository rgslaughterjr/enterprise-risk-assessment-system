"""Pydantic models for state management and data validation.

This module defines the core data structures used throughout the risk assessment system.
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


# ============================================================================
# ServiceNow Models
# ============================================================================

class ServiceNowIncident(BaseModel):
    """ServiceNow incident model."""

    number: str = Field(..., description="Incident number (e.g., INC0010001)")
    short_description: str = Field(..., description="Brief description")
    description: Optional[str] = Field(None, description="Detailed description")
    priority: str = Field(..., description="Priority level (1-5)")
    state: str = Field(..., description="Incident state")
    assigned_to: Optional[str] = Field(None, description="Assigned user")
    sys_created_on: str = Field(..., description="Creation timestamp")
    sys_updated_on: str = Field(..., description="Update timestamp")
    sys_id: str = Field(..., description="System ID")


class CMDBItem(BaseModel):
    """Configuration Management Database item model."""

    name: str = Field(..., description="Asset name")
    sys_class_name: str = Field(..., description="Asset class/type")
    sys_id: str = Field(..., description="System ID")
    ip_address: Optional[str] = Field(None, description="IP address")
    dns_domain: Optional[str] = Field(None, description="DNS domain")
    operational_status: Optional[str] = Field(None, description="Operational status")


# ============================================================================
# Vulnerability Models
# ============================================================================

class CVEDetail(BaseModel):
    """CVE vulnerability details from NVD."""

    cve_id: str = Field(..., description="CVE identifier")
    description: str = Field(..., description="Vulnerability description")
    cvss_score: Optional[float] = Field(None, description="CVSS base score")
    cvss_severity: Optional[str] = Field(None, description="Severity rating")
    published_date: Optional[str] = Field(None, description="Publication date")
    last_modified: Optional[str] = Field(None, description="Last modified date")
    cpe_matches: List[str] = Field(default_factory=list, description="Affected products")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class ExploitationStatus(BaseModel):
    """Exploitation status from multiple sources."""

    cve_id: str = Field(..., description="CVE identifier")
    in_cisa_kev: bool = Field(False, description="In CISA KEV catalog")
    virustotal_detections: int = Field(0, description="VirusTotal detection count")
    exploit_available: bool = Field(False, description="Public exploit available")
    actively_exploited: bool = Field(False, description="Active exploitation detected")


class VulnerabilityAnalysis(BaseModel):
    """Complete vulnerability analysis result."""

    cve_detail: CVEDetail
    exploitation_status: ExploitationStatus
    priority_score: float = Field(..., description="Calculated priority (0-100)")
    recommendation: str = Field(..., description="Remediation recommendation")


# ============================================================================
# Threat Intelligence Models
# ============================================================================

class MITRETechnique(BaseModel):
    """MITRE ATT&CK technique."""

    technique_id: str = Field(..., description="Technique ID (e.g., T1059)")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Description")
    tactics: List[str] = Field(default_factory=list, description="Associated tactics")
    platforms: List[str] = Field(default_factory=list, description="Target platforms")


class ThreatActor(BaseModel):
    """Threat actor profile."""

    name: str = Field(..., description="Actor name")
    aliases: List[str] = Field(default_factory=list, description="Known aliases")
    description: str = Field(..., description="Description")
    techniques: List[str] = Field(default_factory=list, description="Known techniques")
    targeted_sectors: List[str] = Field(default_factory=list, description="Target sectors")


class ThreatIntelligence(BaseModel):
    """Comprehensive threat intelligence."""

    cve_id: str = Field(..., description="Related CVE")
    techniques: List[MITRETechnique] = Field(default_factory=list)
    threat_actors: List[ThreatActor] = Field(default_factory=list)
    iocs: Dict[str, List[str]] = Field(default_factory=dict, description="IOCs by type")
    narrative: str = Field(..., description="Threat narrative")


# ============================================================================
# Document Processing Models
# ============================================================================

class DocumentMetadata(BaseModel):
    """Document metadata."""

    filename: str
    file_type: str
    page_count: Optional[int] = None
    author: Optional[str] = None
    created_date: Optional[str] = None
    modified_date: Optional[str] = None


class ExtractedEntity(BaseModel):
    """Extracted entity from document."""

    entity_type: Literal["cve", "control", "asset", "risk", "finding"]
    value: str
    confidence: float
    context: str = Field(..., description="Surrounding text context")


class DocumentAnalysis(BaseModel):
    """Document analysis result."""

    metadata: DocumentMetadata
    text_content: str
    entities: List[ExtractedEntity]
    summary: str


# ============================================================================
# Risk Scoring Models
# ============================================================================

class LikelihoodScore(BaseModel):
    """FAIR-based likelihood assessment."""

    cve_severity: int = Field(..., ge=1, le=5, description="CVE CVSS severity (1-5)")
    exploitation_status: int = Field(..., ge=1, le=5, description="Exploitation evidence (1-5)")
    asset_exposure: int = Field(..., ge=1, le=5, description="Asset exposure level (1-5)")
    threat_capability: int = Field(..., ge=1, le=5, description="Threat actor capability (1-5)")
    control_effectiveness: int = Field(..., ge=1, le=5, description="Existing controls (1-5)")
    overall_score: int = Field(..., ge=1, le=5, description="Overall likelihood (1-5)")
    justification: str = Field(..., description="Scoring rationale")


class ImpactScore(BaseModel):
    """FAIR-based impact assessment."""

    asset_criticality: int = Field(..., ge=1, le=5, description="Asset business criticality (1-5)")
    data_sensitivity: int = Field(..., ge=1, le=5, description="Data sensitivity level (1-5)")
    business_impact: int = Field(..., ge=1, le=5, description="Business process impact (1-5)")
    compliance_impact: int = Field(..., ge=1, le=5, description="Regulatory impact (1-5)")
    operational_impact: int = Field(..., ge=1, le=5, description="Operational disruption (1-5)")
    overall_score: int = Field(..., ge=1, le=5, description="Overall impact (1-5)")
    justification: str = Field(..., description="Scoring rationale")


class RiskRating(BaseModel):
    """Complete risk rating."""

    cve_id: str
    asset_name: str
    likelihood: LikelihoodScore
    impact: ImpactScore
    risk_level: Literal["Critical", "High", "Medium", "Low"]
    risk_score: int = Field(..., ge=1, le=25, description="Risk matrix score (1-25)")
    overall_justification: str = Field(..., description="Complete risk justification")
    recommendations: List[str] = Field(default_factory=list)


# ============================================================================
# Report Models
# ============================================================================

class ExecutiveSummary(BaseModel):
    """Executive summary for report."""

    total_vulnerabilities: int
    critical_risks: int
    high_risks: int
    medium_risks: int
    low_risks: int
    key_findings: List[str]
    top_recommendations: List[str]


class RiskAssessmentReport(BaseModel):
    """Complete risk assessment report."""

    report_id: str
    generated_at: datetime
    executive_summary: ExecutiveSummary
    incidents: List[ServiceNowIncident]
    vulnerabilities: List[VulnerabilityAnalysis]
    threats: List[ThreatIntelligence]
    risk_ratings: List[RiskRating]
    document_path: Optional[str] = None


# ============================================================================
# Agent State Models (for LangGraph)
# ============================================================================

class AgentState(BaseModel):
    """State shared across all agents in LangGraph workflow."""

    # User input
    query: str = Field(..., description="User query or task")

    # ServiceNow data
    incidents: List[ServiceNowIncident] = Field(default_factory=list)
    cmdb_items: List[CMDBItem] = Field(default_factory=list)

    # Vulnerability data
    vulnerabilities: List[VulnerabilityAnalysis] = Field(default_factory=list)

    # Threat intelligence
    threats: List[ThreatIntelligence] = Field(default_factory=list)

    # Document analysis
    documents: List[DocumentAnalysis] = Field(default_factory=list)

    # Risk scores
    risk_ratings: List[RiskRating] = Field(default_factory=list)

    # Report
    report: Optional[RiskAssessmentReport] = None
    report_path: Optional[str] = None

    # Workflow control
    next_agent: Optional[str] = Field(None, description="Next agent to call")
    completed: bool = Field(False, description="Workflow completion flag")
    error: Optional[str] = Field(None, description="Error message if any")

    # User interaction
    user_feedback: Optional[str] = Field(None, description="User check-in response")

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ============================================================================
# Agent Security & Diagnostics Models
# ============================================================================

class SecurityTest(BaseModel):
    """Individual security test result."""
    
    test_id: str = Field(..., description="Unique test identifier")
    test_name: str = Field(..., description="Human-readable test name")
    category: Literal["input_validation", "authentication", "data_protection", "api_security", "dependencies", "configuration"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    status: Literal["pass", "fail", "warning", "skipped"]
    findings: List[str] = Field(default_factory=list, description="Detailed findings")
    recommendations: List[str] = Field(default_factory=list, description="Remediation recommendations")
    timestamp: datetime = Field(default_factory=datetime.now)


class NISTAIRMFControl(BaseModel):
    """NIST AI RMF control assessment."""
    
    control_id: str = Field(..., description="Control identifier")
    control_name: str = Field(..., description="Control name")
    function: Literal["GOVERN", "MAP", "MEASURE", "MANAGE"]
    implemented: bool = Field(..., description="Whether control is implemented")
    effectiveness: Literal["effective", "partially_effective", "ineffective", "not_applicable"]
    evidence: List[str] = Field(default_factory=list, description="Evidence of implementation")
    gaps: List[str] = Field(default_factory=list, description="Identified gaps")


class NISTAIRMFAssessment(BaseModel):
    """NIST AI Risk Management Framework assessment."""
    
    function: Literal["GOVERN", "MAP", "MEASURE", "MANAGE"]
    controls: List[NISTAIRMFControl] = Field(default_factory=list)
    compliance_score: float = Field(..., ge=0.0, le=100.0, description="Compliance percentage")
    implemented_controls: int = Field(..., description="Number of implemented controls")
    total_controls: int = Field(..., description="Total number of controls")
    gaps: List[str] = Field(default_factory=list, description="Overall gaps")
    recommendations: List[str] = Field(default_factory=list, description="Improvement recommendations")


class NISTCSFCategory(BaseModel):
    """NIST CSF 2.0 category assessment."""
    
    category_id: str = Field(..., description="Category identifier (e.g., ID.AM)")
    category_name: str = Field(..., description="Category name")
    function: Literal["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER", "GOVERN"]
    implementation_tier: Literal[1, 2, 3, 4] = Field(..., description="Implementation tier (1-4)")
    controls_implemented: int = Field(..., description="Number of controls implemented")
    controls_total: int = Field(..., description="Total number of controls")
    maturity_level: Literal["initial", "managed", "defined", "quantitatively_managed", "optimizing"]


class NISTCSFAssessment(BaseModel):
    """NIST Cybersecurity Framework 2.0 assessment."""
    
    function: Literal["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER", "GOVERN"]
    categories: List[NISTCSFCategory] = Field(default_factory=list)
    compliance_score: float = Field(..., ge=0.0, le=100.0, description="Compliance percentage")
    implementation_tier: Literal[1, 2, 3, 4] = Field(..., description="Overall implementation tier")
    gaps: List[str] = Field(default_factory=list, description="Identified gaps")
    recommendations: List[str] = Field(default_factory=list, description="Improvement recommendations")


class VulnerabilityFinding(BaseModel):
    """Security vulnerability finding."""
    
    vulnerability_id: str = Field(..., description="Unique vulnerability identifier")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description")
    severity: Literal["critical", "high", "medium", "low", "info"]
    category: str = Field(..., description="Vulnerability category (OWASP, CWE, etc.)")
    affected_component: str = Field(..., description="Affected component or module")
    remediation: str = Field(..., description="Remediation guidance")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score if applicable")


class DiagnosticReport(BaseModel):
    """Comprehensive diagnostic report for an agent."""
    
    report_id: str = Field(..., description="Unique report identifier")
    timestamp: datetime = Field(default_factory=datetime.now)
    agent_name: str = Field(..., description="Name of assessed agent")
    agent_version: Optional[str] = Field(None, description="Agent version")
    
    # Security tests
    security_tests: List[SecurityTest] = Field(default_factory=list)
    security_score: float = Field(..., ge=0.0, le=100.0, description="Overall security score")
    
    # NIST compliance
    nist_ai_rmf_assessments: List[NISTAIRMFAssessment] = Field(default_factory=list)
    nist_csf_assessments: List[NISTCSFAssessment] = Field(default_factory=list)
    
    # Vulnerabilities
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    critical_vulnerabilities: int = Field(0, description="Count of critical vulnerabilities")
    high_vulnerabilities: int = Field(0, description="Count of high vulnerabilities")
    
    # Overall assessment
    overall_score: float = Field(..., ge=0.0, le=100.0, description="Overall health score")
    risk_level: Literal["critical", "high", "medium", "low"] = Field(..., description="Overall risk level")
    recommendations: List[str] = Field(default_factory=list, description="Prioritized recommendations")


class CertificationReport(BaseModel):
    """Production certification report."""
    
    report_id: str = Field(..., description="Unique certification report ID")
    agent_name: str = Field(..., description="Agent being certified")
    assessment_date: datetime = Field(default_factory=datetime.now)
    assessor: str = Field(..., description="Who performed the assessment")
    
    # Certification decision
    production_ready: bool = Field(..., description="Whether agent is production-ready")
    certification_status: Literal["certified", "conditional", "not_certified"]
    risk_level: Literal["critical", "high", "medium", "low"]
    
    # Scores
    security_score: float = Field(..., ge=0.0, le=100.0)
    nist_ai_rmf_score: float = Field(..., ge=0.0, le=100.0)
    nist_csf_score: float = Field(..., ge=0.0, le=100.0)
    overall_compliance_score: float = Field(..., ge=0.0, le=100.0)
    
    # Findings
    critical_findings: List[str] = Field(default_factory=list)
    high_findings: List[str] = Field(default_factory=list)
    medium_findings: List[str] = Field(default_factory=list)
    
    # Remediation
    remediation_plan: List[str] = Field(default_factory=list, description="Required remediation steps")
    estimated_remediation_time: Optional[str] = Field(None, description="Estimated time to remediate")
    
    # Approval
    approver_notes: str = Field("", description="Notes from approver")
    approval_date: Optional[datetime] = Field(None, description="Date of approval")
    next_assessment_date: Optional[datetime] = Field(None, description="Next scheduled assessment")


class AgentInventory(BaseModel):
    """Inventory of agents in the system."""
    
    agent_name: str = Field(..., description="Agent name")
    agent_type: str = Field(..., description="Agent type/category")
    version: Optional[str] = Field(None, description="Agent version")
    description: str = Field(..., description="Agent description")
    last_assessed: Optional[datetime] = Field(None, description="Last security assessment date")
    certification_status: Optional[Literal["certified", "conditional", "not_certified", "not_assessed"]] = None
    risk_level: Optional[Literal["critical", "high", "medium", "low"]] = None
