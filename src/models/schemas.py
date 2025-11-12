"""Pydantic models for state management and data validation.

This module defines the core data structures used throughout the risk assessment system.
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
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

    class Config:
        arbitrary_types_allowed = True
