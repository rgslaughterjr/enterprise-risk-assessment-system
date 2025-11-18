# API Reference

Complete API documentation for the Enterprise Risk Assessment System.

**Version:** 1.0.0
**Last Updated:** 2024-11-18
**Status:** Production-ready (Weeks 1-7 complete)

---

## Table of Contents

1. [Authentication & Configuration](#authentication)
2. [Core Agents](#core-agents)
   - [ServiceNow Agent](#servicenow-agent)
   - [Vulnerability Agent](#vulnerability-agent)
   - [Threat Agent](#threat-agent)
   - [Document Agent](#document-agent)
   - [Risk Scoring Agent](#risk-scoring-agent)
   - [Report Agent](#report-agent)
3. [Advanced Agents](#advanced-agents)
   - [Control Discovery Agent](#control-discovery-agent)
   - [Threat Scenario Agent](#threat-scenario-agent)
   - [ToT Risk Scorer](#tot-risk-scorer)
4. [RAG Components](#rag-components)
   - [Semantic Chunker](#semantic-chunker)
   - [Hybrid Retriever](#hybrid-retriever)
   - [Query Optimizer](#query-optimizer)
5. [Document Intelligence](#document-intelligence)
   - [OCR Processor](#ocr-processor)
   - [Table Extractor](#table-extractor)
   - [Document Classifier](#document-classifier)
   - [Entity Extractor](#entity-extractor)
6. [External API Clients](#external-api-clients)
7. [Data Models](#data-models)
8. [Error Handling](#error-handling)
9. [Rate Limits & Best Practices](#rate-limits)

---

<a id='authentication'></a>
## 1. Authentication & Configuration

### Environment Variables

All API credentials must be configured in `.env` file:

```bash
# Required - LLM Provider
ANTHROPIC_API_KEY=sk-ant-...

# Required - ServiceNow Personal Developer Instance
SERVICENOW_INSTANCE=https://devXXXXX.service-now.com
SERVICENOW_USERNAME=admin
SERVICENOW_PASSWORD=...

# Required - Threat Intelligence APIs
NVD_API_KEY=...                    # NIST National Vulnerability Database
VIRUSTOTAL_API_KEY=...             # VirusTotal API v3
ALIENVAULT_OTX_KEY=...             # AlienVault Open Threat Exchange

# Optional - Observability
LANGSMITH_API_KEY=...              # LangSmith tracing
LANGSMITH_TRACING=true
LANGSMITH_PROJECT=enterprise-risk-assessment
```

### Initialization

```python
from dotenv import load_dotenv
load_dotenv()

# Verify environment
import os
assert os.getenv('ANTHROPIC_API_KEY'), "Missing ANTHROPIC_API_KEY"
assert os.getenv('SERVICENOW_INSTANCE'), "Missing ServiceNow credentials"
```

---

<a id='core-agents'></a>
## 2. Core Agents

<a id='servicenow-agent'></a>
### ServiceNow Agent

Query ServiceNow incidents, assets, and CMDB data.

**Import:**
```python
from src.agents.servicenow_agent import ServiceNowAgent
```

#### Constructor

```python
ServiceNowAgent(
    servicenow_instance: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None
)
```

**Parameters:**
- `servicenow_instance` (str, optional): ServiceNow instance URL. Defaults to `SERVICENOW_INSTANCE` env var.
- `username` (str, optional): ServiceNow username. Defaults to `SERVICENOW_USERNAME` env var.
- `password` (str, optional): ServiceNow password. Defaults to `SERVICENOW_PASSWORD` env var.

#### Methods

##### `get_incidents_for_analysis()`

Retrieve incidents for risk assessment.

```python
def get_incidents_for_analysis(
    priority: Optional[str] = None,
    state: Optional[str] = None,
    limit: int = 10
) -> List[ServiceNowIncident]
```

**Parameters:**
- `priority` (str, optional): Filter by priority (1-5). Example: `"1"` for critical incidents.
- `state` (str, optional): Filter by state. Example: `"2"` for in-progress.
- `limit` (int): Maximum number of incidents to return. Default: 10.

**Returns:** `List[ServiceNowIncident]`

**Example:**
```python
agent = ServiceNowAgent()

# Get critical incidents
incidents = agent.get_incidents_for_analysis(priority="1", limit=5)

for inc in incidents:
    print(f"{inc.number}: {inc.short_description}")
    print(f"  Priority: {inc.priority} | State: {inc.state}")
    print(f"  Opened: {inc.opened_at}")
```

**Response Schema:**
```python
class ServiceNowIncident:
    sys_id: str
    number: str
    short_description: str
    description: str
    priority: str
    state: str
    opened_at: str
    assigned_to: Optional[str]
    assignment_group: Optional[str]
```

##### `get_asset_details()`

Retrieve CMDB asset information.

```python
def get_asset_details(
    asset_name: str
) -> Optional[CMDBItem]
```

**Parameters:**
- `asset_name` (str): Name or CI identifier of the asset.

**Returns:** `CMDBItem` or `None`

**Example:**
```python
asset = agent.get_asset_details("firewall-prod-01")
print(f"Asset: {asset.name}")
print(f"Class: {asset.sys_class_name}")
print(f"Operational Status: {asset.operational_status}")
```

##### `query()`

Natural language query interface.

```python
def query(user_input: str) -> str
```

**Parameters:**
- `user_input` (str): Natural language query.

**Example:**
```python
result = agent.query("Show me all P1 incidents opened this week")
print(result)
```

---

<a id='vulnerability-agent'></a>
### Vulnerability Agent

Analyze CVEs using NVD, VirusTotal, and CISA KEV.

**Import:**
```python
from src.agents.vulnerability_agent import VulnerabilityAgent
```

#### Constructor

```python
VulnerabilityAgent(
    nvd_api_key: Optional[str] = None,
    vt_api_key: Optional[str] = None,
    otx_api_key: Optional[str] = None
)
```

#### Methods

##### `analyze_cves()`

Comprehensive CVE analysis with exploitation intelligence.

```python
def analyze_cves(
    cve_ids: List[str]
) -> List[VulnerabilityAnalysis]
```

**Parameters:**
- `cve_ids` (List[str]): List of CVE identifiers. Example: `["CVE-2024-3400"]`.

**Returns:** `List[VulnerabilityAnalysis]`

**Example:**
```python
agent = VulnerabilityAgent()

analyses = agent.analyze_cves(["CVE-2024-3400", "CVE-2024-21762"])

for analysis in analyses:
    cve = analysis.cve_detail
    exp = analysis.exploitation_status

    print(f"CVE: {cve.cve_id}")
    print(f"CVSS: {cve.cvss_score} ({cve.cvss_severity})")
    print(f"Priority Score: {analysis.priority_score}/100")
    print(f"CISA KEV: {exp.in_cisa_kev}")
    print(f"VirusTotal Detections: {exp.vt_detections}")
```

**Response Schema:**
```python
class VulnerabilityAnalysis:
    cve_detail: CVEDetail
    exploitation_status: ExploitationStatus
    priority_score: int  # 0-100

class CVEDetail:
    cve_id: str
    cvss_score: float
    cvss_severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    cvss_vector: Optional[str]
    description: str
    published_date: str
    last_modified_date: str
    cwe_ids: List[str]

class ExploitationStatus:
    in_cisa_kev: bool
    kev_date_added: Optional[str]
    vt_detections: int
    vt_malicious: int
    otx_pulses: int
```

##### `get_cve_details()`

Get detailed CVE information from NVD.

```python
def get_cve_details(cve_id: str) -> CVEDetail
```

**Example:**
```python
cve = agent.get_cve_details("CVE-2024-3400")
print(f"Description: {cve.description}")
print(f"CWE: {cve.cwe_ids}")
```

---

<a id='threat-agent'></a>
### Threat Agent

MITRE ATT&CK and AlienVault OTX threat intelligence.

**Import:**
```python
from src.agents.threat_agent import ThreatAgent
```

#### Methods

##### `analyze_cve_threat()`

Map CVE to MITRE ATT&CK techniques and gather IOCs.

```python
def analyze_cve_threat(
    cve_id: str,
    vulnerability_type: str
) -> ThreatIntelligence
```

**Parameters:**
- `cve_id` (str): CVE identifier.
- `vulnerability_type` (str): Vulnerability classification (e.g., "OS command injection").

**Returns:** `ThreatIntelligence`

**Example:**
```python
agent = ThreatAgent()

threat_intel = agent.analyze_cve_threat(
    cve_id="CVE-2024-3400",
    vulnerability_type="OS command injection"
)

print(f"Mapped Techniques ({len(threat_intel.techniques)}):")
for tech in threat_intel.techniques:
    print(f"  {tech.technique_id}: {tech.name}")
    print(f"    Tactic: {tech.tactic}")

print(f"\nIOCs ({len(threat_intel.iocs)}):")
for ioc in threat_intel.iocs:
    print(f"  {ioc.type}: {ioc.value}")

print(f"\nCampaigns: {threat_intel.campaigns}")
```

**Response Schema:**
```python
class ThreatIntelligence:
    techniques: List[MitreTechnique]
    iocs: List[IOC]
    narrative: str
    campaigns: List[str]
    threat_actors: List[str]

class MitreTechnique:
    technique_id: str  # e.g., "T1190"
    name: str
    tactic: str
    description: str

class IOC:
    type: str  # "ip", "domain", "hash", "url"
    value: str
    context: Optional[str]
```

##### `get_mitre_techniques()`

Search MITRE ATT&CK techniques by keyword.

```python
def get_mitre_techniques(
    search_term: str,
    limit: int = 10
) -> List[MitreTechnique]
```

**Example:**
```python
techniques = agent.get_mitre_techniques("command injection")
```

---

<a id='document-agent'></a>
### Document Agent

RAG-based document querying and entity extraction.

**Import:**
```python
from src.agents.document_agent import DocumentAgent
```

#### Methods

##### `query_documents()`

Query ingested documents using hybrid retrieval.

```python
def query_documents(
    query: str,
    top_k: int = 5
) -> List[Dict[str, Any]]
```

**Parameters:**
- `query` (str): Natural language query.
- `top_k` (int): Number of results to return. Default: 5.

**Returns:** List of document chunks with scores.

**Example:**
```python
agent = DocumentAgent()

# Ingest documents first
agent.ingest_document("policies/access_control.pdf")

# Query
results = agent.query_documents("What are the MFA requirements?", top_k=3)

for result in results:
    print(f"Score: {result['score']:.3f}")
    print(f"Text: {result['text'][:200]}...")
    print(f"Source: {result['metadata']['source']}")
```

##### `extract_risk_entities()`

Extract CVEs, controls, assets from documents.

```python
def extract_risk_entities(
    text: str
) -> Dict[str, List[str]]
```

**Example:**
```python
text = "CVE-2024-3400 affects firewall-prod-01. Implement AC-2 and SI-2."
entities = agent.extract_risk_entities(text)

print(f"CVEs: {entities['cves']}")
print(f"Assets: {entities['assets']}")
print(f"Controls: {entities['controls']}")
```

---

<a id='risk-scoring-agent'></a>
### Risk Scoring Agent

FAIR-based 5×5 risk matrix calculation.

**Import:**
```python
from src.agents.risk_scoring_agent import RiskScoringAgent
```

#### Methods

##### `calculate_risk()`

Calculate comprehensive risk rating.

```python
def calculate_risk(
    cve_id: str,
    asset_name: str,
    cvss_score: float,
    in_cisa_kev: bool = False,
    asset_criticality: int = 3,
    data_sensitivity: int = 3,
    business_impact: int = 3,
    compliance_impact: int = 3,
    has_compensating_controls: bool = False,
    internet_facing: bool = True
) -> RiskRating
```

**Parameters:**
- `cve_id` (str): CVE identifier.
- `asset_name` (str): Asset name.
- `cvss_score` (float): CVSS base score (0.0-10.0).
- `in_cisa_kev` (bool): Whether CVE is in CISA KEV catalog.
- `asset_criticality` (int): Asset importance (1-5). 5 = mission-critical.
- `data_sensitivity` (int): Data classification (1-5). 5 = highly sensitive.
- `business_impact` (int): Business impact (1-5). 5 = severe financial/operational impact.
- `compliance_impact` (int): Regulatory impact (1-5). 5 = critical compliance requirement.
- `has_compensating_controls` (bool): Whether mitigating controls exist.
- `internet_facing` (bool): Whether asset is exposed to internet.

**Returns:** `RiskRating`

**Example:**
```python
agent = RiskScoringAgent()

risk = agent.calculate_risk(
    cve_id="CVE-2024-3400",
    asset_name="firewall-prod-01",
    cvss_score=10.0,
    in_cisa_kev=True,
    asset_criticality=5,
    data_sensitivity=5,
    business_impact=5,
    compliance_impact=4,
    has_compensating_controls=False,
    internet_facing=True
)

print(f"Risk Score: {risk.score}/25")
print(f"Risk Level: {risk.level}")
print(f"Likelihood: {risk.likelihood}/5")
print(f"Impact: {risk.impact}/5")
print(f"\n{risk.justification}")
```

**Response Schema:**
```python
class RiskRating:
    cve_id: str
    asset_name: str
    likelihood: int  # 1-5
    impact: int      # 1-5
    score: int       # 1-25 (likelihood × impact)
    level: str       # "Critical", "High", "Medium", "Low"
    justification: str
```

**Risk Level Thresholds:**
- **Critical:** Score ≥ 20 (e.g., 5×4, 4×5, 5×5)
- **High:** Score 12-19
- **Medium:** Score 6-11
- **Low:** Score 1-5

---

<a id='report-agent'></a>
### Report Agent

Generate professional DOCX reports.

**Import:**
```python
from src.agents.report_agent import ReportAgent
```

#### Methods

##### `generate_report()`

Create comprehensive risk assessment report.

```python
def generate_report(
    vulnerabilities: List[VulnerabilityAnalysis],
    risk_ratings: List[RiskRating],
    output_path: str = "risk_assessment_report.docx"
) -> str
```

**Parameters:**
- `vulnerabilities` (List[VulnerabilityAnalysis]): Vulnerability analysis results.
- `risk_ratings` (List[RiskRating]): Risk rating results.
- `output_path` (str): Output file path. Default: "risk_assessment_report.docx".

**Returns:** Path to generated report.

**Example:**
```python
agent = ReportAgent()

report_path = agent.generate_report(
    vulnerabilities=vuln_analyses,
    risk_ratings=risk_ratings,
    output_path="reports/assessment_2024-11-18.docx"
)

print(f"Report generated: {report_path}")
```

**Report Contents:**
1. Executive Summary
2. Risk Heatmap (5×5 matrix visualization)
3. Vulnerability Findings Table
4. Detailed Risk Analysis
5. Remediation Recommendations
6. Appendix: MITRE ATT&CK Mappings

---

<a id='advanced-agents'></a>
## 3. Advanced Agents

<a id='control-discovery-agent'></a>
### Control Discovery Agent

Discover security controls from multiple sources.

**Import:**
```python
from src.agents.control_discovery_agent import ControlDiscoveryAgent
```

#### Methods

##### `discover_controls()`

```python
def discover_controls(
    sources: List[str] = ['servicenow_grc', 'confluence', 'filesystem'],
    control_frameworks: List[str] = ['NIST_800_53', 'ISO_27001']
) -> List[Dict[str, Any]]
```

**Parameters:**
- `sources` (List[str]): Data sources to search.
- `control_frameworks` (List[str]): Control frameworks to map against.

**Example:**
```python
agent = ControlDiscoveryAgent()

controls = agent.discover_controls(
    sources=['servicenow_grc', 'confluence'],
    control_frameworks=['NIST_800_53']
)

for ctrl in controls:
    print(f"{ctrl['control_id']}: {ctrl['title']}")
    print(f"  Source: {ctrl['source']}")
    print(f"  Status: {ctrl['implementation_status']}")
```

---

<a id='threat-scenario-agent'></a>
### Threat Scenario Agent

Generate threat scenarios using Markov Chains.

**Import:**
```python
from src.agents.threat_scenario_agent import ThreatScenarioAgent
```

#### Methods

##### `generate_scenarios()`

```python
def generate_scenarios(
    initial_technique: str,
    num_scenarios: int = 3,
    max_steps: int = 5
) -> List[Dict[str, Any]]
```

**Parameters:**
- `initial_technique` (str): Starting MITRE technique ID (e.g., "T1190").
- `num_scenarios` (int): Number of scenarios to generate.
- `max_steps` (int): Maximum attack chain length.

**Example:**
```python
agent = ThreatScenarioAgent()

scenarios = agent.generate_scenarios(
    initial_technique="T1190",  # Exploit Public-Facing Application
    num_scenarios=3,
    max_steps=5
)

for scenario in scenarios:
    print(f"{scenario['name']} (P={scenario['probability']:.2%})")
    for step in scenario['attack_path']:
        print(f"  {step['technique_id']}: {step['technique_name']}")
```

---

<a id='tot-risk-scorer'></a>
### ToT Risk Scorer

Tree of Thought multi-branch risk evaluation.

**Import:**
```python
from src.agents.tot_risk_scorer import ToTRiskScorer
```

#### Methods

##### `evaluate_risk_with_tot()`

```python
def evaluate_risk_with_tot(
    cve_id: str,
    asset_name: str,
    cvss_score: float,
    in_cisa_kev: bool,
    asset_criticality: int,
    num_thoughts: int = 3,
    depth: int = 2
) -> Dict[str, Any]
```

**Parameters:**
- Standard risk parameters (same as `RiskScoringAgent.calculate_risk()`)
- `num_thoughts` (int): Number of reasoning branches. Default: 3.
- `depth` (int): Reasoning tree depth. Default: 2.

**Returns:** Dict with `thoughts`, `final_score`, and `recommendation`.

**Example:**
```python
agent = ToTRiskScorer()

result = agent.evaluate_risk_with_tot(
    cve_id="CVE-2024-3400",
    asset_name="firewall-prod-01",
    cvss_score=10.0,
    in_cisa_kev=True,
    asset_criticality=5,
    num_thoughts=3
)

print(f"Final Score: {result['final_score']}/25")
for thought in result['thoughts']:
    print(f"  Path: {thought['path']} | Score: {thought['risk_score']}")
```

---

<a id='rag-components'></a>
## 4. RAG Components

<a id='semantic-chunker'></a>
### Semantic Chunker

Advanced text chunking with 5 strategies.

**Import:**
```python
from src.tools.semantic_chunker import SemanticChunker
```

#### Methods

##### `chunk_text()`

```python
def chunk_text(
    text: str,
    strategy: str = "semantic",
    chunk_size: int = 500,
    chunk_overlap: int = 50
) -> List[Dict[str, Any]]
```

**Parameters:**
- `text` (str): Input text to chunk.
- `strategy` (str): Chunking strategy. Options:
  - `"fixed"` - Fixed-size chunks
  - `"sentence"` - Sentence-based boundaries
  - `"paragraph"` - Paragraph-based boundaries
  - `"semantic"` - Semantic similarity-based
  - `"hybrid"` - Combination of strategies
- `chunk_size` (int): Target chunk size in characters.
- `chunk_overlap` (int): Overlap between chunks.

**Returns:** List of chunks with metadata.

**Example:**
```python
chunker = SemanticChunker()

chunks = chunker.chunk_text(
    text=policy_document,
    strategy="semantic",
    chunk_size=500
)

for chunk in chunks:
    print(f"Chunk {chunk['chunk_id']}: {len(chunk['text'])} chars")
    print(f"  {chunk['text'][:100]}...")
```

---

<a id='hybrid-retriever'></a>
### Hybrid Retriever

BM25 + semantic search fusion.

**Import:**
```python
from src.tools.hybrid_retriever import HybridRetriever
```

#### Methods

##### `add_documents()`

```python
def add_documents(
    documents: List[Dict[str, Any]]
) -> None
```

##### `retrieve()`

```python
def retrieve(
    query: str,
    top_k: int = 5,
    semantic_weight: float = 0.9,
    keyword_weight: float = 0.1
) -> List[Dict[str, Any]]
```

**Parameters:**
- `query` (str): Search query.
- `top_k` (int): Number of results.
- `semantic_weight` (float): Weight for semantic search (0.0-1.0).
- `keyword_weight` (float): Weight for BM25 keyword search (0.0-1.0).

**Example:**
```python
retriever = HybridRetriever()
retriever.add_documents(chunks)

results = retriever.retrieve(
    query="authentication requirements",
    top_k=5,
    semantic_weight=0.9,
    keyword_weight=0.1
)

for result in results:
    print(f"Score: {result['score']:.3f}")
    print(f"Text: {result['text'][:150]}...")
```

---

<a id='query-optimizer'></a>
### Query Optimizer

Query expansion, rewriting, and HyDE.

**Import:**
```python
from src.tools.query_optimizer import QueryOptimizer
```

#### Methods

##### `expand_query()`

```python
def expand_query(query: str) -> str
```

Expand query with synonyms.

##### `rewrite_query()`

```python
def rewrite_query(
    query: str,
    context: str = "cybersecurity policy database"
) -> str
```

Rewrite query for better retrieval.

##### `generate_hypothetical_document()`

```python
def generate_hypothetical_document(query: str) -> str
```

Generate hypothetical document (HyDE technique).

**Example:**
```python
optimizer = QueryOptimizer()

original = "authentication controls"
expanded = optimizer.expand_query(original)
rewritten = optimizer.rewrite_query(original)
hyde = optimizer.generate_hypothetical_document(original)

print(f"Original: {original}")
print(f"Expanded: {expanded}")
print(f"Rewritten: {rewritten}")
print(f"HyDE: {hyde[:200]}...")
```

---

<a id='document-intelligence'></a>
## 5. Document Intelligence

<a id='ocr-processor'></a>
### OCR Processor

Extract text from scanned PDFs and images.

**Import:**
```python
from src.tools.ocr_processor import OCRProcessor
```

#### Methods

##### `process_pdf()`

```python
def process_pdf(
    pdf_path: str,
    preprocess: bool = True
) -> str
```

**Parameters:**
- `pdf_path` (str): Path to PDF file.
- `preprocess` (bool): Apply image preprocessing (grayscale, contrast, denoising).

**Example:**
```python
ocr = OCRProcessor()
text = ocr.process_pdf("scanned_audit_report.pdf")
print(text)
```

---

<a id='table-extractor'></a>
### Table Extractor

Extract structured tables from PDFs.

**Import:**
```python
from src.tools.table_extractor import TableExtractor
```

#### Methods

##### `extract_tables()`

```python
def extract_tables(
    pdf_path: str,
    page_numbers: Optional[List[int]] = None
) -> List[Dict[str, Any]]
```

**Returns:** List of tables with headers and rows.

**Example:**
```python
extractor = TableExtractor()
tables = extractor.extract_tables("compliance_report.pdf")

for i, table in enumerate(tables):
    print(f"Table {i+1}:")
    print(f"  Headers: {table['headers']}")
    print(f"  Rows: {len(table['rows'])}")
```

---

<a id='document-classifier'></a>
### Document Classifier

ML-based document categorization.

**Import:**
```python
from src.tools.document_classifier import DocumentClassifier
```

#### Methods

##### `train()`

```python
def train(
    training_data: List[Dict[str, str]]
) -> None
```

**Parameters:**
- `training_data` (List[Dict]): List of `{'text': str, 'category': str}` dicts.

##### `classify()`

```python
def classify(text: str) -> str
```

**Returns:** Document category.

**Categories:**
- `policy_document`
- `procedure_document`
- `audit_report`
- `risk_assessment`
- `compliance_report`
- `technical_specification`
- `incident_report`

**Example:**
```python
classifier = DocumentClassifier()
classifier.train(training_documents)

category = classifier.classify(document_text)
print(f"Document Type: {category}")
```

---

<a id='entity-extractor'></a>
### Entity Extractor

Extract CVEs, controls, assets, risks.

**Import:**
```python
from src.tools.entity_extractor import EntityExtractor
```

#### Methods

##### `extract_entities()`

```python
def extract_entities(text: str) -> Dict[str, List[str]]
```

**Returns:** Dict with keys: `cves`, `controls`, `assets`, `risks`, `findings`.

**Example:**
```python
extractor = EntityExtractor()

text = """
Critical vulnerability CVE-2024-3400 affects asset firewall-prod-01.
NIST controls AC-2 and SI-2 are not implemented.
Risk rating: HIGH - requires immediate remediation.
"""

entities = extractor.extract_entities(text)

print(f"CVEs: {entities['cves']}")
print(f"Controls: {entities['controls']}")
print(f"Assets: {entities['assets']}")
print(f"Risks: {entities['risks']}")
```

---

<a id='external-api-clients'></a>
## 6. External API Clients

### NVD Client

**Import:**
```python
from src.tools.nvd_client import NVDClient
```

**Methods:**
```python
client = NVDClient(api_key=os.getenv('NVD_API_KEY'))
cve = client.get_cve("CVE-2024-3400")
```

### VirusTotal Client

**Import:**
```python
from src.tools.virustotal_client import VirusTotalClient
```

**Methods:**
```python
client = VirusTotalClient(api_key=os.getenv('VIRUSTOTAL_API_KEY'))
analysis = client.get_url_analysis("example.com")
```

### CISA KEV Client

**Import:**
```python
from src.tools.cisa_kev_client import CISAKEVClient
```

**Methods:**
```python
client = CISAKEVClient()
is_exploited = client.is_cve_in_kev("CVE-2024-3400")
```

### AlienVault OTX Client

**Import:**
```python
from src.tools.otx_client import OTXClient
```

**Methods:**
```python
client = OTXClient(api_key=os.getenv('ALIENVAULT_OTX_KEY'))
pulses = client.get_cve_pulses("CVE-2024-3400")
```

### MITRE ATT&CK Client

**Import:**
```python
from src.tools.mitre_client import MitreClient
```

**Methods:**
```python
client = MitreClient()
technique = client.get_technique("T1190")
tactics = client.get_tactics()
```

---

<a id='data-models'></a>
## 7. Data Models

All data models use Pydantic for validation. See `src/models/schemas.py` for complete definitions.

### Key Models

```python
from src.models.schemas import (
    CVEDetail,
    ExploitationStatus,
    VulnerabilityAnalysis,
    ThreatIntelligence,
    MitreTechnique,
    IOC,
    RiskRating,
    RiskAssessmentReport,
    ServiceNowIncident,
    CMDBItem
)
```

---

<a id='error-handling'></a>
## 8. Error Handling

All API calls implement retry logic with exponential backoff using `tenacity`:

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
def api_call():
    # API request
    pass
```

### Common Exceptions

```python
from src.exceptions import (
    APIRateLimitError,
    APIAuthenticationError,
    APINotFoundError,
    ValidationError
)

try:
    result = agent.analyze_cves(["CVE-2024-3400"])
except APIRateLimitError:
    # Wait and retry
    time.sleep(60)
except APIAuthenticationError:
    # Check API keys
    print("Invalid credentials")
except ValidationError as e:
    # Invalid input
    print(f"Validation error: {e}")
```

---

<a id='rate-limits'></a>
## 9. Rate Limits & Best Practices

### API Rate Limits

| API | Free Tier | Paid Tier | Notes |
|-----|-----------|-----------|-------|
| **NVD** | 5 req/30s | 50 req/30s | Requires API key for higher limit |
| **VirusTotal** | 4 req/min | 1000 req/day | Free tier sufficient for most use cases |
| **AlienVault OTX** | 10 req/sec | N/A | No authentication required |
| **MITRE ATT&CK** | Unlimited | N/A | Local STIX data |
| **ServiceNow** | Depends on instance | N/A | PDI has generous limits |

### Best Practices

1. **Batch Requests:**
   ```python
   # Good: Batch CVE analysis
   analyses = vuln_agent.analyze_cves(["CVE-2024-3400", "CVE-2024-21762"])

   # Avoid: Individual requests in loop
   for cve_id in cve_ids:
       analysis = vuln_agent.analyze_cves([cve_id])  # Inefficient
   ```

2. **Cache Results:**
   ```python
   from functools import lru_cache

   @lru_cache(maxsize=128)
   def get_cve_details(cve_id: str):
       return nvd_client.get_cve(cve_id)
   ```

3. **Use LangSmith Tracing:**
   ```python
   os.environ['LANGSMITH_TRACING'] = 'true'
   # Automatic tracing for all agent calls
   ```

4. **Handle Pagination:**
   ```python
   all_incidents = []
   offset = 0
   while True:
       batch = snow_agent.get_incidents(limit=100, offset=offset)
       if not batch:
           break
       all_incidents.extend(batch)
       offset += 100
   ```

5. **Async for Performance:**
   ```python
   import asyncio

   async def analyze_multiple_cves(cve_ids):
       tasks = [agent.analyze_cve_async(cve) for cve in cve_ids]
       return await asyncio.gather(*tasks)
   ```

---

## Support & Resources

- **Documentation:** See `CLAUDE.md` for architecture and workflows
- **Examples:** `examples/basic_usage.py`, `examples/jupyter_demo.ipynb`
- **Tests:** `tests/` (812 passing tests, 67% coverage)
- **Deployment:** `docs/DEPLOYMENT_GUIDE.md`

**Version:** 1.0.0 | **License:** MIT | **Status:** ✅ Production-ready (Weeks 1-7)
