# Enterprise Risk Assessment System

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![Tests](https://img.shields.io/badge/tests-64%2F66%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-29%25-yellow)

Production-ready multi-agent system for automated cybersecurity risk assessment with real API integrations.

## Overview

Multi-agent orchestration system that automates comprehensive risk assessment workflows by:

- **ServiceNow Integration** - Querying incidents, assets, and security exceptions
- **Vulnerability Analysis** - Analyzing CVEs using NVD, VirusTotal, and CISA KEV
- **Threat Intelligence** - Researching threats via MITRE ATT&CK and AlienVault OTX
- **Document Processing** - Extracting findings from PDF, DOCX, and XLSX files
- **Risk Scoring** - Calculating FAIR-based risk ratings (5×5 matrix)
- **Report Generation** - Creating professional DOCX reports with visualizations

**Built as part of 12-week AI Agent Development Curriculum (Week 6: Project 2)**

## 🚀 Week 7 Session 1: Advanced RAG Foundation

**Date:** November 15, 2025

Transformed the Document Agent into an enterprise-grade RAG system with:

### New Components

1. **Semantic Chunker** (`src/tools/semantic_chunker.py`)
   - 5 chunking strategies: Fixed-size, Sentence-based, Paragraph-based, Semantic similarity, Hybrid
   - Intelligent overlap management for context preservation
   - Metadata tracking (chunk_id, strategy, source)
   - **58 comprehensive tests** with **79% coverage**

2. **Hybrid Retriever** (`src/tools/hybrid_retriever.py`)
   - BM25 keyword search + semantic vector search fusion
   - **0.9 semantic weight + 0.1 keyword weight** (from Week 2 learning)
   - Score normalization and weighted fusion
   - ChromaDB integration for semantic search
   - **48 comprehensive tests** with **81% coverage**

3. **Query Optimizer** (`src/tools/query_optimizer.py`)
   - Query expansion with domain synonyms
   - Query rewriting (technical, formal styles)
   - Multi-query generation (3 variations)
   - HyDE (Hypothetical Document Embeddings)
   - Query caching for performance
   - **49 comprehensive tests** with **70% coverage**

4. **Enhanced Document Parser** (`src/tools/document_parser.py`)
   - Added support for: `.txt`, `.md` (markdown), `.csv` files
   - Document classification (security_report, risk_assessment, audit_report, etc.)
   - Automated tagging (vulnerability-management, network-security, compliance, etc.)
   - Confidence scoring for parsed documents

### Test Metrics

- **Total Tests Added:** 155 tests (exceeds 90+ requirement)
- **Pass Rate:** 100% (155/155 passing)
- **Coverage:**
  - semantic_chunker.py: 79%
  - hybrid_retriever.py: 81%
  - query_optimizer.py: 70%
- **Test Files:**
  - `tests/tools/test_semantic_chunker.py` (58 tests)
  - `tests/tools/test_hybrid_retriever.py` (48 tests)
  - `tests/tools/test_query_optimizer.py` (49 tests)

### Key Learnings Applied

- **Week 2:** 0.9/0.1 semantic/keyword weight ratio for optimal hybrid search
- **Production-Ready:** Comprehensive error handling, logging, caching
- **Testing:** 100% pass rate with edge case coverage, integration tests

### Technical Highlights

- Jaccard similarity for semantic chunking (no external dependencies)
- BM25Okapi for keyword search (rank-bm25 library)
- Min-max score normalization for fair fusion
- Template-based HyDE for query augmentation
- Domain-specific synonym expansion (cybersecurity terms)

## Architecture

### Multi-Agent System

```
User Query → Supervisor Orchestrator (LangGraph)
    ↓
    ├── ServiceNow Query Agent → Incidents & Assets
    ├── Vulnerability Analysis Agent → CVE Details & Exploitation Status
    ├── Threat Research Agent → MITRE ATT&CK & Threat Intelligence
    ├── Document Ingestion Agent → PDF/DOCX/XLSX Parsing
    ├── Risk Scoring Agent → FAIR-based 5×5 Matrix
    └── Report Generator → Professional DOCX Reports
    ↓
Risk Assessment Report (DOCX)
```

### Technology Stack

- **LLM:** Claude 3.5 Sonnet (Anthropic)
- **Orchestration:** LangGraph (supervisor pattern with user check-ins)
- **Agent Framework:** LangChain tool calling + ReAct pattern
- **Observability:** LangSmith distributed tracing
- **Document Processing:** python-docx, pypdf, openpyxl
- **Visualization:** matplotlib, seaborn

### Real API Integrations

- **ServiceNow PDI** - Personal Developer Instance for ITSM data
- **NVD API** - National Vulnerability Database (CVE details, CVSS scores)
- **VirusTotal API** - Malware detection and exploitation evidence
- **CISA KEV** - Known Exploited Vulnerabilities catalog
- **AlienVault OTX** - Open Threat Exchange (threat intelligence, IOCs)
- **MITRE ATT&CK** - Adversarial tactics and techniques framework

## Project Structure

```
enterprise-risk-assessment-system/
├── src/
│   ├── agents/                  # 6 Specialized Agents
│   │   ├── servicenow_agent.py      # ServiceNow query agent
│   │   ├── vulnerability_agent.py   # Vulnerability analysis (NVD/VT/KEV)
│   │   ├── threat_agent.py          # Threat intelligence (MITRE/OTX)
│   │   ├── document_agent.py        # Document parsing (PDF/DOCX/XLSX)
│   │   ├── risk_scoring_agent.py    # FAIR-based risk scoring
│   │   └── report_agent.py          # DOCX report generation
│   ├── supervisor/              # LangGraph Orchestration
│   │   └── supervisor.py            # Multi-agent workflow coordinator
│   ├── tools/                   # External API Clients
│   │   ├── servicenow_client.py     # ServiceNow REST API
│   │   ├── nvd_client.py            # NVD API v2.0
│   │   ├── virustotal_client.py     # VirusTotal API v3
│   │   ├── cisa_kev_client.py       # CISA KEV catalog
│   │   ├── otx_client.py            # AlienVault OTX API
│   │   ├── mitre_client.py          # MITRE ATT&CK framework
│   │   ├── document_parser.py       # Multi-format document parser
│   │   └── docx_generator.py        # Report generator
│   ├── models/                  # Data Models
│   │   └── schemas.py               # Pydantic models for state management
│   └── utils/                   # Utilities
│       └── error_handler.py         # Error handling & retry logic
├── tests/                       # Test Suite
│   ├── test_servicenow_client.py
│   ├── test_vulnerability_agent.py
│   └── ...
├── examples/                    # Usage Examples
│   └── basic_usage.py               # Comprehensive usage examples
├── reports/                     # Generated Reports (gitignored)
├── .env.example                 # Environment template
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## Setup

### Prerequisites

- **Python 3.11+**
- **API Keys for:**
  - Anthropic Claude API
  - ServiceNow Personal Developer Instance (PDI)
  - NVD API (NIST)
  - VirusTotal API
  - AlienVault OTX API
  - LangSmith (optional, for tracing)

### Installation

```bash
# Clone repository
git clone https://github.com/rgslaughterjr/enterprise-risk-assessment-system.git
cd enterprise-risk-assessment-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Environment Variables

```bash
# LLM
ANTHROPIC_API_KEY=your_anthropic_key_here

# Observability (optional)
LANGSMITH_API_KEY=your_langsmith_key_here
LANGSMITH_TRACING=true
LANGSMITH_PROJECT=enterprise-risk-assessment

# ServiceNow Personal Developer Instance
SERVICENOW_INSTANCE=https://devXXXXX.service-now.com
SERVICENOW_USERNAME=admin
SERVICENOW_PASSWORD=your_password_here

# Threat Intelligence APIs
NVD_API_KEY=your_nvd_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ALIENVAULT_OTX_KEY=your_otx_key_here
```

## Usage

### Complete Workflow with Supervisor

```python
from src.supervisor.supervisor import RiskAssessmentSupervisor

# Initialize supervisor
supervisor = RiskAssessmentSupervisor()

# Run complete risk assessment
result = supervisor.run_assessment(
    query="Assess critical vulnerabilities in production environment",
    cve_ids=["CVE-2024-3400", "CVE-2024-21762"]
)

# Access results
print(f"Analyzed: {len(result['vulnerabilities'])} vulnerabilities")
print(f"Risk Ratings: {len(result['risk_ratings'])}")
print(f"Report: {result['report_path']}")
```

### Individual Agent Usage

#### 1. ServiceNow Query Agent

```python
from src.agents.servicenow_agent import ServiceNowAgent

agent = ServiceNowAgent()

# Natural language query
response = agent.query("Show me all critical priority incidents")

# Programmatic access
incidents = agent.get_incidents_for_analysis(priority="1", limit=10)
assets = agent.get_assets_for_analysis(limit=20)
```

#### 2. Vulnerability Analysis Agent

```python
from src.agents.vulnerability_agent import VulnerabilityAgent

agent = VulnerabilityAgent()

# Analyze CVEs
analyses = agent.analyze_cves(["CVE-2024-3400", "CVE-2024-21762"])

for analysis in analyses:
    print(f"{analysis.cve_detail.cve_id}: {analysis.cve_detail.cvss_severity}")
    print(f"In CISA KEV: {analysis.exploitation_status.in_cisa_kev}")
    print(f"Priority: {analysis.priority_score}/100")
```

#### 3. Threat Research Agent

```python
from src.agents.threat_agent import ThreatAgent

agent = ThreatAgent()

# Research threat intelligence
threat_intel = agent.analyze_cve_threat(
    "CVE-2024-3400",
    "OS command injection in PAN-OS management interface"
)

print(f"MITRE Techniques: {len(threat_intel.techniques)}")
print(f"IOCs: {sum(len(v) for v in threat_intel.iocs.values())}")
```

#### 4. Risk Scoring Agent

```python
from src.agents.risk_scoring_agent import RiskScoringAgent

agent = RiskScoringAgent()

# Calculate risk rating
risk_rating = agent.calculate_risk(
    cve_id="CVE-2024-3400",
    asset_name="firewall-prod-01",
    cvss_score=10.0,
    in_cisa_kev=True,
    vt_detections=15,
    asset_criticality=5
)

print(f"Risk Level: {risk_rating.risk_level}")
print(f"Risk Score: {risk_rating.risk_score}/25")
```

#### 5. Report Generator

```python
from src.agents.report_agent import ReportAgent
from src.models.schemas import RiskAssessmentReport

agent = ReportAgent()

# Generate comprehensive report
report_path = agent.generate_report(
    report_data=report_data,
    output_path="reports/my_assessment.docx"
)

print(f"Report saved to: {report_path}")
```

## Features

### 1. ServiceNow Integration
- Query incidents by priority, state, or custom filters
- Search CMDB for assets (servers, databases, network devices)
- Retrieve security exceptions and risk acceptances
- Create new incidents programmatically

### 2. Vulnerability Analysis
- **NVD Integration:** CVSS scores, affected products, CVE descriptions
- **VirusTotal:** Malware sample detection, exploitation evidence
- **CISA KEV:** Known exploited vulnerabilities (prioritization)
- **Priority Scoring:** 0-100 scale combining severity + exploitation

### 3. Threat Intelligence
- **MITRE ATT&CK:** Map CVEs to tactics and techniques
- **AlienVault OTX:** Threat feeds, IOCs, campaign intelligence
- **Threat Narratives:** Auto-generated threat summaries
- **Technique Research:** Search by keyword, tactic, or threat actor

### 4. Document Processing
- **Multi-Format:** PDF, DOCX, XLSX support
- **Entity Extraction:** CVEs, controls, assets, risks, findings
- **Metadata Parsing:** Author, dates, page counts
- **Batch Processing:** Handle multiple documents

### 5. Risk Scoring (FAIR-based 5×5)
- **Likelihood Dimensions:** CVE severity, exploitation, asset exposure, threat capability, controls
- **Impact Dimensions:** Asset criticality, data sensitivity, business impact, compliance, operations
- **Risk Levels:** Critical (20-25), High (15-19), Medium (8-14), Low (1-7)
- **Detailed Justifications:** Explain every score component

### 6. Professional Reports
- **Executive Summary:** High-level overview with key metrics
- **Risk Heatmap:** Visual risk distribution chart
- **Findings Table:** Comprehensive vulnerability listing
- **Detailed Analysis:** CVE details, exploitation status, threat intelligence
- **Recommendations:** Prioritized remediation actions
- **Appendices:** Methodology, definitions, references

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_servicenow_client.py -v
```

## Development Progress

**Week 6 Labs: ✓ Complete**

- ✅ Lab 6.1: ServiceNow PDI Setup & Testing
- ✅ Lab 6.2: ServiceNow Query Agent
- ✅ Lab 6.3: Vulnerability Analysis Agent
- ✅ Lab 6.4: Threat Research Agent
- ✅ Lab 6.5: Document Ingestion Agent
- ✅ Lab 6.6: Risk Scoring Agent
- ✅ Lab 6.7: Report Generator Agent
- ✅ Lab 6.8: Supervisor Orchestrator (LangGraph)

## API Rate Limits

Be aware of rate limits when using external APIs:

- **NVD:** 5 requests/30s (no key), 50 requests/30s (with key)
- **VirusTotal:** 4 requests/min (free tier)
- **AlienVault OTX:** 10 requests/sec
- **ServiceNow PDI:** No documented limits

The system implements automatic rate limiting and exponential backoff retry logic.

## Examples

See `examples/basic_usage.py` for comprehensive usage examples including:
- Individual agent demonstrations
- Complete workflow execution
- Error handling patterns
- Result processing

## Related Projects

Part of 12-week AI Agent Development Curriculum:

- **Week 1-3:** [Compliance RAG System](https://github.com/rgslaughterjr/compliance-rag-system) - Production RAG with ChromaDB
- **Week 4:** [ReAct Agent Framework](https://github.com/rgslaughterjr/react-agent-framework) - Multi-tool agent foundation
- **Week 5:** LangGraph Orchestration (labs) - Supervisor patterns
- **Week 6:** Enterprise Risk Assessment (this project) - Multi-agent production system

## Portfolio Highlights

**Resume Bullets:**
- Built production multi-agent risk assessment system integrating 6 external APIs (ServiceNow, NVD, VirusTotal, CISA KEV, MITRE ATT&CK, AlienVault OTX) with LangGraph orchestration
- Implemented 7 specialized agents using LangChain tool calling and ReAct pattern for vulnerability analysis, threat research, and automated FAIR-based risk scoring
- Developed automated DOCX report generation with professional formatting, visualizations, and executive summaries for cybersecurity risk assessments

**Technical Skills Demonstrated:**
- Multi-agent orchestration with LangGraph
- RESTful API integration and rate limiting
- Error handling and retry logic (tenacity)
- Pydantic data validation and state management
- Document processing (PDF, DOCX, XLSX)
- Report generation with python-docx and matplotlib
- Test-driven development with pytest
- Production-ready code with comprehensive logging

## Contributing

This is a learning project. For questions or improvements, open an issue or PR.

## License

MIT License

## Author

**Richard Slaughter**
Lead Cybersecurity Risk Analyst (CRISC certified)
Learning AI Agent Development for Senior Engineering Roles

**Contact:** Via GitHub issues

---

**Acknowledgments:** Built using Anthropic's Claude API, LangChain framework, and various open-source security data sources.
