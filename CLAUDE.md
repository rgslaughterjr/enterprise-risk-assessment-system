# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Production multi-agent AI system for automated cybersecurity risk assessment. Built with LangGraph orchestration, integrating 6+ enterprise APIs (ServiceNow, NVD, VirusTotal, CISA KEV, MITRE ATT&CK, AlienVault OTX), advanced RAG pipeline with hybrid retrieval, and document intelligence (OCR, table extraction, ML classification).

**Current Status:** Weeks 1-7 complete and production-ready. Week 8-12 features are incomplete stubs.

## Common Commands

### Testing

```bash
# Run all passing tests (skip incomplete Week 8-12)
pytest tests/ -v --ignore=tests/security/ --ignore=tests/reasoning/ --ignore=tests/tools/test_week8_adapters.py

# Run with coverage
pytest --cov=src --cov-report=html --ignore=tests/security/ --ignore=tests/reasoning/ --ignore=tests/tools/test_week8_adapters.py

# Run specific test categories
pytest -m "not integration"  # Skip integration tests
pytest -m "not slow"         # Skip slow tests

# Run specific test file
pytest tests/test_servicenow_client.py -v

# Run Week 7 RAG tests
pytest tests/tools/test_semantic_chunker.py -v       # 58 tests
pytest tests/tools/test_hybrid_retriever.py -v       # 48 tests
pytest tests/tools/test_query_optimizer.py -v        # 49 tests

# Run Week 7 Document Intelligence tests
pytest tests/tools/test_ocr_processor.py -v          # 32 tests
pytest tests/tools/test_table_extractor.py -v        # 39 tests
pytest tests/tools/test_document_classifier.py -v    # 41 tests
pytest tests/tools/test_pptx_parser.py -v            # 33 tests
```

### Development

```bash
# Run demo scripts
python demo_full.py                      # Full system demo
python demo_document_intelligence.py     # Document intelligence demo
python examples/basic_usage.py           # Individual agent examples

# Check tool dependencies
python check_tools.py
```

### Environment Setup

```bash
# Virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Configure environment (.env required)
cp .env.example .env
# Add API keys for:
# - ANTHROPIC_API_KEY (Claude)
# - SERVICENOW_INSTANCE, SERVICENOW_USERNAME, SERVICENOW_PASSWORD
# - NVD_API_KEY, VIRUSTOTAL_API_KEY, ALIENVAULT_OTX_KEY
# - LANGSMITH_API_KEY (optional for tracing)
```

## Architecture

### Multi-Agent Orchestration (LangGraph)

The system uses a **supervisor pattern** where `src/supervisor/supervisor.py` coordinates 7 specialized agents in a sequential workflow:

```
User Query → Supervisor (LangGraph StateGraph)
    │
    ├─→ 1. ServiceNow Agent
    │      └─→ Query incidents, assets, CMDB (ServiceNow PDI)
    │
    ├─→ 2. Vulnerability Agent
    │      └─→ Analyze CVEs (NVD API, VirusTotal, CISA KEV)
    │
    ├─→ 3. Threat Agent
    │      └─→ Research threats (MITRE ATT&CK, AlienVault OTX)
    │
    ├─→ 4. Document Agent (Week 7)
    │      ├─→ RAG Pipeline: Hybrid retrieval (BM25 + semantic)
    │      ├─→ OCR: Extract text from scanned PDFs/images
    │      ├─→ Tables: Extract structured data from PDFs
    │      ├─→ Classify: ML-based document categorization
    │      └─→ Entity Extraction: CVEs, controls, assets, risks
    │
    ├─→ 5. Risk Scoring Agent
    │      └─→ FAIR-based 5×5 matrix (likelihood × impact)
    │
    └─→ 6. Report Agent
           └─→ Generate professional DOCX with charts
```

### Key Architectural Decisions

**1. Why LangGraph over plain LangChain?**
- Built-in state management with checkpointing
- Conditional routing based on workflow state
- Native support for parallel agent execution
- User check-ins between phases

**2. Why Hybrid RAG (0.9 semantic + 0.1 BM25)?**
- Semantic (0.9): Captures conceptual similarity ("vulnerability" ≈ "security flaw")
- BM25 (0.1): Exact keyword matches (CVE-2024-1234, NIST AC-1)
- **Result:** 25% improvement in Recall@5 vs pure semantic search (from Week 2 learning)

**3. Why ChromaDB over Pinecone?**
- Local-first development (no cloud dependency)
- Open source with permissive license
- Fast for <100K documents (our use case)
- Easy integration with sentence-transformers

## Core Components

### Agents (src/agents/)

All agents inherit LangChain tool calling pattern and expose both:
- `.query(user_input)` - Natural language interface
- `.analyze_*()` - Programmatic API

**servicenow_agent.py** (Week 6)
- Queries ServiceNow Personal Developer Instance (PDI)
- Tools: get_incidents, get_assets, get_exceptions
- Returns: ServiceNowIncident, CMDBItem models

**vulnerability_agent.py** (Week 6)
- Integrates NVD API v2.0, VirusTotal API v3, CISA KEV
- Calculates priority score (0-100) from CVSS + exploitation evidence
- Returns: VulnerabilityAnalysis with CVEDetail, ExploitationStatus

**threat_agent.py** (Week 6)
- MITRE ATT&CK technique mapping (691 techniques)
- AlienVault OTX threat intelligence (IOCs, pulses)
- Generates threat narrative
- Returns: ThreatIntelligence with techniques, IOCs, campaigns

**document_agent.py** (Week 7)
- **RAG Pipeline:**
  - Semantic chunking (5 strategies: fixed, sentence, paragraph, semantic, hybrid)
  - Hybrid retrieval (BM25 + semantic fusion)
  - Query optimization (expansion, rewriting, HyDE)
- **Document Intelligence:**
  - OCR for scanned PDFs/images (pytesseract)
  - Table extraction (PyMuPDF)
  - ML classification (TF-IDF + Naive Bayes)
  - PowerPoint parsing
- **Entity Extraction:** CVEs, controls, assets, risks, findings

**risk_scoring_agent.py** (Week 6)
- FAIR-based 5×5 risk matrix
- Likelihood factors: CVSS, exploitation, exposure, threat capability, controls
- Impact factors: Asset criticality, data sensitivity, business impact, compliance
- Returns: RiskRating (score 1-25, level Critical/High/Medium/Low)

**report_agent.py** (Week 6)
- Professional DOCX generation with python-docx
- Executive summary, risk heatmap, findings table, recommendations
- Matplotlib/seaborn visualizations

### Tools (src/tools/)

**External API Clients** (Week 6)
- `servicenow_client.py` - ServiceNow REST API
- `nvd_client.py` - National Vulnerability Database v2.0
- `virustotal_client.py` - VirusTotal API v3
- `cisa_kev_client.py` - CISA Known Exploited Vulnerabilities
- `otx_client.py` - AlienVault Open Threat Exchange
- `mitre_client.py` - MITRE ATT&CK framework

All implement retry logic (tenacity) and respect rate limits:
- NVD: 50 req/30s (with key), 5 req/30s (without)
- VirusTotal: 4 req/min (free tier)
- OTX: 10 req/sec

**Week 7 RAG Components**
- `semantic_chunker.py` - 5 chunking strategies with overlap management
- `hybrid_retriever.py` - BM25 (rank-bm25) + semantic (ChromaDB) fusion
- `query_optimizer.py` - Query expansion, rewriting, HyDE, caching

**Week 7 Document Intelligence**
- `ocr_processor.py` - Tesseract OCR with preprocessing (grayscale, contrast, denoising)
- `table_extractor.py` - PyMuPDF table detection, merged cell handling
- `document_classifier.py` - scikit-learn TF-IDF + Multinomial Naive Bayes (7 categories)
- `pptx_parser.py` - python-pptx slide/notes/table extraction
- `entity_extractor.py` - Regex-based NER for CVEs, controls, risks
- `relationship_mapper.py` - Entity relationship graph construction
- `sharepoint_simulator.py` - SharePoint integration testing

**Utilities**
- `document_parser.py` - Multi-format parser (PDF, DOCX, XLSX, PPTX, TXT, MD, CSV)
- `docx_generator.py` - Report generation with formatting/charts

### Data Models (src/models/schemas.py)

All models use Pydantic for validation:

```python
CVEDetail          # NVD data: cve_id, cvss_score, cvss_severity, description
ExploitationStatus # CISA KEV + VirusTotal: in_cisa_kev, vt_detections
ThreatIntelligence # MITRE techniques, IOCs, narrative, campaigns
RiskRating         # 5×5 matrix: likelihood (1-5), impact (1-5), score (1-25), level
RiskAssessmentReport # Complete report data for DOCX generation
```

### Supervisor Workflow (src/supervisor/supervisor.py)

LangGraph StateGraph with conditional routing:

```python
class SupervisorState(TypedDict):
    query: str
    cve_ids: List[str]
    incidents: List[Dict]
    vulnerabilities: List[Dict]
    threats: List[Dict]
    risk_ratings: List[Dict]
    report_path: str
    next_step: str
    completed: bool

# Build workflow
workflow = StateGraph(SupervisorState)
workflow.add_node("servicenow", servicenow_node)
workflow.add_node("vulnerability", vulnerability_node)
workflow.add_node("threat", threat_node)
workflow.add_node("risk_scoring", risk_scoring_node)
workflow.add_node("report", report_node)

# Conditional routing
workflow.add_conditional_edges("servicenow", route_next, {...})
```

## Week-by-Week Evolution

**Week 1-3:** Compliance RAG System (separate repo)
- ChromaDB vector store, semantic search, document ingestion

**Week 4:** ReAct Agent Framework (separate repo)
- Tool calling, reasoning-acting loop, multi-step planning

**Week 5:** LangGraph Orchestration (labs)
- Supervisor pattern, state management, conditional routing

**Week 6:** Multi-Agent Risk Assessment (this project)
- 6 core agents (ServiceNow, Vulnerability, Threat, Document, Risk Scoring, Report)
- 6 external API integrations
- LangGraph supervisor workflow
- FAIR-based 5×5 risk matrix
- Professional DOCX report generation
- **Tests:** 64/66 passing

**Week 7 Session 1:** Advanced RAG Foundation
- Semantic chunker: 5 strategies (fixed, sentence, paragraph, semantic, hybrid)
- Hybrid retriever: BM25 (0.1) + semantic (0.9) fusion
- Query optimizer: Expansion, rewriting, HyDE, caching
- **Tests:** 155 tests added, 100% pass rate, 79-81% coverage

**Week 7 Session 2:** Document Intelligence
- OCR processor: pytesseract + pdf2image for scanned PDFs
- Table extractor: PyMuPDF for complex table extraction
- Document classifier: ML-based (TF-IDF + Naive Bayes, 7 categories)
- PowerPoint parser: python-pptx for slide content
- **Tests:** 165 tests added, 100% pass rate, 79-94% coverage

**Week 7 Session 3:** SharePoint + Entity Extraction
- SharePoint simulator for integration testing
- Entity extractor: Regex NER for CVEs, controls, assets, risks
- Relationship mapper: Entity graph construction
- **Tests:** 60+ tests added

**Total Week 1-7:** 812 passing tests, 67% coverage

## Common Workflows

### Complete Risk Assessment

```python
from src.supervisor.supervisor import RiskAssessmentSupervisor

supervisor = RiskAssessmentSupervisor()
result = supervisor.run_assessment(
    query="Assess critical vulnerabilities in production environment",
    cve_ids=["CVE-2024-3400", "CVE-2024-21762"]
)

print(f"Analyzed {len(result['vulnerabilities'])} vulnerabilities")
print(f"Generated report: {result['report_path']}")
```

### Individual Agent Usage

See `examples/basic_usage.py` for comprehensive examples:

```python
# ServiceNow queries
from src.agents.servicenow_agent import ServiceNowAgent
agent = ServiceNowAgent()
incidents = agent.get_incidents_for_analysis(priority="1", limit=10)

# Vulnerability analysis
from src.agents.vulnerability_agent import VulnerabilityAgent
agent = VulnerabilityAgent()
analyses = agent.analyze_cves(["CVE-2024-3400"])

# Threat intelligence
from src.agents.threat_agent import ThreatAgent
agent = ThreatAgent()
threat_intel = agent.analyze_cve_threat("CVE-2024-3400", "OS command injection")

# Risk scoring
from src.agents.risk_scoring_agent import RiskScoringAgent
agent = RiskScoringAgent()
risk_rating = agent.calculate_risk(
    cve_id="CVE-2024-3400",
    asset_name="firewall-prod-01",
    cvss_score=10.0,
    in_cisa_kev=True,
    asset_criticality=5
)
```

### RAG Pipeline (Week 7)

```python
from src.tools.semantic_chunker import SemanticChunker
from src.tools.hybrid_retriever import HybridRetriever
from src.tools.query_optimizer import QueryOptimizer

# Chunk document with semantic strategy
chunker = SemanticChunker()
chunks = chunker.chunk_text(document_text, strategy="semantic")

# Hybrid retrieval (BM25 + semantic)
retriever = HybridRetriever()
retriever.add_documents(chunks)
results = retriever.retrieve(
    query="What are the authentication controls?",
    top_k=5,
    semantic_weight=0.9,  # Default from Week 2 learning
    keyword_weight=0.1
)

# Query optimization
optimizer = QueryOptimizer()
expanded = optimizer.expand_query("authentication controls")
# → "authentication controls login access identity verification"
```

### Document Intelligence (Week 7)

```python
from src.tools.document_parser import DocumentParser

parser = DocumentParser()

# OCR for scanned PDFs
text = parser.parse_scanned_pdf("scanned_audit_report.pdf")

# Extract tables
tables = parser.extract_tables("compliance_report.pdf")
# Returns: List[Dict] with headers and rows

# Classify document type
doc_type = parser.classify_document_type("security_policy.pdf")
# Returns: "policy_document" (7 categories)

# Parse PowerPoint
content = parser.parse_pptx("risk_presentation.pptx")
# Returns: Dict with slides, notes, tables, images
```

## Testing Strategy

### Test Structure

```
tests/
├── test_<component>.py        # Unit tests for agents/clients (64 tests)
├── tools/
│   ├── test_semantic_chunker.py       # 58 tests, 79% coverage
│   ├── test_hybrid_retriever.py       # 48 tests, 81% coverage
│   ├── test_query_optimizer.py        # 49 tests, 70% coverage
│   ├── test_ocr_processor.py          # 32 tests, 94% coverage
│   ├── test_table_extractor.py        # 39 tests, 83% coverage
│   ├── test_document_classifier.py    # 41 tests, 79% coverage
│   ├── test_pptx_parser.py            # 33 tests, 88% coverage
│   ├── test_entity_extractor.py       # 30+ tests
│   └── test_relationship_mapper.py    # 30+ tests
└── integration/
    └── # E2E workflow tests (20+ tests)
```

### Test Markers (pytest.ini)

- `@pytest.mark.integration` - E2E tests (skip with `-m "not integration"`)
- `@pytest.mark.slow` - Slow tests (skip with `-m "not slow"`)

### Mocking External APIs

All tests mock API calls to avoid rate limits and ensure deterministic results:

```python
@pytest.fixture
def mock_nvd_client(mocker):
    mock = mocker.patch("src.tools.nvd_client.NVDClient.get_cve")
    mock.return_value = CVEDetail(cve_id="CVE-2024-1234", cvss_score=9.8, ...)
    return mock
```

## Performance Metrics

- **RAG Pipeline:** p50=450ms, p95=1200ms, p99=2500ms
- **Throughput:** 50+ CVEs/minute
- **Test Coverage:** 67% overall (79-94% on Week 7 components)
- **Test Count:** 812 passing tests

## Environment Variables

Required in `.env`:

```bash
# LLM
ANTHROPIC_API_KEY=sk-ant-...

# ServiceNow PDI
SERVICENOW_INSTANCE=https://devXXXXX.service-now.com
SERVICENOW_USERNAME=admin
SERVICENOW_PASSWORD=...

# Threat Intelligence
NVD_API_KEY=...        # NIST National Vulnerability Database
VIRUSTOTAL_API_KEY=... # VirusTotal
ALIENVAULT_OTX_KEY=... # AlienVault Open Threat Exchange

# Optional Observability
LANGSMITH_API_KEY=...
LANGSMITH_TRACING=true
LANGSMITH_PROJECT=enterprise-risk-assessment
```

## Key Dependencies

See `requirements.txt` for full list. Critical dependencies:

**AI/ML Framework:**
- langchain==1.0.5 - Agent framework, tool calling
- langgraph==1.0.3 - Multi-agent orchestration
- langchain-anthropic==1.0.2 - Claude integration
- anthropic==0.72.0 - Claude API

**RAG Stack:**
- chromadb==1.3.4 - Vector database
- sentence-transformers==5.1.2 - Embeddings
- rank-bm25==0.2.2 - BM25 keyword search

**Document Intelligence:**
- pytesseract - OCR (requires Tesseract system installation)
- pdf2image - PDF to image conversion
- PyMuPDF (fitz) - Advanced PDF table extraction
- python-pptx - PowerPoint parsing
- scikit-learn==1.7.2 - TF-IDF, Naive Bayes classifier

**Document Processing:**
- python-docx==1.2.0 - DOCX generation
- pypdf==6.1.3 - PDF parsing
- openpyxl==3.1.5 - Excel parsing
- beautifulsoup4==4.14.2 - HTML parsing

**Utilities:**
- tenacity==9.1.2 - Retry logic
- pydantic==2.12.4 - Data validation
- matplotlib==3.10.7, seaborn==0.13.2 - Visualizations

## Incomplete Features (Week 8-12 Stubs)

These directories contain incomplete implementations and should be ignored:

- `src/security/` - Input validation, output filtering (incomplete)
- `src/monitoring/` - Observer, cost tracker (incomplete)
- `src/reasoning/` - Tree of Thought, Markov chains (incomplete)
- `src/frameworks/` - NIST AI RMF, OCTAVE (incomplete)
- `src/deployment/` - AWS Bedrock adapter (incomplete)
- `infrastructure/cloudformation/` - AWS deployment (incomplete)
- `docker/` - Containerization (incomplete)
- `tests/security/`, `tests/reasoning/` - Incomplete test files

Run tests with: `pytest --ignore=tests/security/ --ignore=tests/reasoning/ --ignore=tests/tools/test_week8_adapters.py`

## Project Statistics (Week 1-7)

- **Code:** 5,000+ lines of production Python
- **Tests:** 812 passing tests
- **Coverage:** 67% overall (79-94% on RAG components)
- **API Integrations:** 6+ external APIs (ServiceNow, NVD, VirusTotal, CISA KEV, MITRE, OTX)
- **Agents:** 7 specialized agents (6 core + document intelligence)
- **Frameworks:** LangGraph, LangChain, ChromaDB, scikit-learn
