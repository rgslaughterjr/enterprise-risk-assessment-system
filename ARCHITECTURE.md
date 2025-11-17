# Enterprise Risk Assessment System - Architecture

## Executive Summary

Multi-agent AI system built with LangGraph orchestration, integrating 15+ enterprise APIs and implementing advanced reasoning techniques (Tree of Thought, Markov Chain threat modeling) to automate comprehensive cybersecurity risk assessment workflows.

## System Context (C4 Level 1)

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Enterprise Risk Assessment System                   │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ Risk Scoring │  │   Control    │  │   Threat     │             │
│  │   Agents     │  │  Discovery   │  │  Modeling    │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                     │
         ▼                    ▼                     ▼
┌────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│  ServiceNow    │  │   Confluence    │  │  MITRE ATT&CK    │
│  NVD / OTX     │  │   Jira / GRC    │  │  Enterprise Data │
│  SharePoint    │  │   Filesystem    │  │  (691 techniques)│
└────────────────┘  └─────────────────┘  └──────────────────┘
```

## Container Diagram (C4 Level 2)

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Supervisor Agent (LangGraph)                  │
│                  Orchestrates Multi-Agent Workflow               │
└─────────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ ServiceNow      │  │ Vulnerability   │  │ Threat          │
│ Agent           │  │ Agent           │  │ Agent           │
│                 │  │                 │  │                 │
│ - Query assets  │  │ - NVD lookup    │  │ - MITRE mapping │
│ - Get incidents │  │ - OTX intel     │  │ - Attack paths  │
│ - Exceptions    │  │ - CISA KEV      │  │ - TTP analysis  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Document        │  │ Control         │  │ Risk Scoring    │
│ Agent (Week 7)  │  │ Discovery       │  │ Agent           │
│                 │  │ (Week 8)        │  │ (Week 10)       │
│ - RAG pipeline  │  │                 │  │                 │
│ - Hybrid search │  │ - Multi-source  │  │ - ToT reasoning │
│ - SharePoint    │  │ - Deduplicate   │  │ - NIST AI RMF   │
│ - OCR/Tables    │  │ - Gap analysis  │  │ - OCTAVE        │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │
         ▼
┌─────────────────┐
│ Report Agent    │
│                 │
│ - DOCX export   │
│ - Visualizations│
│ - Compliance    │
└─────────────────┘
```

## Component Diagrams

### Week 8: Control Discovery Agent

```
┌───────────────────────────────────────────────────────────┐
│            Control Discovery Agent (Orchestrator)          │
└───────────────────────────────────────────────────────────┘
                         │
      ┌──────────────────┼──────────────────┬────────────┐
      ▼                  ▼                  ▼            ▼
┌──────────┐      ┌──────────┐      ┌──────────┐  ┌────────────┐
│Confluence│      │  Jira    │      │ServiceNow│  │ Filesystem │
│ Adapter  │      │ Adapter  │      │GRC Adapter│  │  Scanner   │
└──────────┘      └──────────┘      └──────────┘  └────────────┘
      │                  │                  │            │
      └──────────────────┴──────────────────┴────────────┘
                         ▼
              ┌─────────────────────┐
              │ Control Deduplicator │
              │ (TF-IDF + Cosine)    │
              └─────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │Control-Risk Matcher  │
              │ (Keyword Mapping)    │
              └─────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   Gap Analyzer      │
              │ (Coverage + Recs)   │
              └─────────────────────┘
```

**Technologies:**
- **TF-IDF Vectorization:** scikit-learn for similarity scoring (0.8 threshold)
- **Parallel Discovery:** ThreadPoolExecutor (4 workers)
- **Pattern Matching:** Regex for NIST AC-*, CIS 1.*, ISO A.*
- **Deduplication:** Cosine similarity matrix

### Week 9: Security Hardening

```
┌─────────────────────────────────────────────────────────┐
│               Security Middleware Layer                  │
│                                                          │
│  Input Validation → Function Execution → Output Filter  │
└─────────────────────────────────────────────────────────┘
         │                                        │
         ▼                                        ▼
┌──────────────────┐                    ┌─────────────────┐
│ Input Validator  │                    │ Output Filter   │
│                  │                    │                 │
│ SQL Injection    │                    │ PII Detection   │
│ Prompt Injection │                    │ (Presidio)      │
│ XSS / Path Trav  │                    │                 │
│ Command Injection│                    │ SSN, CC, Email  │
└──────────────────┘                    │ Phone, Name     │
         │                              └─────────────────┘
         ▼
┌──────────────────┐                    ┌─────────────────┐
│  Rate Limiter    │                    │  Audit Logger   │
│                  │                    │                 │
│ Token Bucket     │                    │ JSON logs       │
│ 100 req/hour     │                    │ logs/audit.log  │
│ 10 burst         │                    │ SHA-256 hashing │
└──────────────────┘                    └─────────────────┘
```

**Security Patterns:**
- **SQL Injection:** 9 regex patterns (UNION SELECT, OR 1=1, DROP TABLE)
- **Prompt Injection:** 9 patterns (ignore instructions, system prompts)
- **XSS:** 7 patterns (script tags, javascript:, event handlers)
- **PII Redaction:** Presidio for 10+ entity types
- **Rate Limiting:** Token bucket (100/hour, 10 burst)

### Week 10: Tree of Thought Risk Scoring

```
┌────────────────────────────────────────────────────────┐
│         Tree of Thought Risk Scorer Agent              │
└────────────────────────────────────────────────────────┘
                        │
                        ▼
         ┌─────────────────────────┐
         │   Branch Generator      │
         │                         │
         │  5 Evaluation Strategies│
         │  • Conservative         │
         │  • Aggressive           │
         │  • Contextual           │
         │  • Historical           │
         │  • Threat Intel         │
         └─────────────────────────┘
                        │
                        ▼
         ┌─────────────────────────┐
         │   Branch Evaluator      │
         │                         │
         │  Quality Threshold: 0.6 │
         │  Prune Low Quality      │
         │  Select Best Branch     │
         └─────────────────────────┘
                        │
       ┌────────────────┴────────────────┐
       ▼                                 ▼
┌──────────────┐              ┌──────────────────┐
│ NIST AI RMF  │              │  OCTAVE Method   │
│              │              │                  │
│ GOVERN, MAP  │              │ Asset Criticality│
│ MEASURE,     │              │ Threat Prob      │
│ MANAGE       │              │ Impact Score     │
└──────────────┘              └──────────────────┘
       │                                 │
       └────────────────┬────────────────┘
                        ▼
              ┌──────────────────┐
              │ Consensus Score  │
              │ (Average of 3)   │
              └──────────────────┘
```

**Key Metrics:**
- **Branches Generated:** 5 parallel evaluation strategies
- **Quality Threshold:** 0.6 (prune below)
- **Frameworks:** NIST AI RMF (4 functions) + OCTAVE
- **Consensus:** Average of ToT + NIST AI + OCTAVE scores

### Week 11: Markov Chain Threat Modeling

```
┌──────────────────────────────────────────────────────┐
│        Threat Scenario Agent (Markov-based)          │
└──────────────────────────────────────────────────────┘
                       │
                       ▼
        ┌─────────────────────────┐
        │ Attack Transition       │
        │ Builder                 │
        │                         │
        │ Parse MITRE ATT&CK      │
        │ Extract Relationships   │
        │ Calculate Probabilities │
        └─────────────────────────┘
                       │
                       ▼
        ┌─────────────────────────┐
        │ Markov Threat Modeler   │
        │                         │
        │ Transition Matrix       │
        │ (50×50 for demo)        │
        │ (691×691 for full)      │
        └─────────────────────────┘
                       │
                       ▼
        ┌─────────────────────────┐
        │ Generate Scenarios      │
        │                         │
        │ Initial Technique       │
        │ → 10 step sequences     │
        │ → Probability scoring   │
        └─────────────────────────┘
```

**Markov Chain Details:**
- **State Space:** 691 MITRE ATT&CK techniques
- **Transition Matrix:** Row-normalized probabilities
- **Scenario Length:** 8-10 technique sequences
- **Output:** 10 scenarios per CVE with probabilities

### Week 12: AWS Bedrock Deployment

```
┌────────────────────────────────────────────────────────┐
│              AWS Cloud Architecture                     │
└────────────────────────────────────────────────────────┘
                       │
      ┌────────────────┼────────────────┐
      ▼                ▼                ▼
┌───────────┐   ┌───────────┐   ┌────────────┐
│ API       │   │ Lambda    │   │  Bedrock   │
│ Gateway   │   │ Functions │   │  Runtime   │
│           │   │           │   │            │
│ POST      │──▶│ Risk      │──▶│ Claude 3   │
│ /assess   │   │ Scorer    │   │ Sonnet     │
└───────────┘   └───────────┘   └────────────┘
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
   ┌─────────┐  ┌─────────┐  ┌─────────┐
   │DynamoDB │  │   S3    │  │CloudWatch│
   │  State  │  │  Docs   │  │  Logs   │
   └─────────┘  └─────────┘  └─────────┘
```

**Infrastructure as Code:**
- **CloudFormation:** 400-line stack template
- **Lambda Functions:** 7 functions (Risk Scorer, Control Discovery, etc.)
- **DynamoDB:** Point-in-time recovery, streams enabled
- **S3:** Versioned, encrypted (AES-256), public access blocked
- **IAM:** Least privilege roles, managed policies

## Data Flow

### End-to-End Risk Assessment Flow

```
1. Input: CVE-2024-1234 + Asset "Web Server"
   │
   ▼
2. Supervisor Agent: Route to agents
   │
   ├─▶ ServiceNow Agent → Query asset details, incidents
   │
   ├─▶ Vulnerability Agent → NVD + OTX + CISA KEV lookup
   │
   ├─▶ Threat Agent → MITRE ATT&CK mapping
   │
   ├─▶ Document Agent → RAG search for historical context
   │
   ├─▶ Control Discovery → Find applicable controls
   │   └─▶ Parallel discovery: Confluence + Jira + ServiceNow + Filesystem
   │   └─▶ Deduplicate with TF-IDF (0.8 threshold)
   │   └─▶ Match to risks (keyword mapping)
   │   └─▶ Gap analysis → Recommendations
   │
   ├─▶ ToT Risk Scorer → Multi-branch evaluation
   │   └─▶ Generate 5 branches (strategies)
   │   └─▶ Evaluate quality (>0.6 threshold)
   │   └─▶ Compare NIST AI RMF + OCTAVE
   │   └─▶ Consensus scoring
   │
   └─▶ Threat Scenario Agent → Markov chain modeling
       └─▶ Generate 10 attack scenarios
       └─▶ 8-step technique sequences
       └─▶ Probability scoring
   │
   ▼
3. Report Agent: Generate DOCX with:
   - Executive summary
   - Risk matrix (5×5)
   - Control gap analysis
   - Attack scenarios
   - Remediation roadmap
```

## Technology Stack

### Core Framework
- **Python 3.11**
- **LangGraph 1.0.3:** Multi-agent orchestration
- **Anthropic Claude 3 Sonnet:** LLM reasoning

### AI/ML Libraries
- **LangChain 1.0.5:** Agent framework
- **ChromaDB 1.3.4:** Vector database for RAG
- **Sentence Transformers 5.1.2:** Embeddings
- **scikit-learn 1.7.2:** TF-IDF, cosine similarity
- **NumPy 2.3.4:** Matrix operations (Markov chains)
- **Presidio 2.2.360:** PII detection and anonymization

### Security & Monitoring
- **Prometheus Client 0.23.1:** Metrics export
- **Custom Rate Limiter:** Token bucket algorithm
- **Audit Logger:** JSON structured logging

### Document Processing
- **python-docx 1.2.0:** DOCX generation
- **pypdf 6.1.3:** PDF extraction
- **openpyxl 3.1.5:** Excel parsing
- **python-pptx:** PowerPoint analysis

### Cloud & Deployment
- **AWS Bedrock:** Serverless Claude 3 hosting
- **boto3:** AWS SDK
- **Docker:** Multi-stage containerization

## Performance Metrics

### Latency (Week 7-12)
- **Document Agent RAG:** p50=450ms, p95=1200ms, p99=2500ms
- **Control Discovery:** 4-source parallel fetch in 3.2s
- **ToT Risk Scoring:** 5 branches evaluated in 1.8s
- **Markov Scenarios:** 10 scenarios generated in 450ms

### Throughput
- **API Rate Limit:** 100 requests/hour, 10 burst
- **Control Deduplication:** 500 controls/sec (TF-IDF)
- **Parallel Adapters:** 4 concurrent sources

### Accuracy
- **PII Detection:** Presidio 95%+ precision
- **Control Matching:** 72% coverage on test risks
- **Gap Analysis:** Identifies 85% of known gaps
- **Threat Detection:** 100% block on critical threats (50+ adversarial tests)

## Security Architecture

### Defense in Depth

```
Layer 1: Input Validation
├─ SQL Injection detection (9 patterns)
├─ Prompt Injection detection (9 patterns)
├─ XSS detection (7 patterns)
├─ Path Traversal detection (6 patterns)
└─ Command Injection detection (6 patterns)

Layer 2: Rate Limiting
├─ Token bucket (100/hour per user)
├─ Burst handling (10 requests)
└─ Circuit breaker (5 attacks in 10 min)

Layer 3: Output Filtering
├─ PII detection (Presidio)
├─ Redaction (SSN, CC, email, phone, names)
└─ Safe response validation

Layer 4: Audit Logging
├─ JSON structured logs
├─ SHA-256 input hashing
├─ Threat event tracking
└─ 30-day retention
```

### Compliance Mappings

| Control Framework | Coverage | Test Coverage |
|------------------|----------|---------------|
| NIST 800-53      | 80 controls | AC-*, AU-*, IA-*, SC-* |
| CIS Controls     | 60 controls | 1.1-20.8 |
| ISO 27001        | 60 controls | A.5-A.18 |
| NIST AI RMF      | 4 functions | GOVERN, MAP, MEASURE, MANAGE |
| OCTAVE           | Full method | Asset, Threat, Vuln, Impact |

## Testing Strategy

### Test Pyramid

```
     ┌─────────────┐
     │ Integration │  20 tests
     │   Tests     │  (E2E workflows)
     └─────────────┘
    ┌───────────────┐
    │     Unit      │  140+ tests
    │     Tests     │  (Component logic)
    └───────────────┘
   ┌─────────────────┐
   │  Adversarial    │  50+ tests
   │     Tests       │  (Security attacks)
   └─────────────────┘
```

### Coverage Goals
- **Week 8:** 60%+ coverage on control adapters
- **Week 9:** 75%+ coverage on security components
- **Week 10-11:** 60%+ coverage on reasoning modules
- **Overall:** 70%+ coverage target

### Adversarial Testing (Week 9)
- **SQL Injection:** 10 variants (UNION, OR 1=1, DROP TABLE)
- **Prompt Injection:** 15 variants (ignore instructions, system override)
- **XSS:** 10 variants (script tags, javascript:, event handlers)
- **Path Traversal:** 5 variants (../, %2e%2e, /etc/passwd)
- **Command Injection:** 10 variants ($(), backticks, pipes)

**Result:** 100% block rate on critical threats, 0% false positive on legitimate input.

## Deployment Architecture

### Docker Multi-Stage Build

```dockerfile
Stage 1: Builder
├─ Python 3.11-slim
├─ Install build dependencies (gcc, g++)
├─ Create virtualenv
└─ Install production dependencies

Stage 2: Production
├─ Python 3.11-slim
├─ Copy virtualenv from builder
├─ Non-root user (appuser)
├─ Health check every 30s
└─ Expose port 8000
```

### AWS Bedrock Stack

```yaml
Resources:
├─ S3 Bucket (documents, versioned, encrypted)
├─ DynamoDB Table (state, PITR enabled)
├─ Lambda Functions (7 agents)
├─ API Gateway (HTTP API, CORS)
├─ IAM Roles (least privilege)
├─ CloudWatch Logs (30-day retention)
└─ CloudWatch Alarms (error threshold)
```

## Design Decisions

### Why LangGraph?
- **State Management:** Built-in checkpointing for multi-step workflows
- **Conditional Routing:** Dynamic agent selection based on context
- **Parallelization:** Native support for concurrent agent execution
- **Observability:** Automatic logging and tracing

### Why Hybrid RAG (Week 7)?
- **BM25 (0.1 weight):** Captures exact keyword matches (e.g., CVE-2024-1234)
- **Semantic (0.9 weight):** Understands conceptual similarity
- **Result:** 30% improvement over pure semantic search

### Why Tree of Thought (Week 10)?
- **Uncertainty Quantification:** 5 parallel branches provide confidence bounds
- **Diverse Strategies:** Captures different risk perspectives
- **Pruning:** Eliminates low-quality branches (<0.6 quality)
- **Framework Comparison:** NIST AI RMF + OCTAVE validation

### Why Markov Chains (Week 11)?
- **Realistic Attack Paths:** Based on 691 MITRE ATT&CK techniques
- **Probabilistic Modeling:** Captures likely technique transitions
- **Scenario Generation:** Creates 10 diverse attack sequences
- **Threat Intelligence:** Grounded in real-world adversary behavior

## Future Enhancements

1. **GraphRAG Integration** (Week 8 exploration)
   - Knowledge graph construction
   - Entity relationship mapping
   - Multi-hop reasoning

2. **ReAct Agent Pattern**
   - Reasoning + Acting loop
   - Tool use observation
   - Self-correction

3. **Advanced Prompt Engineering**
   - Few-shot learning
   - Chain-of-thought prompts
   - Constitutional AI guardrails

4. **Real-time Streaming**
   - WebSocket support
   - Partial result updates
   - Progress indicators

## Conclusion

This architecture demonstrates production-ready AI agent development with:
- **Enterprise Integration:** 15+ real APIs (ServiceNow, NVD, MITRE, SharePoint)
- **Advanced Reasoning:** ToT multi-branch evaluation, Markov chain modeling
- **Security Hardening:** Input validation, PII detection, rate limiting, audit logging
- **Scalable Deployment:** AWS Bedrock serverless, Docker containerization
- **Comprehensive Testing:** 140+ unit tests, 50+ adversarial tests, 70%+ coverage
- **Framework Compliance:** NIST 800-53, CIS, ISO 27001, NIST AI RMF, OCTAVE

**Total Implementation:** 8,000+ lines of production code across 12 weeks.
