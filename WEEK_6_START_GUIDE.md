# Week 6 Project 2 Start Guide

**Date Created:** November 11, 2024  
**Status:** Ready to begin Week 6 Project 2  
**Last Completed:** Week 5 (all 4 labs) + Lab 6.1 (ServiceNow verification)

---

## CRITICAL: Load Context First

**When starting fresh chat for Week 6, paste this entire document AND instruct Claude to:**

1. **Read Project Knowledge Documents** (in order of priority):
   - `UPDATED_12_WEEK_CURRICULUM.md` ← Most comprehensive
   - `WEEK_4_COMPLETION_SUMMARY.md`
   - `CLAUDE_CODE_STRATEGY.md`
   - `ERROR_FREE_FRAMEWORK_SUMMARY.md`

2. **Search Previous Conversations:**
   - Use `conversation_search` or `recent_chats` tool
   - Query: "Week 5 complete Lab 6.1 ServiceNow enterprise risk assessment"
   - Understand what was accomplished in previous session

3. **Verify Understanding:**
   - Student profile (Richard Slaughter, CRISC)
   - Learning style preferences
   - Enterprise system vision
   - Current progress status

---

## Student Profile Quick Reference

**Name:** Richard Slaughter  
**Role:** Lead Cybersecurity Risk Analyst (CRISC certified)  
**Goal:** Build 4 production AI agent projects for senior AI engineering roles ($160K-$280K)

**Learning Style:**
- Requires detailed conceptual explanations alongside working code
- Values learning-focused development (understand "why" before "how")
- Prefers concise, direct communication
- **Commands in separate copyable blocks** (NO commentary mixed in)
- Ask clarifying questions rather than making assumptions

**Development Environment:**
- Windows 11 with PowerShell 7.5.4
- Python 3.11.9
- Base directory: `C:\Users\richa\Documents\ai-agent-course`
- Git/GitHub workflow established

---

## Current Progress Summary

### Completed Work ✓

**Weeks 1-3: RAG Foundations → Production**
- Basic RAG → Advanced RAG → Production RAG
- Project 1: Compliance Knowledge Base Agent (93% complete)
- Repository: https://github.com/rgslaughterjr/compliance-rag-system

**Week 4: Agent Fundamentals**
- ReAct agent pattern
- Multi-tool agents
- Conversation memory
- Error handling
- Production framework (5,798 lines, 87 tests)
- Repository: https://github.com/rgslaughterjr/react-agent-framework

**Week 5: LangGraph Orchestration** ✓ COMPLETE
- Lab 5.1: StateGraph basics
- Lab 5.2: Conditional routing
- Lab 5.3: Supervisor pattern (100% routing accuracy)
- Lab 5.4: LangSmith tracing (11 traces in dashboard)
- **Cost:** $0.09 (extremely efficient)

**Week 6 Setup** ✓ COMPLETE
- Repository created: https://github.com/rgslaughterjr/enterprise-risk-assessment-system
- Lab 6.1: ServiceNow PDI tested and verified
- All API keys configured and working
- Workspace cleaned (old placeholders removed)

---

## Week 6 Project 2 Objectives

### **Enterprise Risk Assessment Foundation**

**Goal:** Build production multi-agent system with real API integrations

**Duration:** ~40 hours over 1 week  
**Approach:** Claude Code (~$250 budget)  
**Repository:** `enterprise-risk-assessment-system`

### **7 Agents to Build:**

1. **ServiceNow Query Agent** (Lab 6.2)
   - Query incidents, security exceptions, CMDB assets
   - Uses: ServiceNow PDI REST API

2. **Vulnerability Analysis Agent** (Lab 6.3)
   - Parse vulnerability data
   - Query NVD for CVE details
   - Check VirusTotal for exploitation
   - Check CISA KEV for known exploits
   - Uses: NVD API, VirusTotal API, CISA KEV

3. **Threat Research Agent** (Lab 6.4)
   - Map CVEs to MITRE ATT&CK techniques
   - Query AlienVault OTX for threat intelligence
   - Research threat actors
   - Generate threat scenarios
   - Uses: MITRE ATT&CK, AlienVault OTX API

4. **Document Ingestion Agent** (Lab 6.5)
   - Parse Excel, Word, PDF documents
   - Extract security findings
   - Entity recognition
   - Metadata extraction

5. **Risk Scoring Agent** (Lab 6.6)
   - FAIR-based 5×5 matrix
   - Likelihood × Impact dimensions
   - Risk rating with justification

6. **Report Generator** (Lab 6.7)
   - DOCX output using python-docx
   - Sections: Executive Summary, Findings, Threat Analysis, Risk Scores, Recommendations
   - Charts using matplotlib
   - Professional formatting

7. **Supervisor Agent** (Lab 6.8)
   - LangGraph orchestration
   - Coordinates all specialist agents
   - User check-ins at decision points
   - Sequential workflow management
   - State management across agents

---

## API Keys & Configuration Status

### ✓ All Configured in .env

**Location:** `C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system\.env`

```bash
# LLM
ANTHROPIC_API_KEY=configured ✓
OPENAI_API_KEY=configured ✓

# Observability
LANGSMITH_API_KEY=configured ✓
LANGSMITH_TRACING=true
LANGSMITH_PROJECT=enterprise-risk-assessment

# ServiceNow PDI
SERVICENOW_INSTANCE=https://dev271799.service-now.com ✓
SERVICENOW_USERNAME=admin ✓
SERVICENOW_PASSWORD=configured ✓

# Threat Intelligence
NVD_API_KEY=configured ✓
VIRUSTOTAL_API_KEY=configured ✓
ALIENVAULT_OTX_KEY=configured ✓

# MITRE ATT&CK - No key needed (public access)
# Data cached locally: enterprise-attack.json (34MB) ✓
```

### Lab 6.1 Verification Results

**ServiceNow PDI tested successfully:**
- ✓ Authentication working
- ✓ Query incidents (found 5 incidents)
- ✓ Query CMDB (found 5 configuration items)
- ✓ Create incident (INC0010001 created)
- ⚠️ Security incident table (400 error - may need plugin, not critical)

**All external APIs ready for integration!**

---

## Current File Structure

```
C:\Users\richa\Documents\ai-agent-course\
├── .env                                    # Main API keys
├── enterprise-attack.json                  # MITRE data (34MB cached)
├── documents/                              # Compliance PDFs
├── week-1-labs/ through week-5-labs/       # Completed labs ✓
├── react-agent-framework/                  # Week 4 framework (cloned)
├── project-1-rag-compliance/               # Project 1 (cloned)
└── enterprise-risk-assessment-system/      # Week 6 Project 2 ← WORK HERE
    ├── .env                                # Project-specific keys (copy of main)
    ├── .env.example                        # Template for GitHub
    ├── .gitignore                          # Protects .env
    ├── README.md                           # Project documentation
    └── labs/                               # Week 6 labs
        ├── lab-6.1-servicenow-setup/       # ✓ Complete
        │   └── lab_6_1_servicenow_test.py
        ├── lab-6.2-servicenow-agent/       # ← Next
        ├── lab-6.3-vulnerability-agent/
        ├── lab-6.4-threat-agent/
        ├── lab-6.5-document-agent/
        ├── lab-6.6-risk-scoring/
        ├── lab-6.7-supervisor/
        └── lab-6.8-report-generator/
```

---

## Week 6 Development Strategy

### **Phase 1: Individual Agents (Labs 6.2-6.6)**

**Approach:** Build and test each agent independently

**Each lab should:**
1. Create agent implementation
2. Create tool integrations for external APIs
3. Include comprehensive error handling
4. Add unit tests
5. Test with real API calls
6. Document usage examples

**Cost estimate:** ~$150 for agents

---

### **Phase 2: Orchestration (Lab 6.7)**

**Approach:** LangGraph supervisor to coordinate agents

**Implementation:**
- Extend Week 5 supervisor pattern
- Add user check-in points
- State management across agents
- Sequential workflow execution

**Cost estimate:** ~$50 for orchestration

---

### **Phase 3: Report Generation (Lab 6.8)**

**Approach:** Professional DOCX reports

**Features:**
- Executive summary
- Detailed findings
- Threat analysis
- Risk scores with justification
- Charts and visualizations
- Professional formatting

**Cost estimate:** ~$50 for reporting

---

## Architecture Overview

### **Technology Stack**

```
LLM: Claude 3.5 Sonnet (Anthropic)
Orchestration: LangGraph (supervisor pattern)
Agent Framework: ReAct pattern (from Week 4)
Observability: LangSmith tracing
Document Processing: python-docx, pypdf
Visualization: matplotlib
Testing: pytest
```

### **Extends Previous Work**

```python
# Project 2 imports Week 4 framework
from react_agent_framework.agent import ReactAgent
from react_agent_framework.tools import ToolRegistry
from react_agent_framework.memory import ConversationMemory
from react_agent_framework.error_handler import ErrorHandler

# Adds LangGraph orchestration
from langgraph.graph import StateGraph

# Creates 7 specialized agents
servicenow_agent = ReactAgent(name="ServiceNow", tools=[...])
vuln_agent = ReactAgent(name="Vulnerability", tools=[...])
threat_agent = ReactAgent(name="Threat", tools=[...])
# ... etc

# Orchestrates with LangGraph supervisor
workflow = StateGraph(...)
```

---

## Claude Code Usage Strategy

### **When to Use Claude Code**

**Use Claude Code for:**
- Building complete agent implementations
- Integrating external APIs
- Creating production framework
- Writing comprehensive tests
- Generating project structure

**Budget:** ~$250 total for Week 6

### **When to Use Regular Claude**

**Use Regular Claude for:**
- Conceptual questions
- Architecture discussions
- Code reviews
- Debugging specific issues
- Learning explanations

---

## Session Starting Instructions

### **For Fresh Chat Session:**

**Step 1: Navigate to Project**

```powershell
cd C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system
```

**Step 2: Verify Environment**

```powershell
# Check .env exists
Get-ChildItem .env

# Check labs structure
Get-ChildItem labs -Directory
```

**Step 3: Provide Context to Claude**

Paste this entire document into new chat and say:

```
I'm ready to start Week 6 Project 2 - Enterprise Risk Assessment System.

Context loaded from Week 6 Start Guide.

Please:
1. Review project knowledge documents (UPDATED_12_WEEK_CURRICULUM.md)
2. Search recent conversations about Week 5 completion and Lab 6.1
3. Confirm you understand the 7 agents to build
4. Ask if I'm ready to start with Claude Code or have questions

Current directory: C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system
```

**Step 4: Claude Will:**
- Load context from project knowledge
- Review previous session
- Confirm understanding
- Ask if you want to start immediately or discuss approach

---

## Lab-by-Lab Breakdown

### **Lab 6.2: ServiceNow Query Agent** (~4 hours, ~$40)

**Objective:** Build agent that queries ServiceNow PDI

**Tools to create:**
- `servicenow_client.py` - REST API wrapper
- `query_incidents()` - Get security incidents
- `query_cmdb()` - Get asset details
- `query_security_exceptions()` - Get approved exceptions

**Agent capabilities:**
- Natural language queries → ServiceNow API calls
- Return structured incident data
- Include asset context
- Handle pagination
- Error handling for API failures

**Test cases:**
- Query incidents by priority
- Query specific incident by number
- Query CMDB assets by type
- Query incidents affecting specific asset

---

### **Lab 6.3: Vulnerability Analysis Agent** (~5 hours, ~$50)

**Objective:** Build agent that analyzes CVE data

**Tools to create:**
- `nvd_client.py` - NVD API integration
- `virustotal_client.py` - VirusTotal API integration
- `cisa_kev_client.py` - CISA KEV feed parser
- `get_cve_details()` - CVE → NVD data
- `check_exploitation()` - VirusTotal + CISA checks
- `prioritize_vulns()` - Severity + exploitation scoring

**Agent capabilities:**
- Parse CVE IDs from text
- Query NVD for details (CVSS, description, affected products)
- Check VirusTotal for exploit samples
- Check CISA KEV for known exploitation
- Calculate prioritization score

**Test cases:**
- Single CVE analysis
- Batch CVE processing
- Exploitation status determination
- Prioritization ranking

---

### **Lab 6.4: Threat Research Agent** (~5 hours, ~$50)

**Objective:** Build agent that researches threats

**Tools to create:**
- `mitre_client.py` - MITRE ATT&CK integration
- `otx_client.py` - AlienVault OTX integration
- `map_cve_to_techniques()` - CVE → ATT&CK techniques
- `research_threat_actor()` - Threat actor profiles
- `get_threat_context()` - Campaign intelligence

**Agent capabilities:**
- Map CVEs to MITRE ATT&CK techniques
- Query threat actor profiles from OTX
- Get IOCs (IPs, domains, hashes) from campaigns
- Generate threat narratives

**Test cases:**
- CVE to technique mapping
- Threat actor research (APT29, Lazarus, etc.)
- Campaign analysis
- IOC extraction

---

### **Lab 6.5: Document Ingestion Agent** (~4 hours, ~$40)

**Objective:** Build agent that processes documents

**Tools to create:**
- `pdf_parser.py` - PDF text extraction
- `excel_parser.py` - Excel data extraction
- `word_parser.py` - DOCX processing
- `entity_extractor.py` - NER for controls/assets/risks

**Agent capabilities:**
- Parse multiple document formats
- Extract security findings
- Identify entities (CVEs, controls, assets)
- Metadata extraction

**Test cases:**
- Audit report parsing
- Risk assessment document processing
- Vulnerability scan report parsing
- Entity recognition accuracy

---

### **Lab 6.6: Risk Scoring Agent** (~3 hours, ~$30)

**Objective:** Build agent that scores risks

**Framework:**
- FAIR-based 5×5 matrix
- Likelihood dimensions: CVE severity, exploitation status, asset exposure, threat actor capability, existing controls
- Impact dimensions: Asset criticality, data sensitivity, business impact, compliance impact, operational impact

**Agent capabilities:**
- Calculate likelihood score (1-5)
- Calculate impact score (1-5)
- Generate overall risk rating (Critical/High/Medium/Low)
- Provide scoring justification

**Test cases:**
- Various CVE/asset combinations
- Edge cases (no exploitation data)
- Control effectiveness incorporation
- Justification quality

---

### **Lab 6.7: LangGraph Supervisor** (~3 hours, ~$30)

**Objective:** Build supervisor that orchestrates agents

**Architecture:**
```
User Query → Supervisor
    ↓
ServiceNow Agent → Get affected assets
    ↓
Vulnerability Agent → Analyze CVEs
    ↓
Threat Agent → Research threats
    ↓
Risk Scoring Agent → Calculate risk
    ↓
Report Generator → Create DOCX
```

**Supervisor capabilities:**
- Route tasks to appropriate agents
- Maintain state across agent calls
- User check-ins at decision points
- Error recovery
- Progress tracking

**Test cases:**
- Complete workflow execution
- Routing decisions
- State persistence
- Error handling

---

### **Lab 6.8: Report Generator** (~2 hours, ~$20)

**Objective:** Build agent that generates reports

**Tools to create:**
- `docx_generator.py` - DOCX creation
- `chart_generator.py` - Matplotlib charts
- `template_manager.py` - Report templates

**Report sections:**
1. Executive Summary
2. Findings Overview
3. Threat Analysis
4. Risk Scores
5. Recommendations
6. Appendices

**Agent capabilities:**
- Professional DOCX formatting
- Risk heatmap visualization
- Tables and charts
- Multi-page reports

**Test cases:**
- Report generation
- Chart rendering
- Formatting validation
- File output

---

## Success Criteria

### **Week 6 Complete When:**

✓ All 7 agents implemented and tested  
✓ LangGraph supervisor orchestrates workflow  
✓ Real API integrations working  
✓ End-to-end risk assessment workflow complete  
✓ Professional DOCX report generation  
✓ Comprehensive test suite (target: 70%+ coverage)  
✓ Code pushed to GitHub  
✓ Documentation complete  

### **Portfolio Deliverable:**

**GitHub Repository:** https://github.com/rgslaughterjr/enterprise-risk-assessment-system

**Resume bullets:**
- "Built production multi-agent risk assessment system integrating 5 external APIs (ServiceNow, NVD, VirusTotal, MITRE ATT&CK, AlienVault OTX) with LangGraph orchestration"
- "Implemented 7 specialized agents using ReAct pattern for vulnerability analysis, threat research, and automated risk scoring using FAIR framework"
- "Developed automated DOCX report generation with professional formatting, visualizations, and executive summaries for cybersecurity risk assessments"

---

## Important Patterns to Maintain

### **1. Command Format (CRITICAL)**

**Correct:**
```
Explanation here.

Commands:

```powershell
cd enterprise-risk-assessment-system
mkdir src
```

Code separately.
```

**Incorrect:**
```
Let's navigate with `cd enterprise-risk-assessment-system` and create...
```

### **2. Code Quality Standards**

All code must:
- Include comprehensive inline comments
- Have error handling
- Work on first execution
- Include docstrings
- Be modular and testable

### **3. Learning Focus**

- Explain "why" before "how"
- Provide conceptual understanding
- Connect to previous labs
- Show how it applies to enterprise system

---

## Technical Requirements

### **Dependencies to Install**

```bash
# Core
langchain>=0.1.0
langchain-anthropic
langgraph>=0.0.20
python-dotenv

# APIs
requests
mitreattack-python

# Document processing
python-docx
pypdf
openpyxl
pandas

# Visualization
matplotlib

# Testing
pytest
pytest-cov

# Utilities
pydantic
```

### **LangSmith Configuration**

Already set in `.env`:
```bash
LANGSMITH_TRACING=true
LANGSMITH_PROJECT=enterprise-risk-assessment
```

All agent executions will be traced automatically.

---

## Known Issues & Considerations

### **Rate Limits**

- **NVD API:** 5 requests per 30 seconds (free tier)
- **VirusTotal API:** 4 requests per minute (free tier)
- **AlienVault OTX:** 10 requests per second (free tier)
- **ServiceNow PDI:** No documented limits (personal instance)

**Strategy:** Implement retry with exponential backoff (reuse Week 4 error handler)

### **ServiceNow Security Incident Table**

Lab 6.1 showed 400 error for `sn_si_incident` table. This may require plugin activation in ServiceNow. For Week 6, use standard `incident` table instead. Security-specific table is nice-to-have, not required.

### **MITRE ATT&CK Data**

`enterprise-attack.json` (34MB) already cached locally. No download needed for Week 6 development.

---

## Cost Tracking

**Budget:** ~$250 for Week 6 Project 2

**Estimated breakdown:**
- Lab 6.2: ~$40
- Lab 6.3: ~$50
- Lab 6.4: ~$50
- Lab 6.5: ~$40
- Lab 6.6: ~$30
- Lab 6.7: ~$30
- Lab 6.8: ~$20
- **Total:** ~$260 (slightly over, adjust as needed)

**Track actual spend and adjust remaining labs if approaching budget limit.**

---

## After Week 6 Completion

### **Week 7: Advanced Document Processing**

- Multi-format parsing (PowerPoint, OneNote)
- SharePoint integration
- Entity extraction
- Semantic search

### **Week 8: Control Discovery Agent**

- Search company environment for controls
- Multi-source aggregation
- Control-to-risk mapping

### **Weeks 9-12: Security, Observability, Deployment**

- Week 9: Security & guardrails
- Week 10: Advanced risk scoring (Tree of Thought)
- Week 11: Markov Chain threat modeling
- Week 12: Full integration + AWS deployment

---

## Final Reminders

1. **Use Claude Code** for Week 6 development (~$250 budget)
2. **Commands in separate blocks** - no mixed commentary
3. **Ask clarifying questions** - don't assume requirements
4. **Read SKILL.md files** before creating artifacts
5. **Test with real APIs** - no mocks for Week 6!
6. **Comprehensive error handling** - production-quality code
7. **Document everything** - inline comments + README updates

---

## Ready to Start!

**When beginning fresh chat session:**

1. Paste this entire guide
2. Tell Claude: "Ready to start Week 6 Project 2"
3. Claude will load context and confirm understanding
4. Begin building with Claude Code!

**Repository:** https://github.com/rgslaughterjr/enterprise-risk-assessment-system

**Good luck with Week 6! 🚀**

---

**Document Version:** 1.0  
**Last Updated:** November 11, 2024  
**Next Update:** After Week 6 completion
