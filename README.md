\# Enterprise Risk Assessment System



Production multi-agent system for cybersecurity risk assessment with real API integrations.



\## Overview



Multi-agent orchestration system that automates risk assessment workflows by:

\- Querying ServiceNow for incidents and assets

\- Analyzing vulnerabilities using NVD, VirusTotal, CISA KEV

\- Researching threats using MITRE ATT\&CK and AlienVault OTX

\- Processing compliance documents

\- Calculating risk scores using FAIR framework

\- Generating professional DOCX reports



Built as part of 12-week AI Agent Development Curriculum (Week 6: Project 2).



\## Architecture



\### Multi-Agent System

```

User Query → Supervisor Agent

&nbsp;   ↓

&nbsp;   ├── ServiceNow Query Agent

&nbsp;   ├── Vulnerability Analysis Agent

&nbsp;   ├── Threat Research Agent

&nbsp;   ├── Document Ingestion Agent

&nbsp;   ├── Risk Scoring Agent

&nbsp;   └── Report Generator

&nbsp;   ↓

Risk Assessment Report (DOCX)

```



\### Technology Stack

\- \*\*LLM:\*\* Claude 3.5 Sonnet (Anthropic)

\- \*\*Orchestration:\*\* LangGraph (supervisor pattern)

\- \*\*Agent Framework:\*\* ReAct pattern (from Week 4)

\- \*\*Vector DB:\*\* ChromaDB (document retrieval)

\- \*\*Observability:\*\* LangSmith tracing



\### Real API Integrations

\- \*\*ServiceNow PDI\*\* - Incident/asset queries

\- \*\*NVD API\*\* - CVE details and CVSS scores

\- \*\*VirusTotal API\*\* - Malware analysis

\- \*\*AlienVault OTX\*\* - Threat intelligence

\- \*\*MITRE ATT\&CK\*\* - Technique mapping

\- \*\*CISA KEV\*\* - Exploitation status



\## Project Structure

```

enterprise-risk-assessment-system/

├── src/

│   ├── agents/               # Individual agent implementations

│   │   ├── servicenow\_agent.py

│   │   ├── vulnerability\_agent.py

│   │   ├── threat\_agent.py

│   │   ├── document\_agent.py

│   │   ├── risk\_scoring\_agent.py

│   │   └── report\_agent.py

│   ├── supervisor/           # LangGraph supervisor

│   │   └── supervisor.py

│   ├── tools/                # External API integrations

│   │   ├── servicenow\_client.py

│   │   ├── nvd\_client.py

│   │   ├── virustotal\_client.py

│   │   ├── otx\_client.py

│   │   └── mitre\_client.py

│   ├── models/               # Data models

│   │   └── schemas.py

│   └── utils/                # Utilities

│       └── error\_handler.py

├── tests/                    # Test suite

├── examples/                 # Usage examples

├── reports/                  # Generated reports (gitignored)

├── .env.example             # Environment template

├── requirements.txt

└── README.md

```



\## Setup



\### Prerequisites

\- Python 3.11+

\- API keys for: Anthropic, ServiceNow PDI, NVD, VirusTotal, AlienVault OTX



\### Installation

```bash

\# Clone repository

git clone https://github.com/rgslaughterjr/enterprise-risk-assessment-system.git

cd enterprise-risk-assessment-system



\# Install dependencies

pip install -r requirements.txt



\# Configure environment

cp .env.example .env

\# Edit .env with your API keys

```



\### Environment Variables

```bash

\# LLM

ANTHROPIC\_API\_KEY=your\_key\_here



\# Observability

LANGSMITH\_API\_KEY=your\_key\_here

LANGSMITH\_TRACING=true

LANGSMITH\_PROJECT=enterprise-risk-assessment



\# ServiceNow

SERVICENOW\_INSTANCE=https://devXXXXX.service-now.com

SERVICENOW\_USERNAME=admin

SERVICENOW\_PASSWORD=your\_password



\# Threat Intelligence

NVD\_API\_KEY=your\_key\_here

VIRUSTOTAL\_API\_KEY=your\_key\_here

ALIENVAULT\_OTX\_KEY=your\_key\_here

```



\## Usage



\### Example: Assess CVE Risk

```python

from src.supervisor.supervisor import RiskAssessmentSupervisor



supervisor = RiskAssessmentSupervisor()



result = supervisor.assess\_cve(

&nbsp;   cve\_id="CVE-2024-12345",

&nbsp;   affected\_assets=\["server-prod-01", "web-app-frontend"]

)



print(f"Risk Score: {result.risk\_score}")

print(f"Report: {result.report\_path}")

```



\## Development Progress



\*\*Week 6 Labs:\*\*

\- \[ ] Lab 6.1: ServiceNow PDI Setup \& Testing

\- \[ ] Lab 6.2: ServiceNow Query Agent

\- \[ ] Lab 6.3: Vulnerability Analysis Agent

\- \[ ] Lab 6.4: Threat Research Agent

\- \[ ] Lab 6.5: Document Ingestion Agent

\- \[ ] Lab 6.6: Risk Scoring Agent

\- \[ ] Lab 6.7: LangGraph Supervisor

\- \[ ] Lab 6.8: Report Generator



\## Related Projects



Part of 12-week curriculum:

\- \*\*Week 1-3:\*\* \[Compliance RAG System](https://github.com/rgslaughterjr/compliance-rag-system)

\- \*\*Week 4:\*\* \[ReAct Agent Framework](https://github.com/rgslaughterjr/react-agent-framework)

\- \*\*Week 5:\*\* LangGraph Orchestration (labs)

\- \*\*Week 6:\*\* Enterprise Risk Assessment (this project)



\## Author



Richard Slaughter  

Lead Cybersecurity Risk Analyst (CRISC)  

Learning AI Agent Development for Senior Engineering Roles



\## License



MIT License

