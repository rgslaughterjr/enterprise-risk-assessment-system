# Enterprise Risk Assessment System - Streamlit UI

## Overview

This Streamlit application provides an intuitive web interface to interact with all agents in the Enterprise Risk Assessment System.

## Features

### 🤖 8 Specialized Agent Interfaces

1. **ServiceNow Agent** - Query incidents, assets, and security exceptions
2. **Vulnerability Agent** - Analyze CVEs with NVD, VirusTotal, and CISA KEV
3. **Threat Agent** - Map to MITRE ATT&CK and gather threat intelligence
4. **Risk Scoring Agent** - Calculate FAIR-based risk scores
5. **Report Agent** - Generate professional DOCX reports
6. **Document Agent** - Process PDF/DOCX documents
7. **SharePoint Agent** - Browse and search SharePoint files
8. **Entity Extractor** - Extract CVEs, controls, and assets from text

### 🔄 Pre-built Workflows

- **Complete Risk Assessment** - End-to-end workflow from vulnerability to report
- **Document Analysis** - Process and analyze compliance documents
- **CVE Research** - Comprehensive CVE investigation
- **Asset Risk Analysis** - Asset-focused risk assessment

## Installation

```bash
# Install Streamlit (if not already installed)
pip install streamlit

# The application uses the existing agents from src/agents/
```

## Running the Application

```bash
# From the enterprise-risk-assessment-system directory
streamlit run app.py

# The app will open in your browser at http://localhost:8501
```

## Usage

### Quick Start

1. **Select an Agent** from the sidebar
2. **Choose a Tab** (Chat Query or specialized interface)
3. **Enter your query** or fill in the form
4. **Click the action button** to execute
5. **View results** in real-time

### Chat Interface

Each agent has a natural language chat interface:
- Type your question in plain English
- The agent will process and respond
- Results are displayed in markdown format

### Specialized Interfaces

Each agent also has dedicated interfaces for specific tasks:
- **ServiceNow**: Query incidents by priority/state, search assets
- **Vulnerability**: Analyze specific CVEs, prioritize multiple CVEs
- **Threat**: Map CVEs to MITRE ATT&CK, get threat intelligence
- **Risk Scoring**: Calculate risk with custom parameters
- **Entity Extractor**: Extract specific entity types from text

### Complete Workflow

The "Complete Workflow" demonstrates an end-to-end risk assessment:

1. Enter CVE ID and asset information
2. Click "Run Complete Assessment"
3. Watch as the system:
   - Analyzes the vulnerability
   - Gathers threat intelligence
   - Calculates risk scores
   - Generates a report summary

## Configuration

### Environment Variables

Ensure your `.env` file contains:

```bash
GOOGLE_API_KEY=your_key_here  # Required for Gemini models
OPENAI_API_KEY=your_key_here  # Optional for embeddings
```

### Agent Configuration

All agents use the Gemini models configured in `src/agents/`:
- `gemini-2.0-flash` for fast responses
- `gemini-2.5-pro` for complex analysis

## Features by Agent

### ServiceNow Agent
- Natural language queries
- Filter incidents by priority and state
- Search CMDB assets
- Query security exceptions

### Vulnerability Agent
- Comprehensive CVE analysis
- NVD, VirusTotal, CISA KEV integration
- Multi-CVE prioritization
- Exploitation status checking

### Threat Agent
- MITRE ATT&CK technique mapping
- Threat intelligence from AlienVault OTX
- IOC extraction
- Threat actor research

### Risk Scoring Agent
- FAIR-based 5x5 risk matrix
- Likelihood and impact scoring
- Detailed justifications
- Risk level classification

### Report Agent
- Professional DOCX report generation
- Executive summaries
- Risk heatmaps
- Comprehensive findings

### Document Agent
- PDF/DOCX processing
- Text extraction
- Security control identification
- Compliance analysis

### SharePoint Agent
- File browsing
- Pattern-based search
- Metadata retrieval
- Version history

### Entity Extractor
- CVE extraction
- Security control identification
- Asset detection
- Framework recognition (NIST, ISO, CIS)

## Troubleshooting

### "GOOGLE_API_KEY not found"
- Add `GOOGLE_API_KEY` to your `.env` file
- Restart the Streamlit application

### Agent Import Errors
- Ensure you're running from the `enterprise-risk-assessment-system` directory
- Check that `src/agents/` contains all agent files

### "No module named 'streamlit'"
```bash
pip install streamlit
```

## Tips

💡 **Use the Chat Interface** for exploratory queries  
💡 **Use Specialized Interfaces** for structured analysis  
💡 **Try the Complete Workflow** for demonstrations  
💡 **Check the sidebar** for API key status

## Architecture

```
app.py                    # Main application
ui/
├── __init__.py          # Package init
├── components.py        # Reusable UI components
├── agent_interfaces.py  # Agent-specific interfaces
└── workflows.py         # Pre-built workflow demos
```

## Development

### Adding New Features

1. **New Agent Interface**: Add function to `ui/agent_interfaces.py`
2. **New Workflow**: Add function to `ui/workflows.py`
3. **New Component**: Add to `ui/components.py`
4. **Update Navigation**: Modify sidebar in `app.py`

### Customization

- **Styling**: Modify CSS in `app.py`
- **Layout**: Adjust columns and expanders in interfaces
- **Workflows**: Create custom workflows in `ui/workflows.py`

## Support

For issues or questions:
1. Check the agent logs in the terminal
2. Verify API keys are configured
3. Ensure all dependencies are installed
4. Review the agent documentation in `src/agents/`
