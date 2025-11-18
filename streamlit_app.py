"""Enterprise Risk Assessment System - Streamlit GUI.

Interactive web interface for conducting comprehensive risk assessments
with multi-agent orchestration, document intelligence, and reporting.
"""

import streamlit as st
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import json
from datetime import datetime
import tempfile

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import risk assessment components
try:
    from src.agents.supervisor import SupervisorAgent
    from src.agents.cve_fetcher_agent import CVEFetcherAgent
    from src.agents.document_processor_agent import DocumentProcessorAgent
    from src.agents.report_generator_agent import ReportGeneratorAgent
except ImportError as e:
    st.error(f"Import error: {e}")
    st.stop()

# Import visualization libraries
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np

# Page configuration
st.set_page_config(
    page_title="Enterprise Risk Assessment System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .risk-critical {
        color: #d62728;
        font-weight: bold;
    }
    .risk-high {
        color: #ff7f0e;
        font-weight: bold;
    }
    .risk-medium {
        color: #ffbb00;
        font-weight: bold;
    }
    .risk-low {
        color: #2ca02c;
        font-weight: bold;
    }
    .stProgress > div > div > div > div {
        background-color: #1f77b4;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# Session State Initialization
# ============================================================================

def init_session_state():
    """Initialize session state variables."""
    if 'assessment_results' not in st.session_state:
        st.session_state.assessment_results = None
    if 'assessment_running' not in st.session_state:
        st.session_state.assessment_running = False
    if 'api_key_configured' not in st.session_state:
        st.session_state.api_key_configured = False


# ============================================================================
# Sidebar Configuration
# ============================================================================

def render_sidebar():
    """Render sidebar with API configuration and settings."""
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")

        # API Key Configuration
        st.markdown("### 🔑 API Keys")

        anthropic_key = st.text_input(
            "Anthropic API Key",
            type="password",
            help="Required for AI-powered risk analysis"
        )

        if anthropic_key:
            os.environ['ANTHROPIC_API_KEY'] = anthropic_key
            st.session_state.api_key_configured = True
            st.success("✓ API key configured")
        else:
            st.warning("⚠️ API key required")
            st.session_state.api_key_configured = False

        # Optional API Keys
        with st.expander("Optional API Keys"):
            nvd_key = st.text_input(
                "NVD API Key",
                type="password",
                help="For faster CVE fetching (optional)"
            )
            if nvd_key:
                os.environ['NVD_API_KEY'] = nvd_key

        st.markdown("---")

        # Assessment Settings
        st.markdown("### 🎛️ Assessment Settings")

        assessment_mode = st.selectbox(
            "Assessment Mode",
            ["Standard", "Comprehensive", "Quick"],
            help="Choose depth of analysis"
        )

        enable_tot = st.checkbox(
            "Enable Tree of Thought (ToT) Analysis",
            value=True,
            help="Multi-framework risk scoring (slower but more accurate)"
        )

        num_tot_branches = st.slider(
            "ToT Branches",
            min_value=3,
            max_value=10,
            value=5,
            help="Number of evaluation branches for ToT"
        ) if enable_tot else 5

        st.markdown("---")

        # Export Settings
        st.markdown("### 📄 Export Settings")

        export_format = st.selectbox(
            "Report Format",
            ["DOCX", "PDF", "JSON", "Markdown"],
            help="Select output format"
        )

        include_visualizations = st.checkbox(
            "Include Visualizations",
            value=True
        )

        st.markdown("---")

        # About
        with st.expander("ℹ️ About"):
            st.markdown("""
            **Enterprise Risk Assessment System**

            Version: 1.0.0

            A comprehensive AI-powered risk assessment platform featuring:
            - Multi-agent orchestration
            - CVE vulnerability analysis
            - Document intelligence (OCR, tables, classification)
            - Tree of Thought (ToT) risk scoring
            - Gap analysis and control mapping
            - Automated report generation

            Built with LangGraph, ChromaDB, and Claude 3.5 Sonnet.
            """)

        return {
            'assessment_mode': assessment_mode,
            'enable_tot': enable_tot,
            'num_tot_branches': num_tot_branches,
            'export_format': export_format,
            'include_visualizations': include_visualizations
        }


# ============================================================================
# Main Input Section
# ============================================================================

def render_input_section():
    """Render main input section for assessment parameters."""
    st.markdown('<div class="main-header">🛡️ Enterprise Risk Assessment System</div>',
                unsafe_allow_html=True)

    st.markdown("### 📋 Assessment Configuration")

    col1, col2 = st.columns(2)

    with col1:
        # Document Upload
        st.markdown("#### 📁 Document Upload")
        uploaded_files = st.file_uploader(
            "Upload security documents (PDF, DOCX, PPTX, TXT)",
            type=['pdf', 'docx', 'pptx', 'txt'],
            accept_multiple_files=True,
            help="Documents will be analyzed for security policies, controls, and risks"
        )

        # CVE IDs Input
        st.markdown("#### 🔍 CVE Identifiers")
        cve_input = st.text_area(
            "Enter CVE IDs (one per line)",
            placeholder="CVE-2024-1234\nCVE-2024-5678",
            help="Enter CVE IDs to assess, or leave blank to fetch recent vulnerabilities"
        )

        cve_ids = [line.strip() for line in cve_input.split('\n') if line.strip()]

        # Auto-fetch recent CVEs
        auto_fetch_cves = st.checkbox(
            "Auto-fetch recent CVEs",
            value=True,
            help="Automatically fetch recent vulnerabilities from NVD"
        )

        if auto_fetch_cves:
            days_back = st.slider(
                "Fetch CVEs from last N days",
                min_value=1,
                max_value=90,
                value=7
            )
        else:
            days_back = 7

    with col2:
        # Risk Parameters
        st.markdown("#### 🎯 Risk Parameters")

        asset_name = st.text_input(
            "Asset Name",
            value="Production Web Application",
            help="Name of the asset being assessed"
        )

        asset_criticality = st.select_slider(
            "Asset Criticality",
            options=["Low", "Medium", "High", "Critical"],
            value="High",
            help="Business criticality of the asset"
        )

        # Environment
        environment = st.selectbox(
            "Environment",
            ["Production", "Staging", "Development", "Test"],
            help="Deployment environment"
        )

        # Keywords for CVE filtering
        st.markdown("#### 🏷️ Vulnerability Keywords")
        keywords_input = st.text_input(
            "Filter CVEs by keywords (comma-separated)",
            placeholder="SQL injection, XSS, remote code execution",
            help="Only fetch CVEs matching these keywords"
        )

        keywords = [kw.strip() for kw in keywords_input.split(',') if kw.strip()]

        # Control Discovery Sources
        st.markdown("#### 🔐 Control Discovery")
        discovery_sources = st.multiselect(
            "Control Discovery Sources",
            ["Confluence", "ServiceNow GRC", "Filesystem", "SharePoint"],
            default=["ServiceNow GRC", "Filesystem"],
            help="Sources to discover existing security controls"
        )

    return {
        'uploaded_files': uploaded_files,
        'cve_ids': cve_ids,
        'auto_fetch_cves': auto_fetch_cves,
        'days_back': days_back,
        'asset_name': asset_name,
        'asset_criticality': asset_criticality,
        'environment': environment,
        'keywords': keywords,
        'discovery_sources': discovery_sources
    }


# ============================================================================
# Assessment Execution
# ============================================================================

def run_assessment(inputs: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    """Execute comprehensive risk assessment.

    Args:
        inputs: Assessment input parameters
        settings: Configuration settings

    Returns:
        Assessment results dictionary
    """
    results = {
        'timestamp': datetime.utcnow().isoformat(),
        'asset_name': inputs['asset_name'],
        'asset_criticality': inputs['asset_criticality'],
        'environment': inputs['environment'],
        'cves': [],
        'risks': [],
        'controls': [],
        'gaps': [],
        'summary': {},
        'documents_processed': 0
    }

    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        # Step 1: Process uploaded documents (20%)
        if inputs['uploaded_files']:
            status_text.text("📄 Processing uploaded documents...")
            progress_bar.progress(0.1)

            doc_processor = DocumentProcessorAgent()
            processed_docs = []

            for idx, file in enumerate(inputs['uploaded_files']):
                # Save to temp file
                with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.name).suffix) as tmp:
                    tmp.write(file.read())
                    tmp_path = tmp.name

                try:
                    doc_result = doc_processor.process_document(
                        file_path=tmp_path,
                        doc_type="security_document"
                    )
                    processed_docs.append(doc_result)
                except Exception as e:
                    st.warning(f"Error processing {file.name}: {e}")
                finally:
                    os.unlink(tmp_path)

                progress_bar.progress(0.1 + (0.1 * (idx + 1) / len(inputs['uploaded_files'])))

            results['documents_processed'] = len(processed_docs)
            progress_bar.progress(0.2)

        # Step 2: Fetch CVEs (40%)
        status_text.text("🔍 Fetching vulnerability data...")
        progress_bar.progress(0.25)

        cve_agent = CVEFetcherAgent()
        cve_results = cve_agent.fetch_cves(
            cve_ids=inputs['cve_ids'] if inputs['cve_ids'] else None,
            keywords=inputs['keywords'] if inputs['keywords'] else None,
            days_back=inputs['days_back'] if inputs['auto_fetch_cves'] else None
        )

        results['cves'] = cve_results.get('cves', [])
        progress_bar.progress(0.4)

        # Step 3: Risk Scoring (60%)
        status_text.text("📊 Analyzing risks...")
        progress_bar.progress(0.45)

        # Simulate risk scoring (in real implementation, use RiskScorerAgent)
        for idx, cve in enumerate(results['cves'][:10]):  # Limit to 10 for demo
            risk = {
                'cve_id': cve.get('cve_id', 'UNKNOWN'),
                'cvss_score': cve.get('cvss_score', 0.0),
                'description': cve.get('description', ''),
                'risk_level': categorize_risk_level(cve.get('cvss_score', 0.0)),
                'asset': inputs['asset_name'],
                'environment': inputs['environment']
            }
            results['risks'].append(risk)

            progress_bar.progress(0.45 + (0.15 * (idx + 1) / min(10, len(results['cves']))))

        progress_bar.progress(0.6)

        # Step 4: Control Discovery (80%)
        status_text.text("🔐 Discovering security controls...")
        progress_bar.progress(0.65)

        # Simulate control discovery
        results['controls'] = generate_sample_controls(inputs['discovery_sources'])
        progress_bar.progress(0.8)

        # Step 5: Gap Analysis (90%)
        status_text.text("📋 Analyzing control gaps...")
        progress_bar.progress(0.85)

        results['gaps'] = identify_gaps(results['risks'], results['controls'])
        progress_bar.progress(0.9)

        # Step 6: Generate Summary (100%)
        status_text.text("📈 Generating executive summary...")
        results['summary'] = generate_summary(results)
        progress_bar.progress(1.0)

        status_text.text("✅ Assessment complete!")

    except Exception as e:
        st.error(f"Assessment error: {e}")
        import traceback
        st.code(traceback.format_exc())

    return results


def categorize_risk_level(cvss_score: float) -> str:
    """Categorize risk level based on CVSS score."""
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"


def generate_sample_controls(sources: List[str]) -> List[Dict[str, Any]]:
    """Generate sample controls for demonstration."""
    controls = [
        {'control_id': 'AC-1', 'title': 'Access Control Policy', 'source': 'ServiceNow GRC', 'effectiveness': 85},
        {'control_id': 'AC-2', 'title': 'Account Management', 'source': 'ServiceNow GRC', 'effectiveness': 78},
        {'control_id': 'SI-2', 'title': 'Flaw Remediation', 'source': 'Filesystem', 'effectiveness': 72},
        {'control_id': 'RA-5', 'title': 'Vulnerability Scanning', 'source': 'ServiceNow GRC', 'effectiveness': 90},
        {'control_id': 'CM-2', 'title': 'Baseline Configuration', 'source': 'Confluence', 'effectiveness': 65},
    ]
    return [c for c in controls if any(src.lower() in c['source'].lower() for src in sources)]


def identify_gaps(risks: List[Dict], controls: List[Dict]) -> List[Dict]:
    """Identify gaps between risks and controls."""
    gaps = []
    for risk in risks[:5]:  # Analyze top 5 risks
        if risk['risk_level'] in ['Critical', 'High']:
            gaps.append({
                'risk': risk['cve_id'],
                'severity': risk['risk_level'],
                'recommendation': f"Implement additional controls for {risk['cve_id']}",
                'priority': 'High' if risk['risk_level'] == 'Critical' else 'Medium'
            })
    return gaps


def generate_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate executive summary metrics."""
    risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for risk in results['risks']:
        risk_counts[risk['risk_level']] += 1

    return {
        'total_cves': len(results['cves']),
        'total_risks': len(results['risks']),
        'risk_counts': risk_counts,
        'controls_discovered': len(results['controls']),
        'gaps_identified': len(results['gaps']),
        'average_cvss': np.mean([r.get('cvss_score', 0) for r in results['risks']]) if results['risks'] else 0,
        'documents_analyzed': results['documents_processed']
    }


# ============================================================================
# Results Visualization
# ============================================================================

def render_results(results: Dict[str, Any], settings: Dict[str, Any]):
    """Render assessment results with visualizations."""
    st.markdown("---")
    st.markdown("## 📊 Assessment Results")

    # Executive Summary
    st.markdown("### 📈 Executive Summary")

    summary = results['summary']

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total CVEs", summary['total_cves'])
    with col2:
        st.metric("Risks Identified", summary['total_risks'])
    with col3:
        st.metric("Controls Found", summary['controls_discovered'])
    with col4:
        st.metric("Gaps Identified", summary['gaps_identified'])

    col5, col6, col7, col8 = st.columns(4)
    with col5:
        st.metric("Critical", summary['risk_counts']['Critical'],
                 delta=None, delta_color="inverse")
    with col6:
        st.metric("High", summary['risk_counts']['High'])
    with col7:
        st.metric("Medium", summary['risk_counts']['Medium'])
    with col8:
        st.metric("Low", summary['risk_counts']['Low'])

    # Risk Heatmap
    st.markdown("### 🔥 Risk Heatmap")

    if results['risks']:
        fig = create_risk_heatmap(results['risks'])
        st.plotly_chart(fig, use_container_width=True)

    # Risk Distribution
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📊 Risk Distribution")
        fig = create_risk_distribution_chart(summary['risk_counts'])
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### 📉 CVSS Score Distribution")
        if results['risks']:
            fig = create_cvss_histogram(results['risks'])
            st.plotly_chart(fig, use_container_width=True)

    # Findings Table
    st.markdown("### 📋 Top Risks")
    if results['risks']:
        df_risks = pd.DataFrame(results['risks'][:10])
        st.dataframe(
            df_risks[['cve_id', 'cvss_score', 'risk_level', 'description']],
            use_container_width=True,
            hide_index=True
        )

    # Controls Table
    st.markdown("### 🔐 Discovered Controls")
    if results['controls']:
        df_controls = pd.DataFrame(results['controls'])
        st.dataframe(df_controls, use_container_width=True, hide_index=True)

    # Gaps Table
    st.markdown("### ⚠️ Control Gaps")
    if results['gaps']:
        df_gaps = pd.DataFrame(results['gaps'])
        st.dataframe(df_gaps, use_container_width=True, hide_index=True)

    # Download Report
    st.markdown("### 📥 Download Report")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("📄 Download DOCX Report", use_container_width=True):
            report_content = generate_docx_report(results)
            st.download_button(
                label="⬇️ Download DOCX",
                data=report_content,
                file_name=f"risk_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )

    with col2:
        if st.button("📊 Download JSON Report", use_container_width=True):
            json_content = json.dumps(results, indent=2)
            st.download_button(
                label="⬇️ Download JSON",
                data=json_content,
                file_name=f"risk_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

    with col3:
        if st.button("📝 Download Markdown Report", use_container_width=True):
            md_content = generate_markdown_report(results)
            st.download_button(
                label="⬇️ Download MD",
                data=md_content,
                file_name=f"risk_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )


def create_risk_heatmap(risks: List[Dict]) -> go.Figure:
    """Create risk heatmap visualization."""
    # Group by risk level and environment
    risk_matrix = pd.DataFrame(risks)

    if 'environment' in risk_matrix.columns and 'risk_level' in risk_matrix.columns:
        heatmap_data = risk_matrix.groupby(['environment', 'risk_level']).size().unstack(fill_value=0)

        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data.values,
            x=heatmap_data.columns,
            y=heatmap_data.index,
            colorscale='RdYlGn_r',
            text=heatmap_data.values,
            texttemplate='%{text}',
            textfont={"size": 14}
        ))

        fig.update_layout(
            title="Risk Distribution by Environment",
            xaxis_title="Risk Level",
            yaxis_title="Environment",
            height=400
        )
    else:
        fig = go.Figure()

    return fig


def create_risk_distribution_chart(risk_counts: Dict[str, int]) -> go.Figure:
    """Create risk distribution pie chart."""
    colors = {
        'Critical': '#d62728',
        'High': '#ff7f0e',
        'Medium': '#ffbb00',
        'Low': '#2ca02c'
    }

    fig = go.Figure(data=[go.Pie(
        labels=list(risk_counts.keys()),
        values=list(risk_counts.values()),
        marker=dict(colors=[colors[k] for k in risk_counts.keys()]),
        hole=0.3
    )])

    fig.update_layout(
        title="Risk Level Distribution",
        height=400
    )

    return fig


def create_cvss_histogram(risks: List[Dict]) -> go.Figure:
    """Create CVSS score histogram."""
    cvss_scores = [r.get('cvss_score', 0) for r in risks]

    fig = go.Figure(data=[go.Histogram(
        x=cvss_scores,
        nbinsx=10,
        marker_color='#1f77b4'
    )])

    fig.update_layout(
        title="CVSS Score Distribution",
        xaxis_title="CVSS Score",
        yaxis_title="Count",
        height=400
    )

    return fig


def generate_docx_report(results: Dict[str, Any]) -> bytes:
    """Generate DOCX report (placeholder)."""
    # In real implementation, use python-docx to generate proper report
    report = f"""
    ENTERPRISE RISK ASSESSMENT REPORT
    Generated: {results['timestamp']}
    Asset: {results['asset_name']}

    SUMMARY:
    - Total CVEs: {results['summary']['total_cves']}
    - Risks: {results['summary']['total_risks']}
    - Controls: {results['summary']['controls_discovered']}
    - Gaps: {results['summary']['gaps_identified']}
    """
    return report.encode('utf-8')


def generate_markdown_report(results: Dict[str, Any]) -> str:
    """Generate Markdown report."""
    summary = results['summary']

    md = f"""# Enterprise Risk Assessment Report

**Generated:** {results['timestamp']}
**Asset:** {results['asset_name']}
**Criticality:** {results['asset_criticality']}
**Environment:** {results['environment']}

---

## Executive Summary

- **Total CVEs Analyzed:** {summary['total_cves']}
- **Risks Identified:** {summary['total_risks']}
- **Controls Discovered:** {summary['controls_discovered']}
- **Gaps Identified:** {summary['gaps_identified']}
- **Average CVSS Score:** {summary['average_cvss']:.2f}

### Risk Breakdown

| Severity | Count |
|----------|-------|
| Critical | {summary['risk_counts']['Critical']} |
| High     | {summary['risk_counts']['High']} |
| Medium   | {summary['risk_counts']['Medium']} |
| Low      | {summary['risk_counts']['Low']} |

---

## Top Risks

"""

    for idx, risk in enumerate(results['risks'][:10], 1):
        md += f"""
### {idx}. {risk['cve_id']} - {risk['risk_level']}

- **CVSS Score:** {risk['cvss_score']}
- **Description:** {risk['description'][:200]}...

"""

    return md


# ============================================================================
# Main Application
# ============================================================================

def main():
    """Main Streamlit application."""
    init_session_state()

    # Render sidebar
    settings = render_sidebar()

    # Render input section
    inputs = render_input_section()

    # Run Assessment Button
    st.markdown("---")

    col1, col2, col3 = st.columns([1, 1, 1])

    with col2:
        run_button = st.button(
            "🚀 Run Assessment",
            use_container_width=True,
            disabled=not st.session_state.api_key_configured,
            type="primary"
        )

    if not st.session_state.api_key_configured:
        st.warning("⚠️ Please configure your Anthropic API key in the sidebar to run assessments.")

    # Execute Assessment
    if run_button:
        if not (inputs['cve_ids'] or inputs['auto_fetch_cves'] or inputs['uploaded_files']):
            st.error("Please provide CVE IDs, enable auto-fetch, or upload documents.")
        else:
            with st.spinner("Running comprehensive risk assessment..."):
                results = run_assessment(inputs, settings)
                st.session_state.assessment_results = results

    # Display Results
    if st.session_state.assessment_results:
        render_results(st.session_state.assessment_results, settings)


if __name__ == "__main__":
    main()
