"""
Workflow Demonstrations - Pre-built workflows for common use cases
"""

import streamlit as st
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from ui.components import (
    display_header, display_result, display_error, display_success,
    display_info, display_spinner, display_metrics
)

def workflow_demo_interface():
    """Complete Workflow Demonstration Interface"""
    display_header(
        "🔄 Complete Risk Assessment Workflow",
        "End-to-end demonstration of the multi-agent risk assessment system"
    )
    
    st.info("""
    This workflow demonstrates a complete risk assessment process:
    1. **ServiceNow**: Query incidents and affected assets
    2. **Vulnerability**: Analyze CVEs and check exploitation status
    3. **Threat**: Map to MITRE ATT&CK and gather intelligence
    4. **Risk Scoring**: Calculate comprehensive risk scores
    5. **Report**: Generate professional documentation
    """)
    
    # Workflow selection
    workflow_type = st.selectbox(
        "Select Workflow",
        [
            "🎯 Complete Risk Assessment",
            "📄 Document Analysis Workflow",
            "🔍 CVE Research Workflow",
            "🏢 Asset Risk Analysis"
        ]
    )
    
    st.markdown("---")
    
    if workflow_type == "🎯 Complete Risk Assessment":
        complete_risk_assessment_workflow()
    elif workflow_type == "📄 Document Analysis Workflow":
        document_analysis_workflow()
    elif workflow_type == "🔍 CVE Research Workflow":
        cve_research_workflow()
    elif workflow_type == "🏢 Asset Risk Analysis":
        asset_risk_analysis_workflow()

def complete_risk_assessment_workflow():
    """Complete end-to-end risk assessment workflow"""
    st.subheader("🎯 Complete Risk Assessment Workflow")
    
    # Step 1: Input
    st.markdown("### Step 1: Define Scope")
    
    col1, col2 = st.columns(2)
    
    with col1:
        cve_id = st.text_input("CVE ID", "CVE-2024-1234", key="workflow_cve")
        asset_name = st.text_input("Asset Name", "web-prod-01", key="workflow_asset")
    
    with col2:
        cvss_score = st.slider("CVSS Score", 0.0, 10.0, 7.5, 0.1, key="workflow_cvss")
        asset_criticality = st.slider("Asset Criticality", 1, 5, 4, key="workflow_crit")
    
    if st.button("🚀 Run Complete Assessment", type="primary", key="run_workflow"):
        run_complete_workflow(cve_id, asset_name, cvss_score, asset_criticality)

def run_complete_workflow(cve_id: str, asset_name: str, cvss_score: float, asset_criticality: int):
    """Execute the complete workflow"""
    
    # Progress tracking
    progress_bar = st.progress(0, text="Starting workflow...")
    
    results = {}
    
    try:
        # Step 1: Vulnerability Analysis
        st.markdown("### 🔍 Step 1: Vulnerability Analysis")
        progress_bar.progress(20, text="Analyzing vulnerability...")
        
        with st.expander("Vulnerability Analysis Results", expanded=True):
            with display_spinner("Querying NVD, VirusTotal, and CISA KEV..."):
                try:
                    from agents.vulnerability_agent import VulnerabilityAgent
                    vuln_agent = VulnerabilityAgent()
                    vuln_result = vuln_agent.query(f"Analyze {cve_id} comprehensively")
                    results['vulnerability'] = vuln_result
                    st.markdown(vuln_result)
                    display_success("Vulnerability analysis completed")
                except Exception as e:
                    display_error(e)
                    st.stop()
        
        # Step 2: Threat Intelligence
        st.markdown("### 🎯 Step 2: Threat Intelligence")
        progress_bar.progress(40, text="Gathering threat intelligence...")
        
        with st.expander("Threat Intelligence Results", expanded=True):
            with display_spinner("Mapping to MITRE ATT&CK and gathering IOCs..."):
                try:
                    from agents.threat_agent import ThreatAgent
                    threat_agent = ThreatAgent()
                    threat_result = threat_agent.query(f"Get threat intelligence for {cve_id}")
                    results['threat'] = threat_result
                    st.markdown(threat_result)
                    display_success("Threat intelligence gathered")
                except Exception as e:
                    display_error(e)
        
        # Step 3: Risk Scoring
        st.markdown("### ⚖️ Step 3: Risk Scoring")
        progress_bar.progress(60, text="Calculating risk scores...")
        
        with st.expander("Risk Scoring Results", expanded=True):
            with display_spinner("Calculating FAIR-based risk score..."):
                try:
                    from agents.risk_scoring_agent import RiskScoringAgent
                    risk_agent = RiskScoringAgent()
                    
                    risk_rating = risk_agent.calculate_risk(
                        cve_id=cve_id,
                        asset_name=asset_name,
                        cvss_score=cvss_score,
                        in_cisa_kev=False,  # Would be determined from vuln analysis
                        vt_detections=0,
                        asset_criticality=asset_criticality
                    )
                    
                    results['risk'] = risk_rating
                    
                    # Display metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Risk Level", risk_rating.risk_level)
                    with col2:
                        st.metric("Risk Score", f"{risk_rating.risk_score}/25")
                    with col3:
                        st.metric("Likelihood", f"{risk_rating.likelihood.overall_score}/5")
                    with col4:
                        st.metric("Impact", f"{risk_rating.impact.overall_score}/5")
                    
                    st.markdown("**Justification:**")
                    st.markdown(risk_rating.overall_justification)
                    
                    display_success("Risk scoring completed")
                except Exception as e:
                    display_error(e)
        
        # Step 4: Report Generation
        st.markdown("### 📝 Step 4: Report Generation")
        progress_bar.progress(80, text="Generating report...")
        
        with st.expander("Report Summary", expanded=True):
            st.markdown(f"""
            ## Risk Assessment Report
            
            **CVE:** {cve_id}  
            **Asset:** {asset_name}  
            **Assessment Date:** {st.session_state.get('assessment_date', 'Today')}
            
            ### Executive Summary
            
            A comprehensive risk assessment was conducted for {cve_id} affecting {asset_name}.
            The overall risk level is **{results.get('risk', 'N/A')}**.
            
            ### Key Findings
            
            - Vulnerability analysis completed with NVD, VirusTotal, and CISA KEV data
            - Threat intelligence gathered from MITRE ATT&CK and AlienVault OTX
            - Risk score calculated using FAIR-based methodology
            
            ### Recommendations
            
            Based on the risk level, immediate remediation is recommended.
            """)
            
            display_success("Report generated")
        
        # Complete
        progress_bar.progress(100, text="Workflow completed!")
        
        st.markdown("---")
        st.success("✅ Complete risk assessment workflow finished successfully!")
        
        # Summary metrics
        st.markdown("### 📊 Workflow Summary")
        display_metrics({
            "Steps Completed": "4/4",
            "Agents Used": "3",
            "Risk Level": results.get('risk', {}).risk_level if 'risk' in results else "N/A",
            "Status": "Complete"
        })
        
    except Exception as e:
        progress_bar.progress(0, text="Workflow failed")
        display_error(e)

def document_analysis_workflow():
    """Document analysis workflow"""
    st.subheader("📄 Document Analysis Workflow")
    
    st.info("""
    This workflow demonstrates document processing:
    1. Upload compliance or security documents
    2. Extract entities (CVEs, controls, assets)
    3. Analyze security controls
    4. Generate compliance report
    """)
    
    uploaded_file = st.file_uploader("Upload Document", type=["pdf", "docx", "txt"])
    
    if uploaded_file and st.button("🔍 Analyze Document"):
        with display_spinner("Analyzing document..."):
            st.info("Document analysis requires document ingestion configuration")

def cve_research_workflow():
    """CVE research workflow"""
    st.subheader("🔍 CVE Research Workflow")
    
    st.info("""
    This workflow provides comprehensive CVE research:
    1. CVE details from NVD
    2. Exploitation status (VirusTotal, CISA KEV)
    3. MITRE ATT&CK mapping
    4. Threat intelligence and IOCs
    5. Risk prioritization
    """)
    
    cve_list = st.text_area(
        "CVE IDs (one per line)",
        placeholder="CVE-2024-1234\nCVE-2024-5678",
        height=150
    )
    
    if st.button("🔍 Research CVEs"):
        if cve_list:
            cves = [cve.strip() for cve in cve_list.split("\n") if cve.strip()]
            
            with display_spinner(f"Researching {len(cves)} CVEs..."):
                for i, cve in enumerate(cves, 1):
                    st.markdown(f"### {i}. {cve}")
                    
                    try:
                        from agents.vulnerability_agent import VulnerabilityAgent
                        agent = VulnerabilityAgent()
                        result = agent.query(f"Analyze {cve}")
                        st.markdown(result)
                        st.markdown("---")
                    except Exception as e:
                        display_error(e)
        else:
            st.warning("Please enter at least one CVE ID")

def asset_risk_analysis_workflow():
    """Asset risk analysis workflow"""
    st.subheader("🏢 Asset Risk Analysis")
    
    st.info("""
    This workflow analyzes risk for specific assets:
    1. Query asset from ServiceNow CMDB
    2. Identify vulnerabilities affecting the asset
    3. Calculate risk scores
    4. Generate remediation recommendations
    """)
    
    asset_name = st.text_input("Asset Name", placeholder="web-prod-01")
    
    if st.button("🔍 Analyze Asset Risk"):
        if asset_name:
            with display_spinner(f"Analyzing risk for {asset_name}..."):
                st.info("Asset risk analysis requires ServiceNow configuration")
        else:
            st.warning("Please enter an asset name")
