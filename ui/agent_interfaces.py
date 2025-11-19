"""
Agent Interfaces - Streamlit interfaces for each agent
"""

import streamlit as st
import sys
import os
from pathlib import Path

# Ensure src is in path
current_dir = Path(__file__).parent.parent
src_dir = current_dir / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from ui.components import (
    display_header, display_result, display_error, display_success,
    create_input_form, display_agent_status, display_spinner
)

# ============================================================================
# ServiceNow Agent Interface
# ============================================================================

def servicenow_interface():
    """ServiceNow Agent Interface"""
    display_header(
        "📊 ServiceNow Agent",
        "Query incidents, assets, and security exceptions from ServiceNow"
    )
    
    # Tabs for different operations
    tab1, tab2, tab3, tab4 = st.tabs([
        "💬 Chat Query",
        "🔍 Query Incidents",
        "💾 Query Assets",
        "🛡️ Security Exceptions"
    ])
    
    with tab1:
        st.subheader("Natural Language Query")
        query = st.text_area(
            "Ask about incidents, assets, or security data:",
            placeholder="Example: Show me all critical priority incidents",
            height=100
        )
        
        if st.button("🚀 Query ServiceNow", key="sn_chat"):
            if query:
                with display_spinner("Querying ServiceNow..."):
                    try:
                        from agents.servicenow_agent import ServiceNowAgent
                        agent = ServiceNowAgent()
                        result = agent.query(query)
                        display_success("Query completed")
                        st.markdown(result)
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a query")
    
    with tab2:
        st.subheader("Query Incidents")
        col1, col2 = st.columns(2)
        
        with col1:
            priority = st.selectbox(
                "Priority",
                ["All", "1 - Critical", "2 - High", "3 - Moderate", "4 - Low", "5 - Planning"]
            )
        
        with col2:
            state = st.selectbox(
                "State",
                ["All", "New", "In Progress", "On Hold", "Resolved", "Closed"]
            )
        
        limit = st.slider("Max Results", 1, 100, 10)
        
        if st.button("🔍 Search Incidents", key="sn_incidents"):
            with display_spinner("Searching incidents..."):
                try:
                    from agents.servicenow_agent import ServiceNowAgent
                    agent = ServiceNowAgent()
                    
                    priority_val = priority.split(" - ")[0] if priority != "All" else None
                    state_val = state if state != "All" else None
                    
                    incidents = agent.get_incidents_for_analysis(priority=priority_val, limit=limit)
                    
                    if incidents:
                        display_success(f"Found {len(incidents)} incidents")
                        display_result([inc.model_dump() for inc in incidents], "table")
                    else:
                        st.info("No incidents found")
                except Exception as e:
                    display_error(e)
    
    with tab3:
        st.subheader("Query CMDB Assets")
        asset_class = st.text_input("Asset Class (optional)", placeholder="cmdb_ci_server")
        name_filter = st.text_input("Name Filter (optional)", placeholder="prod")
        limit_assets = st.slider("Max Results", 1, 100, 10, key="asset_limit")
        
        if st.button("🔍 Search Assets", key="sn_assets"):
            with display_spinner("Searching assets..."):
                try:
                    from agents.servicenow_agent import ServiceNowAgent
                    agent = ServiceNowAgent()
                    assets = agent.get_assets_for_analysis(
                        asset_class=asset_class or None,
                        limit=limit_assets
                    )
                    
                    if assets:
                        display_success(f"Found {len(assets)} assets")
                        display_result([asset.model_dump() for asset in assets], "table")
                    else:
                        st.info("No assets found")
                except Exception as e:
                    display_error(e)
    
    with tab4:
        st.subheader("Security Exceptions")
        st.info("Query approved security exceptions and risk acceptances")
        
        exception_state = st.selectbox(
            "Exception State",
            ["All", "Approved", "Pending", "Rejected"]
        )
        
        if st.button("🔍 Query Exceptions", key="sn_exceptions"):
            st.info("This feature requires ServiceNow configuration")

# ============================================================================
# Vulnerability Agent Interface
# ============================================================================

def vulnerability_interface():
    """Vulnerability Agent Interface"""
    display_header(
        "🔍 Vulnerability Agent",
        "Analyze CVEs with NVD, VirusTotal, and CISA KEV data"
    )
    
    tab1, tab2, tab3 = st.tabs([
        "💬 Chat Query",
        "🔍 Analyze CVE",
        "📊 Prioritize CVEs"
    ])
    
    with tab1:
        st.subheader("Natural Language Query")
        query = st.text_area(
            "Ask about vulnerabilities:",
            placeholder="Example: Analyze CVE-2024-1234 and check if it's in CISA KEV",
            height=100
        )
        
        if st.button("🚀 Query Vulnerability Agent", key="vuln_chat"):
            if query:
                with display_spinner("Analyzing vulnerability..."):
                    try:
                        from agents.vulnerability_agent import VulnerabilityAgent
                        agent = VulnerabilityAgent()
                        result = agent.query(query)
                        display_success("Analysis completed")
                        st.markdown(result)
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a query")
    
    with tab2:
        st.subheader("Comprehensive CVE Analysis")
        cve_id = st.text_input(
            "CVE ID",
            placeholder="CVE-2024-1234",
            help="Enter a CVE identifier to analyze"
        )
        
        if st.button("🔍 Analyze CVE", key="vuln_analyze"):
            if cve_id:
                with display_spinner(f"Analyzing {cve_id}..."):
                    try:
                        from agents.vulnerability_agent import VulnerabilityAgent
                        agent = VulnerabilityAgent()
                        
                        # Get comprehensive analysis
                        result = agent.query(f"Perform comprehensive analysis of {cve_id}")
                        
                        display_success("Analysis completed")
                        st.markdown(result)
                        
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a CVE ID")
    
    with tab3:
        st.subheader("Prioritize Multiple CVEs")
        cve_list = st.text_area(
            "CVE IDs (one per line)",
            placeholder="CVE-2024-1234\nCVE-2024-5678\nCVE-2024-9999",
            height=150
        )
        
        if st.button("📊 Prioritize CVEs", key="vuln_prioritize"):
            if cve_list:
                cves = [cve.strip() for cve in cve_list.split("\n") if cve.strip()]
                
                with display_spinner(f"Prioritizing {len(cves)} CVEs..."):
                    try:
                        from agents.vulnerability_agent import VulnerabilityAgent
                        agent = VulnerabilityAgent()
                        
                        query = f"Prioritize these CVEs: {', '.join(cves)}"
                        result = agent.query(query)
                        
                        display_success("Prioritization completed")
                        st.markdown(result)
                        
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter at least one CVE ID")

# ============================================================================
# Threat Agent Interface
# ============================================================================

def threat_interface():
    """Threat Agent Interface"""
    display_header(
        "🎯 Threat Agent",
        "Map threats to MITRE ATT&CK and gather threat intelligence"
    )
    
    tab1, tab2, tab3 = st.tabs([
        "💬 Chat Query",
        "🗺️ MITRE Mapping",
        "🔍 Threat Intelligence"
    ])
    
    with tab1:
        st.subheader("Natural Language Query")
        query = st.text_area(
            "Ask about threats:",
            placeholder="Example: Map CVE-2024-1234 to MITRE ATT&CK techniques",
            height=100
        )
        
        if st.button("🚀 Query Threat Agent", key="threat_chat"):
            if query:
                with display_spinner("Researching threat..."):
                    try:
                        from agents.threat_agent import ThreatAgent
                        agent = ThreatAgent()
                        result = agent.query(query)
                        display_success("Research completed")
                        st.markdown(result)
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a query")
    
    with tab2:
        st.subheader("MITRE ATT&CK Mapping")
        cve_id = st.text_input("CVE ID", placeholder="CVE-2024-1234", key="threat_cve")
        cve_desc = st.text_area(
            "CVE Description (optional)",
            placeholder="Brief description of the vulnerability",
            height=100
        )
        
        if st.button("🗺️ Map to ATT&CK", key="threat_map"):
            if cve_id:
                with display_spinner("Mapping to MITRE ATT&CK..."):
                    try:
                        from agents.threat_agent import ThreatAgent
                        agent = ThreatAgent()
                        
                        query = f"Map {cve_id} to MITRE ATT&CK techniques"
                        if cve_desc:
                            query += f". Description: {cve_desc}"
                        
                        result = agent.query(query)
                        display_success("Mapping completed")
                        st.markdown(result)
                        
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a CVE ID")
    
    with tab3:
        st.subheader("Threat Intelligence")
        cve_for_intel = st.text_input("CVE ID", placeholder="CVE-2024-1234", key="threat_intel_cve")
        
        if st.button("🔍 Get Threat Intelligence", key="threat_intel"):
            if cve_for_intel:
                with display_spinner("Gathering threat intelligence..."):
                    try:
                        from agents.threat_agent import ThreatAgent
                        agent = ThreatAgent()
                        
                        result = agent.query(f"Get threat intelligence for {cve_for_intel}")
                        display_success("Intelligence gathered")
                        st.markdown(result)
                        
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a CVE ID")

# ============================================================================
# Risk Scoring Agent Interface
# ============================================================================

def risk_scoring_interface():
    """Risk Scoring Agent Interface"""
    display_header(
        "⚖️ Risk Scoring Agent",
        "Calculate FAIR-based risk scores with detailed justifications"
    )
    
    tab1, tab2 = st.tabs([
        "💬 Chat Query",
        "📊 Calculate Risk"
    ])
    
    with tab1:
        st.subheader("Natural Language Query")
        query = st.text_area(
            "Ask about risk scoring:",
            placeholder="Example: Calculate risk for CVE-2024-1234 on production server",
            height=100
        )
        
        if st.button("🚀 Query Risk Scoring Agent", key="risk_chat"):
            if query:
                with display_spinner("Calculating risk..."):
                    try:
                        from agents.risk_scoring_agent import RiskScoringAgent
                        agent = RiskScoringAgent()
                        result = agent.query(query)
                        display_success("Risk calculation completed")
                        st.markdown(result)
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a query")
    
    with tab2:
        st.subheader("Calculate Risk Score")
        
        col1, col2 = st.columns(2)
        
        with col1:
            cve_id = st.text_input("CVE ID", placeholder="CVE-2024-1234")
            asset_name = st.text_input("Asset Name", placeholder="web-prod-01")
            cvss_score = st.slider("CVSS Score", 0.0, 10.0, 7.5, 0.1)
        
        with col2:
            in_kev = st.checkbox("In CISA KEV")
            vt_detections = st.number_input("VirusTotal Detections", 0, 100, 0)
            asset_criticality = st.slider("Asset Criticality", 1, 5, 3)
        
        if st.button("📊 Calculate Risk", key="risk_calc"):
            if cve_id and asset_name:
                with display_spinner("Calculating comprehensive risk score..."):
                    try:
                        from agents.risk_scoring_agent import RiskScoringAgent
                        agent = RiskScoringAgent()
                        
                        risk_rating = agent.calculate_risk(
                            cve_id=cve_id,
                            asset_name=asset_name,
                            cvss_score=cvss_score,
                            in_cisa_kev=in_kev,
                            vt_detections=vt_detections,
                            asset_criticality=asset_criticality
                        )
                        
                        display_success("Risk calculation completed")
                        
                        # Display risk metrics
                        st.metric("Risk Level", risk_rating.risk_level)
                        st.metric("Risk Score", f"{risk_rating.risk_score}/25")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Likelihood", f"{risk_rating.likelihood.overall_score}/5")
                        with col2:
                            st.metric("Impact", f"{risk_rating.impact.overall_score}/5")
                        
                        # Display justification
                        st.subheader("Risk Justification")
                        st.markdown(risk_rating.overall_justification)
                        
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter CVE ID and Asset Name")

# ============================================================================
# Report Agent Interface
# ============================================================================

def report_interface():
    """Report Agent Interface"""
    display_header(
        "📝 Report Agent",
        "Generate professional DOCX reports with visualizations"
    )
    
    st.info("📝 Report generation interface - Create comprehensive risk assessment reports")
    
    st.subheader("Report Configuration")
    
    report_title = st.text_input("Report Title", "Enterprise Risk Assessment Report")
    report_type = st.selectbox(
        "Report Type",
        ["Comprehensive Risk Assessment", "Vulnerability Analysis", "Threat Intelligence Summary"]
    )
    
    st.subheader("Include Sections")
    include_exec_summary = st.checkbox("Executive Summary", value=True)
    include_findings = st.checkbox("Detailed Findings", value=True)
    include_recommendations = st.checkbox("Recommendations", value=True)
    include_appendix = st.checkbox("Technical Appendix", value=True)
    
    if st.button("📝 Generate Report", key="report_gen"):
        with display_spinner("Generating report..."):
            st.info("Report generation feature requires full risk assessment data. Use the Complete Workflow to generate reports.")

# ============================================================================
# Document Agent Interface
# ============================================================================

def document_interface():
    """Document Agent Interface"""
    display_header(
        "📄 Document Agent",
        "Process and analyze PDF/DOCX documents"
    )
    
    tab1, tab2 = st.tabs([
        "💬 Chat Query",
        "📤 Upload Document"
    ])
    
    with tab1:
        st.subheader("Natural Language Query")
        query = st.text_area(
            "Ask about documents:",
            placeholder="Example: What are the key security controls in the uploaded document?",
            height=100
        )
        
        if st.button("🚀 Query Document Agent", key="doc_chat"):
            if query:
                with display_spinner("Analyzing documents..."):
                    try:
                        from agents.document_agent import DocumentAgent
                        agent = DocumentAgent()
                        result = agent.query(query)
                        display_success("Analysis completed")
                        st.markdown(result)
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a query")
    
    with tab2:
        st.subheader("Upload and Process Document")
        uploaded_file = st.file_uploader(
            "Choose a file",
            type=["pdf", "docx", "txt"],
            help="Upload PDF, DOCX, or TXT files for analysis"
        )
        
        if uploaded_file:
            st.success(f"Uploaded: {uploaded_file.name}")
            
            if st.button("📄 Process Document", key="doc_process"):
                with display_spinner("Processing document..."):
                    st.info("Document processing feature requires document ingestion pipeline. Use the Document Agent chat for queries.")

# ============================================================================
# SharePoint Agent Interface
# ============================================================================

def sharepoint_interface():
    """SharePoint Agent Interface"""
    display_header(
        "📁 SharePoint Agent",
        "Browse and search SharePoint documents"
    )
    
    tab1, tab2, tab3 = st.tabs([
        "💬 Chat Query",
        "📂 Browse Files",
        "🔍 Search Files"
    ])
    
    with tab1:
        st.subheader("Natural Language Query")
        query = st.text_area(
            "Ask about SharePoint files:",
            placeholder="Example: List all PDF files in the documents folder",
            height=100
        )
        
        if st.button("🚀 Query SharePoint Agent", key="sp_chat"):
            if query:
                with display_spinner("Querying SharePoint..."):
                    try:
                        from agents.sharepoint_agent import SharePointAgent
                        agent = SharePointAgent()
                        result = agent.query(query)
                        display_success("Query completed")
                        st.markdown(result)
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a query")
    
    with tab2:
        st.subheader("Browse SharePoint Files")
        path = st.text_input("Path (optional)", placeholder="/", help="Enter path to browse")
        recursive = st.checkbox("Recursive", value=True)
        
        if st.button("📂 List Files", key="sp_list"):
            with display_spinner("Listing files..."):
                st.info("SharePoint browsing requires SharePoint configuration")
    
    with tab3:
        st.subheader("Search Files")
        search_pattern = st.text_input("Search Pattern", placeholder="*.pdf", help="Use glob patterns")
        
        if st.button("🔍 Search", key="sp_search"):
            with display_spinner("Searching files..."):
                st.info("SharePoint search requires SharePoint configuration")

# ============================================================================
# Entity Extractor Agent Interface
# ============================================================================

def entity_extractor_interface():
    """Entity Extractor Agent Interface"""
    display_header(
        "🏷️ Entity Extractor",
        "Extract CVEs, controls, and assets from text"
    )
    
    tab1, tab2 = st.tabs([
        "💬 Chat Query",
        "🏷️ Extract Entities"
    ])
    
    with tab1:
        st.subheader("Natural Language Query")
        query = st.text_area(
            "Ask about entity extraction:",
            placeholder="Example: Extract all CVEs from this text: Found CVE-2024-1234 on server web-prod-01",
            height=100
        )
        
        if st.button("🚀 Query Entity Extractor", key="entity_chat"):
            if query:
                with display_spinner("Extracting entities..."):
                    try:
                        from agents.entity_extractor_agent import EntityExtractorAgent
                        agent = EntityExtractorAgent()
                        result = agent.query(query)
                        display_success("Extraction completed")
                        st.markdown(result)
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter a query")
    
    with tab2:
        st.subheader("Extract Entities from Text")
        text_input = st.text_area(
            "Input Text",
            placeholder="Paste text containing CVEs, controls, assets, etc.",
            height=200
        )
        
        entity_types = st.multiselect(
            "Entity Types to Extract",
            ["CVEs", "Controls", "Assets", "All"],
            default=["All"]
        )
        
        if st.button("🏷️ Extract Entities", key="entity_extract"):
            if text_input:
                with display_spinner("Extracting entities..."):
                    try:
                        from agents.entity_extractor_agent import EntityExtractorAgent
                        agent = EntityExtractorAgent()
                        
                        if "All" in entity_types:
                            query = f"Extract all entities from this text: {text_input}"
                        else:
                            types_str = ", ".join(entity_types)
                            query = f"Extract {types_str} from this text: {text_input}"
                        
                        result = agent.query(query)
                        display_success("Extraction completed")
                        st.markdown(result)
                        
                    except Exception as e:
                        display_error(e)
            else:
                st.warning("Please enter text to analyze")
