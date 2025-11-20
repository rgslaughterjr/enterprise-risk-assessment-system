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

# ============================================================================
# Agent Security & Diagnostics Interface
# ============================================================================

def security_diagnostics_interface():
    """Agent Security & Diagnostics Interface"""
    display_header(
        "🔒 Agent Security & Diagnostics",
        "NIST AI RMF & CSF 2.0 compliance testing and production certification"
    )
    
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🏠 Dashboard",
        "🔍 Self-Diagnostics",
        "🤖 Agent Assessment",
        "📋 NIST AI RMF",
        "🛡️ NIST CSF 2.0",
        "✅ Certification"
    ])
    
    with tab1:
        st.subheader("Security & Compliance Dashboard")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("System Health", "85%", "↑ 5%")
        with col2:
            st.metric("Compliance Score", "78%", "↑ 3%")
        with col3:
            st.metric("Risk Level", "Medium", "↓ Low")
        
        st.markdown("---")
        st.info("💡 **Quick Actions**: Run self-diagnostics to assess system security, or evaluate individual agents for production readiness.")
    
    with tab2:
        st.subheader("System Self-Diagnostics")
        st.markdown("Run comprehensive security and compliance assessment on the entire system.")
        
        if st.button("🔍 Run Self-Diagnostics", key="sec_self_diag"):
            with display_spinner("Running comprehensive diagnostics..."):
                try:
                    from agents.agent_security_diagnostics_agent import AgentSecurityDiagnosticsAgent
                    agent = AgentSecurityDiagnosticsAgent()
                    
                    report = agent.run_self_diagnostics()
                    
                    display_success("Diagnostics completed!")
                    
                    # Display overall metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Overall Score", f"{report.overall_score:.1f}%")
                    with col2:
                        st.metric("Security Score", f"{report.security_score:.1f}%")
                    with col3:
                        st.metric("Risk Level", report.risk_level.upper())
                    with col4:
                        st.metric("Critical Issues", report.critical_vulnerabilities)
                    
                    # Security Tests
                    st.subheader("Security Test Results")
                    test_data = []
                    for test in report.security_tests:
                        test_data.append({
                            "Test": test.test_name,
                            "Category": test.category,
                            "Severity": test.severity,
                            "Status": test.status
                        })
                    if test_data:
                        display_result(test_data, "table")
                    
                    # NIST AI RMF Compliance
                    st.subheader("NIST AI RMF Compliance")
                    for assessment in report.nist_ai_rmf_assessments:
                        with st.expander(f"{assessment.function} - {assessment.compliance_score:.1f}%"):
                            st.write(f"**Implemented Controls**: {assessment.implemented_controls}/{assessment.total_controls}")
                            if assessment.gaps:
                                st.write("**Gaps**:")
                                for gap in assessment.gaps:
                                    st.write(f"- {gap}")
                    
                    # NIST CSF Compliance
                    st.subheader("NIST CSF 2.0 Compliance")
                    for assessment in report.nist_csf_assessments:
                        with st.expander(f"{assessment.function} - {assessment.compliance_score:.1f}%"):
                            st.write(f"**Implementation Tier**: {assessment.implementation_tier}")
                            if assessment.gaps:
                                st.write("**Gaps**:")
                                for gap in assessment.gaps:
                                    st.write(f"- {gap}")
                    
                    # Recommendations
                    st.subheader("Top Recommendations")
                    for i, rec in enumerate(report.recommendations[:5], 1):
                        st.write(f"{i}. {rec}")
                    
                except Exception as e:
                    display_error(e)
    
    with tab3:
        st.subheader("Agent Assessment")
        st.markdown("Assess individual agents for security and compliance.")
        
        agent_to_assess = st.selectbox(
            "Select Agent",
            [
                "ServiceNow Agent",
                "Vulnerability Agent",
                "Threat Agent",
                "Risk Scoring Agent",
                "Document Agent",
                "SharePoint Agent",
                "Entity Extractor Agent",
                "Report Agent"
            ]
        )
        
        if st.button("🤖 Assess Agent", key="sec_assess_agent"):
            with display_spinner(f"Assessing {agent_to_assess}..."):
                try:
                    from agents.agent_security_diagnostics_agent import AgentSecurityDiagnosticsAgent
                    agent = AgentSecurityDiagnosticsAgent()
                    
                    report = agent.assess_agent(agent_to_assess)
                    
                    display_success(f"Assessment of {agent_to_assess} completed!")
                    
                    # Display metrics
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Overall Score", f"{report.overall_score:.1f}%")
                    with col2:
                        st.metric("Security Score", f"{report.security_score:.1f}%")
                    with col3:
                        st.metric("Risk Level", report.risk_level.upper())
                    
                    # Security Tests Summary
                    st.subheader("Security Test Summary")
                    passed = sum(1 for t in report.security_tests if t.status == "pass")
                    failed = sum(1 for t in report.security_tests if t.status == "fail")
                    warnings = sum(1 for t in report.security_tests if t.status == "warning")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Passed", passed)
                    with col2:
                        st.metric("Failed", failed)
                    with col3:
                        st.metric("Warnings", warnings)
                    
                    # Recommendations
                    st.subheader("Recommendations")
                    for i, rec in enumerate(report.recommendations[:5], 1):
                        st.write(f"{i}. {rec}")
                    
                except Exception as e:
                    display_error(e)
    
    with tab4:
        st.subheader("NIST AI Risk Management Framework")
        st.markdown("Assess compliance with NIST AI RMF 1.0 framework.")
        
        function = st.selectbox(
            "Select Function",
            ["All Functions", "GOVERN", "MAP", "MEASURE", "MANAGE"]
        )
        
        if st.button("📋 Run AI RMF Assessment", key="sec_ai_rmf"):
            with display_spinner("Running NIST AI RMF assessment..."):
                try:
                    from tools.nist_ai_rmf_checker import NISTAIRMFChecker
                    checker = NISTAIRMFChecker()
                    
                    if function == "All Functions":
                        assessments = checker.assess_all_functions()
                    else:
                        if function == "GOVERN":
                            assessments = [checker.assess_govern_function()]
                        elif function == "MAP":
                            assessments = [checker.assess_map_function()]
                        elif function == "MEASURE":
                            assessments = [checker.assess_measure_function()]
                        else:
                            assessments = [checker.assess_manage_function()]
                    
                    for assessment in assessments:
                        st.subheader(f"{assessment.function} Function")
                        st.metric("Compliance Score", f"{assessment.compliance_score:.1f}%")
                        st.write(f"**Controls**: {assessment.implemented_controls}/{assessment.total_controls} implemented")
                        
                        with st.expander("View Controls"):
                            for control in assessment.controls:
                                status_icon = "✅" if control.implemented else "❌"
                                st.write(f"{status_icon} **{control.control_id}**: {control.control_name}")
                        
                        if assessment.recommendations:
                            with st.expander("Recommendations"):
                                for rec in assessment.recommendations:
                                    st.write(f"- {rec}")
                    
                except Exception as e:
                    display_error(e)
    
    with tab5:
        st.subheader("NIST Cybersecurity Framework 2.0")
        st.markdown("Assess compliance with NIST CSF 2.0 framework.")
        
        csf_function = st.selectbox(
            "Select Function",
            ["All Functions", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER", "GOVERN"],
            key="csf_function"
        )
        
        if st.button("🛡️ Run CSF Assessment", key="sec_csf"):
            with display_spinner("Running NIST CSF 2.0 assessment..."):
                try:
                    from tools.nist_csf_checker import NISTCSFChecker
                    checker = NISTCSFChecker()
                    
                    if csf_function == "All Functions":
                        assessments = checker.assess_all_functions()
                    else:
                        if csf_function == "IDENTIFY":
                            assessments = [checker.assess_identify_function()]
                        elif csf_function == "PROTECT":
                            assessments = [checker.assess_protect_function()]
                        elif csf_function == "DETECT":
                            assessments = [checker.assess_detect_function()]
                        elif csf_function == "RESPOND":
                            assessments = [checker.assess_respond_function()]
                        elif csf_function == "RECOVER":
                            assessments = [checker.assess_recover_function()]
                        else:
                            assessments = [checker.assess_govern_function()]
                    
                    for assessment in assessments:
                        st.subheader(f"{assessment.function} Function")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Compliance Score", f"{assessment.compliance_score:.1f}%")
                        with col2:
                            st.metric("Implementation Tier", assessment.implementation_tier)
                        
                        with st.expander("View Categories"):
                            for category in assessment.categories:
                                st.write(f"**{category.category_id}**: {category.category_name}")
                                st.write(f"- Controls: {category.controls_implemented}/{category.controls_total}")
                                st.write(f"- Tier: {category.implementation_tier}, Maturity: {category.maturity_level}")
                        
                        if assessment.recommendations:
                            with st.expander("Recommendations"):
                                for rec in assessment.recommendations:
                                    st.write(f"- {rec}")
                    
                except Exception as e:
                    display_error(e)
    
    with tab6:
        st.subheader("Production Certification")
        st.markdown("Generate production readiness certification report.")
        
        agent_to_certify = st.selectbox(
            "Select Agent to Certify",
            [
                "Enterprise Risk Assessment System",
                "ServiceNow Agent",
                "Vulnerability Agent",
                "Threat Agent",
                "Risk Scoring Agent"
            ],
            key="cert_agent"
        )
        
        if st.button("✅ Generate Certification Report", key="sec_cert"):
            with display_spinner("Generating certification report..."):
                try:
                    from agents.agent_security_diagnostics_agent import AgentSecurityDiagnosticsAgent
                    agent = AgentSecurityDiagnosticsAgent()
                    
                    # Run diagnostic first
                    if agent_to_certify == "Enterprise Risk Assessment System":
                        diagnostic = agent.run_self_diagnostics()
                    else:
                        diagnostic = agent.assess_agent(agent_to_certify)
                    
                    # Generate certification
                    cert_report = agent.generate_certification_report(diagnostic)
                    
                    display_success("Certification report generated!")
                    
                    # Display certification decision
                    if cert_report.production_ready:
                        st.success(f"✅ **{agent_to_certify}** is CERTIFIED for production")
                    else:
                        st.error(f"❌ **{agent_to_certify}** is NOT CERTIFIED for production")
                    
                    # Display metrics
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Status", cert_report.certification_status.upper())
                    with col2:
                        st.metric("Risk Level", cert_report.risk_level.upper())
                    with col3:
                        st.metric("Overall Score", f"{cert_report.overall_compliance_score:.1f}%")
                    with col4:
                        st.metric("Critical Findings", len(cert_report.critical_findings))
                    
                    # Compliance Scores
                    st.subheader("Compliance Scores")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Security", f"{cert_report.security_score:.1f}%")
                    with col2:
                        st.metric("NIST AI RMF", f"{cert_report.nist_ai_rmf_score:.1f}%")
                    with col3:
                        st.metric("NIST CSF 2.0", f"{cert_report.nist_csf_score:.1f}%")
                    
                    # Findings
                    if cert_report.critical_findings:
                        st.subheader("Critical Findings")
                        for finding in cert_report.critical_findings:
                            st.error(f"🔴 {finding}")
                    
                    if cert_report.high_findings:
                        st.subheader("High Priority Findings")
                        for finding in cert_report.high_findings[:5]:
                            st.warning(f"🟡 {finding}")
                    
                    # Remediation Plan
                    if cert_report.remediation_plan:
                        st.subheader("Remediation Plan")
                        for i, step in enumerate(cert_report.remediation_plan, 1):
                            st.write(f"{i}. {step}")
                        
                        if cert_report.estimated_remediation_time:
                            st.info(f"⏱️ Estimated Time: {cert_report.estimated_remediation_time}")
                    
                except Exception as e:
                    display_error(e)
