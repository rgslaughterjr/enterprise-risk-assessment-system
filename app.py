"""
Enterprise Risk Assessment System - Streamlit UI
Main application entry point
"""

import streamlit as st
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables FIRST
load_dotenv()

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from ui.components import setup_page, display_header
from ui.agent_interfaces import (
    servicenow_interface,
    vulnerability_interface,
    threat_interface,
    risk_scoring_interface,
    report_interface,
    document_interface,
    sharepoint_interface,
    entity_extractor_interface
)
from ui.workflows import workflow_demo_interface

# Page configuration
st.set_page_config(
    page_title="Enterprise Risk Assessment System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS - Modern Dark Theme with Better Readability
st.markdown("""
<style>
    /* Main container */
    .main {
        background-color: #0e1117;
    }
    
    /* Headers */
    .main-header {
        font-size: 2.8rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1.5rem;
        letter-spacing: -0.5px;
    }
    
    /* Agent cards with glassmorphism */
    .agent-card {
        padding: 1.5rem;
        border-radius: 12px;
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        margin-bottom: 1rem;
        transition: all 0.3s ease;
    }
    
    .agent-card:hover {
        background: rgba(255, 255, 255, 0.08);
        transform: translateY(-2px);
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
    }
    
    .agent-card h3 {
        color: #ffffff;
        font-size: 1.3rem;
        margin-bottom: 0.5rem;
    }
    
    .agent-card p {
        color: #b8b8b8;
        font-size: 0.95rem;
        line-height: 1.6;
    }
    
    /* Status boxes */
    .success-box {
        padding: 1.2rem;
        border-radius: 10px;
        background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
        border-left: 4px solid #10b981;
        color: #10b981;
        font-weight: 500;
    }
    
    .error-box {
        padding: 1.2rem;
        border-radius: 10px;
        background: linear-gradient(135deg, #ef444415 0%, #dc262615 100%);
        border-left: 4px solid #ef4444;
        color: #ef4444;
        font-weight: 500;
    }
    
    .info-box {
        padding: 1.2rem;
        border-radius: 10px;
        background: linear-gradient(135deg, #3b82f615 0%, #2563eb15 100%);
        border-left: 4px solid #3b82f6;
        color: #60a5fa;
        font-weight: 500;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1d29 0%, #0e1117 100%);
    }
    
    [data-testid="stSidebar"] h1 {
        color: #ffffff;
        font-size: 1.5rem;
        font-weight: 700;
    }
    
    /* Radio buttons */
    .stRadio > label {
        color: #e5e7eb !important;
        font-size: 1rem;
        font-weight: 500;
    }
    
    /* Text inputs */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea {
        background-color: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        color: #ffffff;
        font-size: 1rem;
    }
    
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.2);
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 16px rgba(102, 126, 234, 0.3);
    }
    
    /* Expanders */
    .streamlit-expanderHeader {
        background-color: rgba(255, 255, 255, 0.05);
        border-radius: 8px;
        color: #ffffff;
        font-weight: 600;
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        color: #667eea;
        font-weight: 700;
    }
    
    /* Chat messages */
    .stChatMessage {
        background-color: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 1rem;
        margin-bottom: 0.5rem;
    }
    
    /* Improve text readability */
    p, li, span {
        color: #e5e7eb;
        line-height: 1.7;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: #ffffff;
    }
</style>
""", unsafe_allow_html=True)

def main():
    """Main application"""
    
    # Initialize session state
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    if 'current_agent' not in st.session_state:
        st.session_state.current_agent = None
    
    # Sidebar navigation
    with st.sidebar:
        st.title("🛡️ Risk Assessment")
        st.markdown("---")
        
        page = st.radio(
            "Select Interface",
            [
                "🏠 Home",
                "🔄 Complete Workflow",
                "📊 ServiceNow Agent",
                "🔍 Vulnerability Agent",
                "🎯 Threat Agent",
                "⚖️ Risk Scoring Agent",
                "📝 Report Agent",
                "📄 Document Agent",
                "📁 SharePoint Agent",
                "🏷️ Entity Extractor"
            ]
        )
        
        st.markdown("---")
        st.markdown("### About")
        st.info("""
        **Enterprise Risk Assessment System**
        
        AI-powered multi-agent system for comprehensive cybersecurity risk analysis.
        
        **Powered by:**
        - Google Gemini 2.0 Flash
        - LangGraph
        - Real-time threat intelligence
        """)
        
        # Comprehensive API Status Check
        st.markdown("---")
        st.markdown("### 🔌 API Status")
        
        # Google API Key
        if os.getenv("GOOGLE_API_KEY"):
            st.success("✅ Google Gemini")
        else:
            st.error("❌ Google Gemini")
        
        # OpenAI API Key (for embeddings)
        if os.getenv("OPENAI_API_KEY"):
            st.success("✅ OpenAI")
        else:
            st.warning("⚠️ OpenAI (Optional)")
        
        # ServiceNow
        if os.getenv("SERVICENOW_INSTANCE") and os.getenv("SERVICENOW_USERNAME"):
            st.success("✅ ServiceNow")
        else:
            st.warning("⚠️ ServiceNow")
        
        # NVD API
        if os.getenv("NVD_API_KEY"):
            st.success("✅ NVD")
        else:
            st.warning("⚠️ NVD (Optional)")
        
        # VirusTotal
        if os.getenv("VIRUSTOTAL_API_KEY"):
            st.success("✅ VirusTotal")
        else:
            st.warning("⚠️ VirusTotal (Optional)")
        
        # AlienVault OTX
        if os.getenv("ALIENVAULT_OTX_KEY"):
            st.success("✅ AlienVault OTX")
        else:
            st.warning("⚠️ AlienVault (Optional)")
        
        # LangSmith (Observability)
        if os.getenv("LANGSMITH_API_KEY"):
            st.success("✅ LangSmith")
        else:
            st.warning("⚠️ LangSmith (Optional)")
    
    # Main content area
    if page == "🏠 Home":
        display_home()
    elif page == "🔄 Complete Workflow":
        workflow_demo_interface()
    elif page == "📊 ServiceNow Agent":
        servicenow_interface()
    elif page == "🔍 Vulnerability Agent":
        vulnerability_interface()
    elif page == "🎯 Threat Agent":
        threat_interface()
    elif page == "⚖️ Risk Scoring Agent":
        risk_scoring_interface()
    elif page == "📝 Report Agent":
        report_interface()
    elif page == "📄 Document Agent":
        document_interface()
    elif page == "📁 SharePoint Agent":
        sharepoint_interface()
    elif page == "🏷️ Entity Extractor":
        entity_extractor_interface()

def display_home():
    """Display home page with prominent chat interface"""
    st.markdown('<div class="main-header">🛡️ Enterprise Risk Assessment System</div>', unsafe_allow_html=True)
    
    # Prominent Chat Interface at the top
    st.markdown("### 💬 Quick Agent Chat")
    st.markdown("Ask any question to get started - I'll route it to the right agent!")
    
    col1, col2 = st.columns([4, 1])
    with col1:
        user_query = st.text_input(
            "Your Question",
            placeholder="Example: Analyze CVE-2024-1234 or Show me critical incidents",
            label_visibility="collapsed",
            key="home_chat_input"
        )
    with col2:
        send_button = st.button("🚀 Ask", type="primary", use_container_width=True)
    
    if send_button and user_query:
        with st.spinner("Routing to appropriate agent..."):
            # Simple routing logic based on keywords
            query_lower = user_query.lower()
            
            if any(word in query_lower for word in ['cve', 'vulnerability', 'nvd', 'virustotal']):
                st.info("🔍 Routing to Vulnerability Agent...")
                try:
                    from agents.vulnerability_agent import VulnerabilityAgent
                    agent = VulnerabilityAgent()
                    result = agent.query(user_query)
                    st.markdown("#### Response:")
                    st.markdown(result)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
            
            elif any(word in query_lower for word in ['incident', 'servicenow', 'asset', 'cmdb']):
                st.info("📊 Routing to ServiceNow Agent...")
                try:
                    from agents.servicenow_agent import ServiceNowAgent
                    agent = ServiceNowAgent()
                    result = agent.query(user_query)
                    st.markdown("#### Response:")
                    st.markdown(result)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
            
            elif any(word in query_lower for word in ['threat', 'mitre', 'attack', 'technique']):
                st.info("🎯 Routing to Threat Agent...")
                try:
                    from agents.threat_agent import ThreatAgent
                    agent = ThreatAgent()
                    result = agent.query(user_query)
                    st.markdown("#### Response:")
                    st.markdown(result)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
            
            elif any(word in query_lower for word in ['risk', 'score', 'calculate']):
                st.info("⚖️ Routing to Risk Scoring Agent...")
                try:
                    from agents.risk_scoring_agent import RiskScoringAgent
                    agent = RiskScoringAgent()
                    result = agent.query(user_query)
                    st.markdown("#### Response:")
                    st.markdown(result)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
            
            else:
                # Default to vulnerability agent for general queries
                st.info("🔍 Routing to Vulnerability Agent (default)...")
                try:
                    from agents.vulnerability_agent import VulnerabilityAgent
                    agent = VulnerabilityAgent()
                    result = agent.query(user_query)
                    st.markdown("#### Response:")
                    st.markdown(result)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
    
    st.markdown("---")
    
    # System overview
    st.markdown("### 🎯 System Overview")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="agent-card">
            <h3>🤖 8 Specialized Agents</h3>
            <p>Each agent focuses on a specific aspect of risk assessment</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="agent-card">
            <h3>🔗 Real-time Intelligence</h3>
            <p>Integrated with NVD, CISA KEV, MITRE ATT&CK, and more</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="agent-card">
            <h3>📊 Comprehensive Reports</h3>
            <p>Generate professional risk assessment documentation</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Agent capabilities
    st.subheader("Available Agents")
    
    agents = [
        ("📊 ServiceNow Agent", "Query incidents, assets, and security exceptions from ServiceNow"),
        ("🔍 Vulnerability Agent", "Analyze CVEs with NVD, VirusTotal, and CISA KEV data"),
        ("🎯 Threat Agent", "Map threats to MITRE ATT&CK and gather threat intelligence"),
        ("⚖️ Risk Scoring Agent", "Calculate FAIR-based risk scores with detailed justifications"),
        ("📝 Report Agent", "Generate professional DOCX reports with visualizations"),
        ("📄 Document Agent", "Process and analyze PDF/DOCX documents"),
        ("📁 SharePoint Agent", "Browse and search SharePoint files"),
        ("🏷️ Entity Extractor", "Extract CVEs, controls, and assets from text")
    ]
    
    for icon_name, description in agents:
        with st.expander(icon_name):
            st.write(description)
    
    st.markdown("---")
    
    # Quick start
    st.subheader("🚀 Quick Start")
    st.markdown("""
    1. **Use the chat above** for quick queries
    2. **Select an agent** from the sidebar for specialized interfaces
    3. **Try the Complete Workflow** for end-to-end demonstrations
    4. **View results** in real-time with detailed analysis
    
    💡 **Tip:** The chat interface automatically routes your question to the most appropriate agent!
    """)

if __name__ == "__main__":
    main()
