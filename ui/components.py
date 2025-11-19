"""
UI Components - Reusable Streamlit components
"""

import streamlit as st
import json
import pandas as pd
from typing import Any, Dict, List

def setup_page(title: str, icon: str = "🛡️"):
    """Setup page configuration"""
    st.markdown(f'<div class="main-header">{icon} {title}</div>', unsafe_allow_html=True)

def display_header(title: str, description: str):
    """Display page header"""
    st.title(title)
    st.markdown(description)
    st.markdown("---")

def display_chat_message(role: str, content: str):
    """Display a chat message"""
    with st.chat_message(role):
        st.markdown(content)

def display_result(result: Any, format_type: str = "auto"):
    """Display result in appropriate format"""
    
    if result is None:
        st.warning("No result returned")
        return
    
    # Auto-detect format
    if format_type == "auto":
        if isinstance(result, dict):
            format_type = "json"
        elif isinstance(result, list):
            format_type = "table"
        else:
            format_type = "text"
    
    # Display based on format
    if format_type == "json":
        display_json_result(result)
    elif format_type == "table":
        display_table_result(result)
    elif format_type == "markdown":
        st.markdown(result)
    else:
        st.text(result)

def display_json_result(data: Dict):
    """Display JSON data in expandable format"""
    with st.expander("📊 View JSON Data", expanded=True):
        st.json(data)

def display_table_result(data: List[Dict]):
    """Display list of dictionaries as table"""
    if not data:
        st.info("No data to display")
        return
    
    try:
        df = pd.DataFrame(data)
        st.dataframe(df, use_container_width=True)
    except Exception as e:
        st.error(f"Error displaying table: {e}")
        st.json(data)

def display_error(error: Exception):
    """Display error message"""
    st.markdown(f"""
    <div class="error-box">
        <strong>❌ Error:</strong> {str(error)}
    </div>
    """, unsafe_allow_html=True)

def display_success(message: str):
    """Display success message"""
    st.markdown(f"""
    <div class="success-box">
        <strong>✅ Success:</strong> {message}
    </div>
    """, unsafe_allow_html=True)

def display_info(message: str):
    """Display info message"""
    st.markdown(f"""
    <div class="info-box">
        <strong>ℹ️ Info:</strong> {message}
    </div>
    """, unsafe_allow_html=True)

def create_input_form(fields: List[Dict]) -> Dict:
    """Create dynamic input form
    
    Args:
        fields: List of field definitions with keys:
            - name: Field name
            - type: Input type (text, number, select, multiselect, textarea)
            - label: Display label
            - options: Options for select/multiselect
            - default: Default value
            - help: Help text
    
    Returns:
        Dictionary of field values
    """
    values = {}
    
    for field in fields:
        name = field['name']
        field_type = field.get('type', 'text')
        label = field.get('label', name)
        default = field.get('default', None)
        help_text = field.get('help', None)
        
        if field_type == 'text':
            values[name] = st.text_input(label, value=default or "", help=help_text)
        elif field_type == 'number':
            values[name] = st.number_input(label, value=default or 0, help=help_text)
        elif field_type == 'select':
            options = field.get('options', [])
            values[name] = st.selectbox(label, options, help=help_text)
        elif field_type == 'multiselect':
            options = field.get('options', [])
            values[name] = st.multiselect(label, options, default=default, help=help_text)
        elif field_type == 'textarea':
            values[name] = st.text_area(label, value=default or "", help=help_text)
        elif field_type == 'checkbox':
            values[name] = st.checkbox(label, value=default or False, help=help_text)
    
    return values

def display_agent_status(agent_name: str, status: str = "ready"):
    """Display agent status indicator"""
    status_icons = {
        "ready": "✅",
        "running": "⏳",
        "error": "❌",
        "success": "🎉"
    }
    
    icon = status_icons.get(status, "ℹ️")
    st.markdown(f"**Agent Status:** {icon} {agent_name} - {status.title()}")

def create_tabs(tab_names: List[str]):
    """Create tabs for organizing content"""
    return st.tabs(tab_names)

def display_metrics(metrics: Dict[str, Any]):
    """Display metrics in columns"""
    cols = st.columns(len(metrics))
    
    for col, (label, value) in zip(cols, metrics.items()):
        with col:
            st.metric(label, value)

def file_uploader(label: str, file_types: List[str] = None):
    """Create file uploader widget"""
    return st.file_uploader(label, type=file_types)

def display_code(code: str, language: str = "python"):
    """Display code block"""
    st.code(code, language=language)

def create_download_button(data: str, filename: str, label: str = "Download"):
    """Create download button"""
    st.download_button(
        label=label,
        data=data,
        file_name=filename,
        mime="text/plain"
    )

def display_progress(progress: float, text: str = ""):
    """Display progress bar"""
    st.progress(progress, text=text)

def display_spinner(text: str = "Processing..."):
    """Context manager for spinner"""
    return st.spinner(text)
