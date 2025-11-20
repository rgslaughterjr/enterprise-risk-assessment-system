@echo off
REM Streamlit App Launcher - Double-click to start
cd /d "C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system"
start /min cmd /k streamlit run app.py
echo Streamlit app started! Access at http://localhost:8501
timeout /t 3
