# Streamlit App Launcher
# This script starts the Streamlit app and keeps it running

$appPath = "C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system"
$appFile = "app.py"

# Change to app directory
Set-Location $appPath

# Start Streamlit in a new window that stays open
Start-Process powershell -ArgumentList "-NoExit", "-Command", "streamlit run $appFile" -WindowStyle Minimized

Write-Host "✅ Streamlit app started in background"
Write-Host "📱 Access at: http://localhost:8501"
Write-Host "🔄 App will keep running in minimized window"
