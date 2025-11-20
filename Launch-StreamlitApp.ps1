# ============================================================================
# Streamlit Risk Assessment App Launcher
# ============================================================================
# Description: Launches the Streamlit app and opens it in your default browser
# Usage: Right-click → "Run with PowerShell" OR run from PowerShell terminal
# ============================================================================

# Configuration
$AppDirectory = "C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system"
$AppFile = "app.py"
$LocalURL = "http://localhost:8501"
$NetworkURL = "http://192.168.86.250:8501"

# Display banner
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  Enterprise Risk Assessment System - Streamlit Launcher" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

# Check if already running
$existingProcess = Get-Process | Where-Object {$_.ProcessName -like "*streamlit*" -or ($_.CommandLine -like "*streamlit*")}
if ($existingProcess) {
    Write-Host "⚠️  Streamlit is already running!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "📱 Local Access:   $LocalURL" -ForegroundColor Green
    Write-Host "🌐 Network Access: $NetworkURL" -ForegroundColor Green
    Write-Host ""
    
    $response = Read-Host "Do you want to restart the app? (y/N)"
    if ($response -eq 'y' -or $response -eq 'Y') {
        Write-Host "🔄 Stopping existing Streamlit process..." -ForegroundColor Yellow
        Get-Process | Where-Object {$_.ProcessName -like "*streamlit*"} | Stop-Process -Force
        Start-Sleep -Seconds 2
    } else {
        Write-Host "✅ Opening browser to existing app..." -ForegroundColor Green
        Start-Process $LocalURL
        Write-Host ""
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    }
}

# Change to app directory
Write-Host "📂 Navigating to: $AppDirectory" -ForegroundColor Cyan
Set-Location $AppDirectory

# Start Streamlit in background
Write-Host "🚀 Starting Streamlit app..." -ForegroundColor Cyan
$job = Start-Job -ScriptBlock {
    param($dir, $file)
    Set-Location $dir
    streamlit run $file
} -ArgumentList $AppDirectory, $AppFile

# Wait for app to start
Write-Host "⏳ Waiting for app to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Check if app started successfully
$streamlitProcess = Get-Process | Where-Object {$_.ProcessName -like "*streamlit*"}
if ($streamlitProcess) {
    Write-Host ""
    Write-Host "✅ Streamlit app started successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  Access Your App:" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "📱 Local Access:   $LocalURL" -ForegroundColor Green
    Write-Host "🌐 Network Access: $NetworkURL" -ForegroundColor Green
    Write-Host ""
    Write-Host "💡 Tip: The app is running in the background" -ForegroundColor Yellow
    Write-Host "   - Just navigate to the URL above in your browser" -ForegroundColor Yellow
    Write-Host "   - To stop: Open Task Manager and end 'streamlit' process" -ForegroundColor Yellow
    Write-Host ""
    
    # Open browser
    $openBrowser = Read-Host "Open browser now? (Y/n)"
    if ($openBrowser -ne 'n' -and $openBrowser -ne 'N') {
        Write-Host "🌐 Opening browser..." -ForegroundColor Cyan
        Start-Process $LocalURL
    }
} else {
    Write-Host ""
    Write-Host "❌ Failed to start Streamlit app" -ForegroundColor Red
    Write-Host "Please check for errors above" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
