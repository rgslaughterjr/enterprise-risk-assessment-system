@echo off
REM ============================================================================
REM Streamlit Risk Assessment App Launcher (Batch Version)
REM ============================================================================
REM Description: Quick launcher for Streamlit app
REM Usage: Double-click this file to start the app
REM ============================================================================

title Enterprise Risk Assessment System - Streamlit Launcher

echo ============================================================================
echo   Enterprise Risk Assessment System - Streamlit Launcher
echo ============================================================================
echo.

REM Change to app directory
cd /d "C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system"

REM Check if already running
tasklist /FI "IMAGENAME eq streamlit.exe" 2>NUL | find /I /N "streamlit.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo WARNING: Streamlit appears to be already running!
    echo.
    echo Local Access:   http://localhost:8501
    echo Network Access: http://192.168.86.250:8501
    echo.
    choice /C YN /M "Do you want to restart the app"
    if errorlevel 2 goto :open_browser
    if errorlevel 1 goto :kill_and_restart
) else (
    goto :start_app
)

:kill_and_restart
echo.
echo Stopping existing Streamlit process...
taskkill /F /IM streamlit.exe >NUL 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq streamlit*" >NUL 2>&1
timeout /t 2 /nobreak >NUL
goto :start_app

:start_app
echo.
echo Starting Streamlit app...
echo.
start /min cmd /k streamlit run app.py
timeout /t 5 /nobreak >NUL

echo.
echo ============================================================================
echo   App Started Successfully!
echo ============================================================================
echo.
echo Local Access:   http://localhost:8501
echo Network Access: http://192.168.86.250:8501
echo.
echo The app is running in a minimized window
echo To stop: Close the minimized window or use Task Manager
echo.

:open_browser
choice /C YN /M "Open browser now"
if errorlevel 2 goto :end
if errorlevel 1 start http://localhost:8501

:end
echo.
echo Press any key to exit...
pause >nul
