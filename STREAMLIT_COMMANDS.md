# Quick Commands for Streamlit App Management

## Start the App

### PowerShell (Recommended)
```powershell
cd C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system
.\Launch-StreamlitApp.ps1
```

### Batch File
```cmd
cd C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system
Launch-StreamlitApp.bat
```

### Direct Command
```powershell
cd C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system
streamlit run app.py
```

## Stop the App

### PowerShell
```powershell
Get-Process | Where-Object {$_.ProcessName -like "*streamlit*"} | Stop-Process -Force
```

### Command Prompt
```cmd
taskkill /F /IM streamlit.exe
taskkill /F /IM python.exe /FI "WINDOWTITLE eq streamlit*"
```

## Check if Running

### PowerShell
```powershell
Get-Process | Where-Object {$_.ProcessName -like "*streamlit*"}
```

### Command Prompt
```cmd
tasklist | findstr streamlit
```

## Access URLs

- **Local**: http://localhost:8501
- **Network**: http://192.168.86.250:8501

## Files Created

1. **Launch-StreamlitApp.ps1** - Full-featured PowerShell launcher
   - Checks if already running
   - Opens browser automatically
   - Interactive prompts

2. **Launch-StreamlitApp.bat** - Batch file launcher
   - Double-click to run
   - Checks for existing process
   - Minimizes to background

3. **Start Streamlit App.bat** - Simple launcher
   - Quick start, no prompts
   - Runs in background

## Recommended Usage

**Daily Use:**
- Double-click `Launch-StreamlitApp.bat`
- Opens browser automatically
- App runs in background

**From PowerShell:**
- Right-click `Launch-StreamlitApp.ps1`
- Select "Run with PowerShell"

**Auto-Start on Login:**
1. Press `Win + R`
2. Type: `shell:startup`
3. Copy `Launch-StreamlitApp.bat` to that folder
4. App starts automatically when you log in

## Troubleshooting

**App won't start:**
```powershell
# Kill all Python/Streamlit processes
Get-Process python,streamlit -ErrorAction SilentlyContinue | Stop-Process -Force

# Try starting again
cd C:\Users\richa\Documents\ai-agent-course\enterprise-risk-assessment-system
streamlit run app.py
```

**Port 8501 already in use:**
```powershell
# Find what's using the port
netstat -ano | findstr :8501

# Kill the process (replace PID with actual process ID)
taskkill /F /PID <PID>
```

**Can't access from network:**
- Check Windows Firewall
- Ensure you're on the same network
- Use the Network URL: http://192.168.86.250:8501
