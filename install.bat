@echo off
cd /d "%~dp0"

echo ============================================
echo  burpAI - Burp Suite AI Agent Bridge
echo  One-click Windows Setup
echo ============================================
echo.

:: Install dependencies
echo [1/3] Installing npm dependencies...
call npm install --no-fund 2>nul
if %errorlevel% neq 0 (
    echo [!] npm install failed. Make sure Node.js is installed.
    echo    Download: https://nodejs.org
    pause
    exit /b 1
)
echo Done.
echo.

:: Create .mcp.json
echo [2/3] Creating MCP config...
set "MCP_FILE=%~dp0.mcp.json"
echo {> "%MCP_FILE%"
echo   "mcpServers": {>> "%MCP_FILE%"
echo     "burp": {>> "%MCP_FILE%"
echo       "type": "local",>> "%MCP_FILE%"
echo       "command": ["node", "%~dp0src\index.js"]>> "%MCP_FILE%"
echo     }>> "%MCP_FILE%"
echo   }>> "%MCP_FILE%"
echo }>> "%MCP_FILE%"
echo Done.
echo.

:: Done
echo [3/3] Setup complete!
echo.
echo ============================================
echo  NEXT STEPS:
echo ============================================
echo.
echo  1. Start server (manual test):
echo     node "%~dp0src\index.js"
echo.
echo  2. Open Burp Suite -^> Extensions -^> Add
echo     File: "%~dp0plugin\burpAI.py"
echo.
echo  3. In BurpAI tab, set URL to http://127.0.0.1:9999
echo     Check: Auto-send Proxy + Auto-send Repeater
echo.
echo  4. Open OpenCode in this folder:
echo     %~dp0
echo.
echo  Server auto-finds port 9999 or the next available.
echo ============================================
echo.
pause
