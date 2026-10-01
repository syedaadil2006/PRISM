@echo off
title PRISM launcher
rem Double-click to start PRISM and open it in your browser.
rem Works from wherever this folder lives (it uses its own location).
cd /d "%~dp0"

rem First run only: create the Python environment.
if not exist ".venv\Scripts\python.exe" (
    echo First run: setting up Python environment, please wait...
    python -m venv .venv || goto :fail
    ".venv\Scripts\python.exe" -m pip install -q -r backend\requirements.txt || goto :fail
)

rem First run only: build the dashboard.
if not exist "frontend\dist\index.html" (
    echo First run: building the dashboard, please wait...
    call npm --prefix frontend install || goto :fail
    call npm --prefix frontend run build || goto :fail
)

rem Start the server in its own minimised window (skipped if already running).
call :ready
if errorlevel 1 (
    echo Starting PRISM...
    start "PRISM server - close this window to stop PRISM" /min ".venv\Scripts\python.exe" -m uvicorn app.main:app --app-dir backend --port 8000
)

rem Wait until it answers, then open the browser.
set /a tries=0
:wait
call :ready
if not errorlevel 1 goto :open
set /a tries+=1
if %tries% geq 60 goto :fail
timeout /t 1 /nobreak >nul
goto :wait

:open
start "" "http://localhost:8000"
exit /b 0

:ready
powershell -NoProfile -Command "try { Invoke-WebRequest http://127.0.0.1:8000/api/health -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }"
exit /b %errorlevel%

:fail
echo.
echo PRISM could not start. See the messages above.
pause
exit /b 1
