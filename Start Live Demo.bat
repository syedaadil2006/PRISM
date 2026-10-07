@echo off
title PRISM live feed demo
rem Streams the demo attack into a running PRISM in real time, with current
rem timestamps, through the live feed API. Start PRISM first.
rem The dataset is cleared so PRISM analyses only the live events; use
rem "Show full dataset" or Reset in the dashboard to bring it back.
cd /d "%~dp0"

set "PY=.venv\Scripts\python.exe"
if not exist "%PY%" (
    echo PRISM is not set up yet. Run "Start PRISM.bat" first.
    pause
    exit /b 1
)

"%PY%" scripts\live_replay.py %*
echo.
pause
