@echo off
title PRISM launcher
rem Double-click to start PRISM and open it in your browser.
rem The launcher first checks this computer and what PRISM needs. If anything
rem is missing it lists exactly what it will install and asks before doing it.
rem Works from wherever this folder lives (it uses its own location).
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-prism.ps1"
if errorlevel 2 (
    echo.
    echo Setup was cancelled. Nothing was installed.
    pause
    exit /b 2
)
if errorlevel 1 (
    echo.
    echo PRISM could not start. See the messages above.
    pause
    exit /b 1
)
exit /b 0
