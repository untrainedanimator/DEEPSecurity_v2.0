@echo off
REM Launcher for continuous_tests on Windows. Uses the venv's Python if present.
setlocal
cd /D "%~dp0\.."
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe scripts\continuous_tests.py %*
) else (
    python scripts\continuous_tests.py %*
)
