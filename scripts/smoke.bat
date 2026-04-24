@echo off
REM Windows wrapper: runs the smoke test using the venv's Python if active.
setlocal
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe scripts\smoke.py %*
) else (
    python scripts\smoke.py %*
)
