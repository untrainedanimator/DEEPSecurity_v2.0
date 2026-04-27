@echo off
REM ======================================================================
REM  DEEPSecurity FAST soak runner - 1 hour compressed, metrics enabled.
REM
REM  Compresses a 24-hour soak into roughly 60 minutes:
REM     hours=1   interval=1min   e2e-every=12   metrics ON
REM
REM  Use this before tagging a release, or in CI as a leak-detection gate.
REM  The full 24h run is scripts\loop_24h.bat.
REM
REM  Run from cmd.exe directly (NOT with `python` prefix):
REM     scripts\soak_loop_fast.bat
REM ======================================================================

setlocal enableextensions enabledelayedexpansion

set "ROOT=%~dp0.."
pushd "%ROOT%"

if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"

echo [soak_loop_fast] starting 1-hour fast soak
echo [soak_loop_fast] press Ctrl-C in this window to stop cleanly.
echo.

python scripts\loop_24h.py --fast %*
set "RC=%ERRORLEVEL%"

popd
endlocal & exit /b %RC%
