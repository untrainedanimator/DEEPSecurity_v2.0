@echo off
REM ======================================================================
REM  DEEPSecurity 24-hour soak runner (Windows) — lightweight by default.
REM
REM  Default behaviour:
REM    * verify_v2_5 every cycle (~10–15s, idle priority)
REM    * e2e_full only every 4th cycle (~70–90s, idle priority)
REM    * incremental backup every cycle, --keep 48
REM    * pause cycle when laptop is on battery
REM
REM  Usage:
REM     scripts\loop_24h.bat                  REM 24h, every 15 min, lightweight
REM     scripts\loop_24h.bat 12 30            REM 12h, every 30 min, lightweight
REM     scripts\loop_24h.bat 1 5  fast        REM 1h smoke (no E2E)
REM     scripts\loop_24h.bat 24 15 heavy      REM full E2E every cycle, normal priority
REM ======================================================================

setlocal enableextensions enabledelayedexpansion

set "ROOT=%~dp0.."
pushd "%ROOT%"

if not exist ".venv\Scripts\activate.bat" (
    echo [loop_24h.bat] .venv not found at %ROOT%\.venv
    echo Run:    py -3.12 -m venv .venv ^&^& .venv\Scripts\activate ^&^& pip install -r requirements-dev.txt
    popd
    exit /b 1
)

call ".venv\Scripts\activate.bat"

set "HOURS=%~1"
set "INTERVAL=%~2"
set "MODE=%~3"
if "%HOURS%"=="" set "HOURS=24"
if "%INTERVAL%"=="" set "INTERVAL=15"

set "EXTRA="
if /I "%MODE%"=="fast"  set "EXTRA=--skip-e2e"
if /I "%MODE%"=="heavy" set "EXTRA=--no-lightweight --e2e-every 1"

echo [loop_24h.bat] hours=%HOURS%   interval=%INTERVAL%   mode=%MODE% %EXTRA%
echo [loop_24h.bat] press Ctrl-C in this window to stop cleanly.
echo.

python scripts\loop_24h.py --hours %HOURS% --interval-min %INTERVAL% %EXTRA%
set "RC=%ERRORLEVEL%"

popd
endlocal & exit /b %RC%
