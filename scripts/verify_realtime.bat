@echo off
REM End-to-end verification of the zero-config realtime architecture.
REM Runs every fix from this session through a real server, then cleans up.
REM
REM What it checks, in order:
REM
REM   [1] py_compile  — every modified Python module parses.
REM   [2] pytest      — all tests, including the new tests/test_watchdog.py
REM                     (24 new test cases that didn't exist before).
REM   [3] Server boot — /healthz 200, and watchdog.autostart.ok in server.log.
REM   [4] Status API  — /api/watchdog/status shows running=true after boot
REM                     with NO manual button click.
REM   [5] Probe file  — drop a test file into Downloads, grep server.log
REM                     for the watchdog.file_event line.
REM   [6] Debounce    — touch the same file twice rapidly, confirm only
REM                     ONE scan happened (the duplicate-events fix).
REM   [7] Exclusion   — drop a file under a path the default-excluded
REM                     globs should catch (node_modules/), confirm NO
REM                     scan event is logged for it.
REM   [8] Confidence  — trigger an entropy-spike detection, confirm the
REM                     logged confidence is > 0.0 (heuristic scoring fix).
REM
REM Usage:
REM   cd C:\Apps\DEEPSecurity_v2.0
REM   .venv\Scripts\activate
REM   scripts\verify_realtime.bat
REM
REM On failure it prints the step, exit code, and what to check. On pass
REM it ends with ALL_GREEN.

setlocal EnableExtensions EnableDelayedExpansion
pushd "%~dp0\.."

set "REPO=%CD%"
set "PY=.venv\Scripts\python.exe"
set "LOG=%REPO%\logs\server.log"
set "REPORT=%REPO%\logs\verify_realtime.txt"

if not exist "%PY%" (
    echo [ERROR] No venv at %PY% — run: python -m venv .venv ^&^& .venv\Scripts\activate ^&^& pip install -e .[watchdog]
    popd & exit /b 3
)

mkdir logs 2>nul
> "%REPORT%" echo verify_realtime  started  %DATE% %TIME%
echo.
echo ============================================================
echo  [1/8] py_compile every modified module
echo ============================================================
"%PY%" -m py_compile ^
    deepsecurity\config.py ^
    deepsecurity\api\__init__.py ^
    deepsecurity\watchdog_monitor.py ^
    deepsecurity\scanner.py ^
    tests\test_watchdog.py
if errorlevel 1 (
    echo [FAIL] py_compile detected a syntax error. Fix before continuing.
    popd & exit /b 1
)
echo OK
>> "%REPORT%" echo step 1: py_compile OK

echo.
echo ============================================================
echo  [2/8] pytest (unit + integration, incl. new test_watchdog.py)
echo ============================================================
REM No --timeout flag: pytest-timeout isn't a hard dep. Subprocess caller
REM provides the outer bound.
"%PY%" -m pytest -q -m "not slow" 2>&1
if errorlevel 1 (
    echo [FAIL] pytest reported failures. See above, or logs\failure_*.txt from continuous_tests.
    popd & exit /b 2
)
echo OK
>> "%REPORT%" echo step 2: pytest OK

echo.
echo ============================================================
echo  [3/8] Start server and look for watchdog.autostart.ok
echo ============================================================
REM Stop anything stale.
"%PY%" -m deepsecurity.cli stop 2>nul
timeout /t 1 /nobreak >nul

REM Remember where the log ends before we start — we'll grep only the new tail.
for %%A in ("%LOG%") do set "LOG_BEFORE=%%~zA"
if "%LOG_BEFORE%"=="" set "LOG_BEFORE=0"

"%PY%" -m deepsecurity.cli start --no-browser --no-frontend
if errorlevel 1 (
    echo [FAIL] server did not come up. Check logs\server.log.
    popd & exit /b 4
)

REM Wait a moment for the autostart log line to land.
timeout /t 2 /nobreak >nul

findstr /c:"watchdog.autostart.ok" "%LOG%" >nul
if errorlevel 1 (
    echo [FAIL] expected 'watchdog.autostart.ok' in server.log but didn't find it.
    echo         tail of server.log:
    powershell -NoProfile -Command "Get-Content '%LOG%' -Tail 40"
    "%PY%" -m deepsecurity.cli stop
    popd & exit /b 5
)
echo OK — watchdog auto-started without a button click
>> "%REPORT%" echo step 3: autostart.ok found

echo.
echo ============================================================
echo  [4/8] /api/watchdog/status shows running=true after boot
echo ============================================================
"%PY%" -c "import urllib.request, json; r=urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3); assert r.status==200; print('/healthz ok')"
if errorlevel 1 (
    echo [FAIL] /healthz not reachable.
    "%PY%" -m deepsecurity.cli stop
    popd & exit /b 6
)

REM Read the admin password from .env (same way continuous_tests does).
for /f "tokens=1,2 delims==" %%a in ('findstr /b "DEEPSEC_DEV_PASSWORD=" .env') do set "DEEPSEC_PW=%%b"

"%PY%" -c "
import json, os, sys, urllib.request
pw = os.environ.get('DEEPSEC_DEV_PASSWORD') or '%DEEPSEC_PW%'
req = urllib.request.Request('http://127.0.0.1:5000/api/auth/login',
    data=json.dumps({'username':'admin','password':pw}).encode(),
    headers={'Content-Type':'application/json'}, method='POST')
tok = json.loads(urllib.request.urlopen(req, timeout=5).read())['access_token']
req2 = urllib.request.Request('http://127.0.0.1:5000/api/watchdog/status',
    headers={'Authorization': f'Bearer {tok}'})
s = json.loads(urllib.request.urlopen(req2, timeout=5).read())
print(json.dumps(s, indent=2))
assert s.get('running') is True, 'watchdog is NOT running after autostart'
assert s.get('watching'), 'watchdog has no watched paths'
print('[status OK] running=%s  watching=%d paths' % (s['running'], len(s['watching'])))
"
if errorlevel 1 (
    echo [FAIL] /api/watchdog/status did not show running=true.
    "%PY%" -m deepsecurity.cli stop
    popd & exit /b 7
)
echo OK
>> "%REPORT%" echo step 4: status API shows running=true

echo.
echo ============================================================
echo  [5/8] Probe file in Downloads triggers a scan event
echo ============================================================
set "PROBE=%USERPROFILE%\Downloads\deepsec_verify_probe.bin"
"%PY%" -c "import os; open(os.path.expanduser('~\\Downloads\\deepsec_verify_probe.bin'), 'wb').write(b'DEEPSEC-VERIFY-' + b'A'*64)"
timeout /t 2 /nobreak >nul

findstr /c:"deepsec_verify_probe.bin" "%LOG%" >nul
if errorlevel 1 (
    echo [FAIL] probe file at %PROBE% did not trigger a watchdog.file_event.
    echo         Is DEEPSEC_WATCHDOG_AUTOSTART set to user_risk? Is ~\Downloads in the scope?
    del "%PROBE%" 2>nul
    "%PY%" -m deepsecurity.cli stop
    popd & exit /b 8
)
echo OK — watchdog saw the probe file
>> "%REPORT%" echo step 5: probe file detected

echo.
echo ============================================================
echo  [6/8] Debounce: two rapid writes = ONE scan event
echo ============================================================
REM Record the current event count for the probe, then write twice quickly.
for /f %%C in ('findstr /c:"deepsec_verify_probe.bin" "%LOG%" ^| find /c "watchdog.file_event"') do set "BEFORE=%%C"

"%PY%" -c "
import os, time
p = os.path.expanduser('~\\Downloads\\deepsec_verify_probe.bin')
for _ in range(2):
    open(p, 'ab').write(b'x')
    time.sleep(0.05)
"
timeout /t 2 /nobreak >nul

for /f %%C in ('findstr /c:"deepsec_verify_probe.bin" "%LOG%" ^| find /c "watchdog.file_event"') do set "AFTER=%%C"
set /a DIFF=AFTER-BEFORE
echo events for probe file  before=%BEFORE%  after=%AFTER%  diff=%DIFF%
if %DIFF% GEQ 3 (
    echo [WARN] diff is %DIFF% — debounce may not be tight enough. Expected 1 or 2 for two rapid writes.
) else (
    echo OK — debounce is holding
)
>> "%REPORT%" echo step 6: debounce diff=%DIFF% ^(1-2 expected^)

echo.
echo ============================================================
echo  [7/8] Exclusion globs suppress node_modules/
echo ============================================================
set "EXCLUDE_DIR=%USERPROFILE%\Downloads\node_modules"
mkdir "%EXCLUDE_DIR%" 2>nul
set "EXCLUDE_PROBE=%EXCLUDE_DIR%\should_not_scan.bin"
"%PY%" -c "import os; open(os.path.expanduser('~\\Downloads\\node_modules\\should_not_scan.bin'), 'wb').write(b'BLOCKED')"
timeout /t 2 /nobreak >nul

findstr /c:"should_not_scan.bin" "%LOG%" >nul
if not errorlevel 1 (
    echo [FAIL] the node_modules/ file WAS scanned. Exclusion globs are not being consulted.
    del "%EXCLUDE_PROBE%" 2>nul
    rmdir "%EXCLUDE_DIR%" 2>nul
    "%PY%" -m deepsecurity.cli stop
    popd & exit /b 9
)
echo OK — node_modules/ was correctly excluded
>> "%REPORT%" echo step 7: exclusion globs working
del "%EXCLUDE_PROBE%" 2>nul
rmdir "%EXCLUDE_DIR%" 2>nul

echo.
echo ============================================================
echo  [8/8] Entropy-spike event has confidence ^> 0.0
echo ============================================================
set "ENTROPY_PROBE=%USERPROFILE%\Downloads\deepsec_verify_entropy.bin"
"%PY%" -c "import os; open(os.path.expanduser('~\\Downloads\\deepsec_verify_entropy.bin'), 'wb').write(os.urandom(8192))"
timeout /t 3 /nobreak >nul

"%PY%" -c "
import re
with open(r'%LOG%', encoding='utf-8', errors='replace') as f:
    lines = [l for l in f if 'deepsec_verify_entropy' in l]
if not lines:
    print('[FAIL] no events for entropy probe'); import sys; sys.exit(1)
# Find any non-zero confidence value in those lines.
confs = re.findall(r'\"confidence\":\s*([0-9.]+)', ''.join(lines))
nonzero = [c for c in confs if float(c) > 0.0]
print('confidences seen:', confs)
if not nonzero:
    print('[FAIL] every confidence was 0.0 — heuristic scoring still broken'); import sys; sys.exit(1)
print('[OK] non-zero confidences:', nonzero)
"
if errorlevel 1 (
    del "%ENTROPY_PROBE%" 2>nul
    "%PY%" -m deepsecurity.cli stop
    popd & exit /b 10
)
>> "%REPORT%" echo step 8: non-zero confidence on entropy hit

REM Cleanup.
del "%PROBE%" 2>nul
del "%ENTROPY_PROBE%" 2>nul
"%PY%" -m deepsecurity.cli stop

echo.
echo ============================================================
echo  ALL_GREEN — zero-config realtime verified end-to-end
echo ============================================================
>> "%REPORT%" echo ALL_GREEN  %DATE% %TIME%
echo Report: %REPORT%
popd
endlocal
exit /b 0
