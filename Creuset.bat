@echo off
REM ---------------------------------------------------------------------------
REM Creuset — double-click launcher for the results browser.
REM
REM Starts the local web app and opens it in your default browser. Nothing is
REM hosted anywhere: it binds to 127.0.0.1, so it is reachable only from this
REM machine. Docker does NOT need to be running to browse past results.
REM
REM Close this window to stop the app.
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

set PORT=8090
set PY=.venv\Scripts\python.exe

if not exist "%PY%" (
  echo.
  echo   Could not find %PY%
  echo   Expected the virtualenv at the repo root. Create it with:
  echo.
  echo       python -m venv .venv
  echo       .venv\Scripts\python.exe -m pip install -r requirements.txt
  echo.
  pause
  exit /b 1
)

echo.
echo   Creuset results browser
echo   http://127.0.0.1:%PORT%
echo.
echo   Close this window to stop.
echo.

REM Give uvicorn a moment to bind before the browser asks for the page.
start "" /b cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:%PORT%"

"%PY%" -m uvicorn ui.app:app --host 127.0.0.1 --port %PORT%
