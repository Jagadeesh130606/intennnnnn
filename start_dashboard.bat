@echo off
:: start_dashboard.bat
:: Always launches server.py using the project venv (Python 3.11)
:: so llm_guard, torch, and all venv packages are found correctly.

SET ROOT=%~dp0
SET VENV_PYTHON=%ROOT%venv\Scripts\python.exe
SET SERVER=%ROOT%dashboard\server.py

echo ============================================================
echo   Shadow AI Dashboard Launcher
echo   Using Python: %VENV_PYTHON%
echo ============================================================

IF NOT EXIST "%VENV_PYTHON%" (
    echo ERROR: venv Python not found at %VENV_PYTHON%
    echo Make sure you created the venv with:
    echo   python -m venv venv
    echo   venv\Scripts\pip install flask llm-guard
    pause
    exit /b 1
)

:: Install flask into venv if missing
"%VENV_PYTHON%" -c "import flask" 2>nul
IF ERRORLEVEL 1 (
    echo Installing flask into venv...
    "%VENV_PYTHON%" -m pip install flask
)

echo.
echo Starting server... open http://localhost:5000 in your browser
echo Press Ctrl+C to stop.
echo.

"%VENV_PYTHON%" "%SERVER%"
pause
