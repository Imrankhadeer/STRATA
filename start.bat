@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   TERNLINE - Security Intelligence Engine
echo   Fast Track Threat Detection ^& Meta AI Deep Track
echo ============================================================
echo.

REM Check if --local flag was provided
set FORCE_LOCAL=0
if "%1"=="--local" set FORCE_LOCAL=1

REM Check if Docker is installed and running
set HAS_DOCKER=0
docker info >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set HAS_DOCKER=1
)

if %FORCE_LOCAL% equ 0 if %HAS_DOCKER% equ 1 (
    echo [OK] Docker daemon detected!
    echo ==^> Booting full distributed production stack with Docker Compose...
    echo     - PostgreSQL 16 (Port 5433)
    echo     - Redis 7 (Port 6379)
    echo     - Ternline API ^& Console (Port 8000)
    echo.
    echo ==^> Control Console will be available at: http://localhost:8000/console
    echo     (Click "⚡ 1-Click Demo Login" to enter instantly with pre-seeded keys)
    echo.
    docker compose up --build
    goto :eof
)

echo ==^> Starting Ternline in Local Python Mode...
echo.

REM 1. Ensure .env exists
if not exist ".env" (
    echo ==^> Creating local .env from .env.example with development defaults...
    copy .env.example .env >nul
    powershell -Command "(Get-Content .env) -replace 'ENVIRONMENT=production', 'ENVIRONMENT=development' | Set-Content .env"
)

REM 2. Check Python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not found in PATH. Please install Python 3.12+ from python.org.
    pause
    exit /b 1
)

REM 3. Virtual Environment Setup
if not exist ".venv" (
    echo ==^> Creating Python virtual environment in .venv...
    python -m venv .venv
)

echo ==^> Activating virtual environment...
call .venv\Scripts\activate.bat

REM 4. Dependencies
echo ==^> Verifying dependencies from requirements.txt...
pip install -q -r requirements.txt

REM 5. Migrations
echo ==^> Applying Alembic migrations...
alembic upgrade head

REM 6. Start Server
echo.
echo ============================================================
echo   🚀 TERNLINE SERVER STARTING
echo   Console:  http://localhost:8000/console
echo   API Docs: http://localhost:8000/docs
echo   Metrics:  http://localhost:8000/metrics
echo ============================================================
echo   Tip: Click "⚡ 1-Click Demo Login" in the console to evaluate.
echo ============================================================
echo.

uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
