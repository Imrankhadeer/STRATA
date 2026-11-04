# ==============================================================================
# TERNLINE (CYBER ENGINE) — Windows PowerShell Startup Script
# ==============================================================================
param (
    [switch]$Local = $false
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  TERNLINE — Security Intelligence Engine" -ForegroundColor Green
Write-Host "  Fast Track Threat Detection & Meta AI Deep Track" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$hasDocker = $false
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        $hasDocker = $true
    }
} catch {
    $hasDocker = $false
}

if (-not $Local -and $hasDocker) {
    Write-Host "[OK] Docker daemon detected!" -ForegroundColor Green
    Write-Host "==> Booting full distributed production stack with Docker Compose..." -ForegroundColor Yellow
    Write-Host "    - PostgreSQL 16 (Port 5433)"
    Write-Host "    - Redis 7 (Port 6379)"
    Write-Host "    - Ternline API & Console (Port 8000)"
    Write-Host ""
    Write-Host "==> Control Console: http://localhost:8000/console" -ForegroundColor Cyan
    Write-Host "    (Click '⚡ 1-Click Demo Login' to enter instantly with pre-seeded keys)" -ForegroundColor Magenta
    Write-Host ""

    docker compose up --build
    exit $LASTEXITCODE
}

Write-Host "==> Starting Ternline in Local Python Mode..." -ForegroundColor Yellow
Write-Host ""

# 1. Check or create .env
if (-not (Test-Path ".env")) {
    Write-Host "==> Creating local .env from .env.example..." -ForegroundColor Gray
    Copy-Item ".env.example" ".env"
    (Get-Content ".env") -replace 'ENVIRONMENT=production', 'ENVIRONMENT=development' | Set-Content ".env"
}

# 2. Virtual environment check
if (-not (Test-Path ".venv")) {
    Write-Host "==> Creating virtual environment in .venv..." -ForegroundColor Gray
    python -m venv .venv
}

# 3. Activate venv
if (Test-Path ".\.venv\Scripts\Activate.ps1") {
    Write-Host "==> Activating virtual environment..." -ForegroundColor Gray
    & ".\.venv\Scripts\Activate.ps1"
}

# 4. Install dependencies
Write-Host "==> Checking dependencies in requirements.txt..." -ForegroundColor Gray
pip install -q -r requirements.txt

# 5. Database migrations
Write-Host "==> Applying database migrations..." -ForegroundColor Gray
try {
    alembic upgrade head
} catch {
    Write-Host "⚠️ Warning: Database migration failed. Ensure PostgreSQL 16 is running on DATABASE_URL." -ForegroundColor DarkYellow
}

# 6. Launch Server
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  🚀 TERNLINE SERVER STARTING" -ForegroundColor Green
Write-Host "  Console:  http://localhost:8000/console" -ForegroundColor White
Write-Host "  API Docs: http://localhost:8000/docs" -ForegroundColor White
Write-Host "  Metrics:  http://localhost:8000/metrics" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Tip: Click '⚡ 1-Click Demo Login' in the console to evaluate." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
