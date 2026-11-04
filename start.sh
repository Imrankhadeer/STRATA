#!/usr/bin/env bash
# ==============================================================================
# TERNLINE (CYBER ENGINE) — Automated Quickstart Script
# ==============================================================================
# Usage:
#   ./start.sh          # Auto-detects Docker (recommended) or falls back to local Python
#   ./start.sh --local  # Forces local Python virtual environment execution
# ==============================================================================

set -e

echo ""
echo "============================================================"
echo "  TERNLINE — Security Intelligence Engine"
echo "  Fast Track Threat Detection & Meta AI Deep Track"
echo "============================================================"
echo ""

# Check if --local flag was explicitly passed
FORCE_LOCAL=false
if [ "$1" = "--local" ]; then
  FORCE_LOCAL=true
fi

# Check if Docker and Docker Compose are available and running
HAS_DOCKER=false
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  HAS_DOCKER=true
fi

if [ "$FORCE_LOCAL" = false ] && [ "$HAS_DOCKER" = true ]; then
  echo "==> Docker daemon detected!"
  echo "==> Booting full distributed production stack with Docker Compose..."
  echo "    - PostgreSQL 16 (Port 5433)"
  echo "    - Redis 7 (Port 6379)"
  echo "    - Ternline API & Console (Port 8000)"
  echo ""
  echo "==> Control Console will be available at: http://localhost:8000/console"
  echo "    (Click '⚡ 1-Click Demo Login' to enter instantly with pre-seeded keys)"
  echo ""
  
  if docker compose version >/dev/null 2>&1; then
    docker compose up --build
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose up --build
  else
    echo "⚠️ Docker Compose plugin not found, falling back to local Python mode..."
    FORCE_LOCAL=true
  fi
fi

if [ "$FORCE_LOCAL" = true ] || [ "$HAS_DOCKER" = false ]; then
  if [ "$HAS_DOCKER" = false ]; then
    echo "⚠️ Docker daemon is not running or not installed."
  fi
  echo "==> Starting Ternline in Local Python Mode..."
  echo ""

  # 1. Environment file check
  if [ ! -f ".env" ]; then
    echo "==> Creating default local .env configuration from .env.example..."
    cp .env.example .env
    # Ensure development mode is enabled for pre-seeded dev tenant & keys
    if [[ "$OSTYPE" == "darwin"* ]]; then
      sed -i '' 's/ENVIRONMENT=production/ENVIRONMENT=development/' .env
    else
      sed -i 's/ENVIRONMENT=production/ENVIRONMENT=development/' .env
    fi
  fi

  # 2. Python runtime verification
  PYTHON_CMD=""
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
  else
    echo "❌ Error: Python is not installed. Please install Python 3.12+."
    exit 1
  fi

  # 3. Virtual environment setup
  if [ ! -f ".venv/bin/activate" ] && [ ! -f ".venv/Scripts/activate" ]; then
    echo "==> Creating or repairing Python virtual environment in .venv..."
    rm -rf .venv 2>/dev/null || true
    if ! $PYTHON_CMD -m venv .venv; then
      echo "❌ Error: Failed to create virtual environment."
      echo "👉 On Ubuntu/Debian/WSL, you may need to run: sudo apt update && sudo apt install -y python3-venv python3-pip"
      exit 1
    fi
  fi

  echo "==> Activating virtual environment..."
  if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
  elif [ -f ".venv/Scripts/activate" ]; then
    source .venv/Scripts/activate
  else
    echo "❌ Error: Could not find virtual environment activation script in .venv/bin or .venv/Scripts."
    exit 1
  fi

  # 4. Dependency installation
  echo "==> Ensuring required dependencies are installed..."
  pip install -q --upgrade pip
  pip install -q -r requirements.txt

  # 5. Database migrations
  echo "==> Applying Alembic database migrations..."
  alembic upgrade head || echo "⚠️ Warning: Database migration failed. Ensure PostgreSQL 16 is running on DATABASE_URL."

  # 6. Launch Uvicorn
  echo ""
  echo "============================================================"
  echo "  🚀 TERNLINE SERVER STARTING"
  echo "  Console:  http://localhost:8000/console"
  echo "  API Docs: http://localhost:8000/docs"
  echo "  Metrics:  http://localhost:8000/metrics"
  echo "============================================================"
  echo "  Tip: Click '⚡ 1-Click Demo Login' in the console to evaluate."
  echo "============================================================"
  echo ""

  exec uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
fi
