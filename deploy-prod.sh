#!/bin/bash
# ==============================================================================
# Ternline (CYBER ENGINE) Production Deployment Script for AWS EC2
# Bypasses Docker Compose buildx requirements by building natively with docker build
# ==============================================================================
set -e

echo "=========================================================="
echo " Ternline Production Deployment on AWS EC2"
echo "=========================================================="

# 1. Ensure .env.production exists
if [ ! -f .env.production ]; then
  if [ -f .env.production.example ]; then
    echo "[!] .env.production not found. Copying from .env.production.example..."
    cp .env.production.example .env.production
    echo "[!] Please verify or edit your .env.production secrets."
  else
    echo "[ERROR] .env.production not found!"
    exit 1
  fi
fi

# 2. Fix unescaped dollar signs (e.g. $ostNCc) that cause docker compose interpolation warnings
if grep -q '\$ostNCc' .env.production 2>/dev/null; then
  echo "[i] Escaping literal dollar signs in .env.production to prevent interpolation warnings..."
  sed -i 's/\$ostNCc/\$\$ostNCc/g' .env.production
fi

# 3. Build image directly with standard Docker daemon (does not require docker-buildx-plugin >= 0.17.0)
echo "==> Building backend Docker image natively..."
docker build -t ternline/backend:latest .

# 4. Bring up PostgreSQL 16, Redis 7+, and Ternline Backend
echo "==> Launching production containers via Docker Compose..."
docker compose -f docker-compose.prod.yml --env-file .env.production up -d

# 5. Output status and health
echo "==> Production services status:"
docker compose -f docker-compose.prod.yml --env-file .env.production ps

PUBLIC_IP=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "YOUR-EC2-PUBLIC-IP")

echo "=========================================================="
echo " Ternline Engine is running successfully!"
echo " Health Endpoint: http://${PUBLIC_IP}:8000/health"
echo " Web Control Room: http://${PUBLIC_IP}:8000/console"
echo " Ingestion API:    http://${PUBLIC_IP}:8000/v1/events"
echo "=========================================================="

