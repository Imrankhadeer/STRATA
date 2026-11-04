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
  else
    echo "[ERROR] .env.production not found!"
    exit 1
  fi
fi

# 2. Automatically sanitize .env.production (fix $ostNCc warnings, ensure strong >=32 char SECRET_KEY)
python3 - << 'EOF'
import re, secrets

env_path = ".env.production"
try:
    with open(env_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Clean out $ostNCc or unescaped interpolation artifacts
    content = content.replace("$ostNCc", "")

    # Ensure a cryptographically strong SECRET_KEY (>= 32 characters, no unescaped $)
    sec_match = re.search(r'^SECRET_KEY=(.*)$', content, re.MULTILINE)
    current_key = sec_match.group(1).strip() if sec_match else ""
    if not current_key or len(current_key) < 32 or "generate_with" in current_key or "insecure" in current_key or "$" in current_key:
        new_secret = secrets.token_hex(32)
        if sec_match:
            content = re.sub(r'^SECRET_KEY=.*$', f'SECRET_KEY={new_secret}', content, flags=re.MULTILINE)
        else:
            content += f'\nSECRET_KEY={new_secret}\n'
        print("[i] Automatically provisioned a secure 64-character SECRET_KEY in .env.production")

    # Ensure a cryptographically secure POSTGRES_PASSWORD
    pw_match = re.search(r'^POSTGRES_PASSWORD=(.*)$', content, re.MULTILINE)
    current_pw = pw_match.group(1).strip() if pw_match else ""
    if not current_pw or current_pw == "postgres_prod_password_change_me" or "password" in current_pw.lower():
        new_pw = secrets.token_hex(24)
        if pw_match:
            content = re.sub(r'^POSTGRES_PASSWORD=.*$', f'POSTGRES_PASSWORD={new_pw}', content, flags=re.MULTILINE)
        else:
            content += f'\nPOSTGRES_PASSWORD={new_pw}\n'
        print("[i] Automatically provisioned a secure POSTGRES_PASSWORD in .env.production")
        current_pw = new_pw

    # Detect dummy AWS RDS placeholder in DATABASE_URL and route to compose db service
    db_match = re.search(r'^DATABASE_URL=(.*)$', content, re.MULTILINE)
    if not db_match or not db_match.group(1).strip() or "xxxxxxxxx" in db_match.group(1) or "ternline-db" in db_match.group(1):
        content = re.sub(
            r'^DATABASE_URL=.*$',
            f'DATABASE_URL=postgresql+psycopg2://postgres:{current_pw}@db:5432/cyber_engine',
            content,
            flags=re.MULTILINE
        ) if db_match else content + f'\nDATABASE_URL=postgresql+psycopg2://postgres:{current_pw}@db:5432/cyber_engine\n'
        print("[i] Routed DATABASE_URL to local compose PostgreSQL service (db:5432)")

    # Detect dummy AWS ElastiCache placeholder in REDIS_URL and route to compose redis service
    redis_match = re.search(r'^REDIS_URL=(.*)$', content, re.MULTILINE)
    if redis_match and ("xxxxxx" in redis_match.group(1) or "clustercfg" in redis_match.group(1)):
        content = re.sub(
            r'^REDIS_URL=.*$',
            'REDIS_URL=redis://redis:6379/0',
            content,
            flags=re.MULTILINE
        )
        print("[i] Detected unconfigured ElastiCache placeholder; routed REDIS_URL to local compose Redis service (redis:6379)")

    with open(env_path, "w", encoding="utf-8") as f:
        f.write(content)
except Exception as e:
    print(f"[!] Warning while sanitizing {env_path}: {e}")
EOF

# 3. Build image directly with standard Docker daemon (does not require docker-buildx-plugin >= 0.17.0)
echo "==> Building backend Docker image natively..."
docker build -t ternline/backend:latest .

# 4. Bring up PostgreSQL 16, Redis 7+, and Ternline Backend
echo "==> Launching production containers via Docker Compose..."
docker compose -f docker-compose.prod.yml --env-file .env.production up -d

# 5. Wait for database migrations and Uvicorn server to bind
echo "==> Waiting for backend service initialization..."
for i in $(seq 1 10); do
  if curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
    echo "✔ Backend is live and healthy!"
    break
  fi
  sleep 1
done

# 6. Output status and health
echo "==> Production services status:"
docker compose -f docker-compose.prod.yml --env-file .env.production ps

# Inspect recent backend logs if health is not responding
if ! curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
  echo "[!] Backend health check not responding yet. Recent container logs:"
  docker logs --tail 20 ternline_prod_backend
fi

PUBLIC_IP=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "YOUR-EC2-PUBLIC-IP")

echo "=========================================================="
echo " Ternline Engine Deployment Complete!"
echo " Health Endpoint: http://${PUBLIC_IP}:8000/health"
echo " Web Control Room: http://${PUBLIC_IP}:8000/console"
echo " Ingestion API:    http://${PUBLIC_IP}:8000/v1/events"
echo "=========================================================="
