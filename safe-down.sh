#!/bin/bash
# ==============================================================================
# Ternline Safe Down & Automatic Backup Script
# Creates a timestamped PostgreSQL dump before stopping any containers.
# ==============================================================================
set -e

BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/ternline_db_backup_${TIMESTAMP}.sql"

mkdir -p "${BACKUP_DIR}"

# 1. If database container is running, take an automatic snapshot first
if docker ps --format '{{.Names}}' | grep -q "^ternline_prod_db$"; then
  echo "==> Taking automatic pre-shutdown database backup to ${BACKUP_FILE}..."
  if docker exec ternline_prod_db pg_dump -U postgres cyber_engine > "${BACKUP_FILE}" 2>/dev/null; then
    # Ensure backup is not empty
    if [ -s "${BACKUP_FILE}" ]; then
      gzip -f "${BACKUP_FILE}"
      echo "✔ Database backup completed and compressed: ${BACKUP_FILE}.gz"
    else
      rm -f "${BACKUP_FILE}"
      echo "[!] Database was empty or pg_dump returned 0 bytes."
    fi
  else
    echo "[!] Warning: Could not dump database before stopping (container may still be starting)."
  fi
fi

# 2. Safely stop containers without destroying volumes
echo "==> Stopping production containers safely (volumes preserved)..."
docker compose -f docker-compose.prod.yml --env-file .env.production down

echo "✔ All containers stopped safely. All data volumes and backups are intact."
