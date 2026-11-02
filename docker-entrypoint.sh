#!/bin/sh
set -e

# Run database migrations before starting the application
echo "==> Running Alembic database migrations..."
alembic upgrade head
echo "==> Database migrations applied successfully."

# Execute the container command (e.g. uvicorn)
exec "$@"

