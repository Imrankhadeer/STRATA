# ==============================================================================
# Ternline Backend - Hardened Multi-Stage Production Dockerfile
# ==============================================================================

# --- Stage 1: Build & Dependency Resolution ---
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# --- Stage 2: Minimal Hardened Runtime ---
FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/appuser/.local/bin:${PATH}" \
    PYTHONPATH="/app:/app/sdk:${PYTHONPATH}"

# Install minimal runtime shared libraries (libpq5 for PostgreSQL, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/sh appuser

# Copy installed Python packages from builder stage
COPY --from=builder --chown=appuser:appgroup /root/.local /home/appuser/.local

# Copy application source code
COPY --chown=appuser:appgroup backend ./backend
COPY --chown=appuser:appgroup sdk ./sdk
COPY --chown=appuser:appgroup scenarios ./scenarios
COPY --chown=appuser:appgroup alembic.ini .
COPY --chown=appuser:appgroup migrations ./migrations
COPY --chown=appuser:appgroup docker-entrypoint.sh .
COPY --chown=appuser:appgroup index.html TERNLINE_Control_Room_Enhanced.html documentation.html ./

RUN chmod +x /app/docker-entrypoint.sh

USER appuser

EXPOSE 8000

# Docker Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/ops/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
