import logging
from fastapi import FastAPI, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.config import settings
from backend.db.session import get_db, Base, engine
from backend.api.ingest import router as ingest_router

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cyber_engine")

app = FastAPI(
    title="CYBER ENGINE Security Platform",
    description="Developer-friendly security layer and continuous telemetry protection",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router)


@app.get("/health", tags=["health"])
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint verifying backend liveness and database connectivity.
    """
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error("Health check DB query failure: %s", str(e))
        db_status = "unhealthy"

    overall_status = "ok" if db_status == "connected" else "degraded"
    status_code = status.HTTP_200_OK if overall_status == "ok" else status.HTTP_503_SERVICE_UNAVAILABLE

    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall_status,
            "version": "0.1.0",
            "environment": settings.ENVIRONMENT,
            "database": db_status
        }
    )
