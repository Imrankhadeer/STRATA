import os
import sys

# Ensure project root and SDK directory are discoverable when running via uvicorn/gunicorn
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK_DIR = os.path.join(BASE_DIR, "sdk")
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if SDK_DIR not in sys.path:
    sys.path.insert(0, SDK_DIR)

import logging
from fastapi import FastAPI, Depends, status
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.config import settings
from backend.db.session import get_db, Base, engine
from backend.api.ingest import router as ingest_router
from backend.api.investigations import router as investigations_router
from backend.api.rules import router as rules_router
from backend.api.findings import router as findings_router
from backend.api.simulation import router as simulation_router
from backend.api.ops import router as ops_router
from backend.api.keys import router as keys_router
from backend.api.events import router as events_router
from backend.api.defense import router as defense_router
from backend.api.incidents import router as incidents_router
from backend.api.threat_intel import router as threat_intel_router
from backend.api.auth import router as auth_router

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("cyber_engine")

_is_prod = settings.ENVIRONMENT.lower() in ("production", "staging")
app = FastAPI(
    title="CYBER ENGINE Security Platform",
    description="Developer-friendly security layer and continuous telemetry protection",
    version="0.1.0",
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
)

# Secure CORS: Support explicitly configured origins and Vercel domains
raw_cors = os.getenv("ALLOWED_CORS_ORIGINS", settings.ALLOWED_CORS_ORIGINS)
allowed_origins = [o.strip() for o in raw_cors.split(",") if o.strip()]
if settings.ENVIRONMENT.lower() == "development":
    if "null" not in allowed_origins:
        allowed_origins.append("null")

cors_kwargs = {
    "allow_origins": allowed_origins,
    "allow_credentials": True,
    "allow_methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE", "PATCH"],
    "allow_headers": ["Authorization", "Content-Type", "Accept", "X-Tenant-ID", "X-Operator-Token"],
}
if getattr(settings, "CORS_ALLOW_VERCEL", True):
    cors_kwargs["allow_origin_regex"] = r"^https://.*\.vercel\.app$"

app.add_middleware(
    CORSMiddleware,
    **cors_kwargs,
)


@app.middleware("http")
async def _security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    
    # HTML console pages require inline script & style execution per console meta CSP
    content_type = resp.headers.get("content-type", "")
    if "text/html" in content_type:
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self' data: blob:; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' http: https: ws: wss:; "
            "frame-ancestors 'self'"
        )
    else:
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")

    if settings.ENVIRONMENT.lower() in ("production", "staging"):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return resp

app.include_router(ingest_router)
app.include_router(investigations_router)
app.include_router(rules_router)
app.include_router(findings_router)
app.include_router(simulation_router)
app.include_router(ops_router)
app.include_router(keys_router)
app.include_router(events_router)
app.include_router(defense_router)
app.include_router(incidents_router)
app.include_router(threat_intel_router)
app.include_router(auth_router)


@app.on_event("startup")
def startup_db_init():
    if getattr(app.state, "_db_initialized", False):
        return
    app.state._db_initialized = True

    from backend.config import validate_production_settings as _validate_prod
    _validate_prod()
    """Ensure tables exist, and only seed default dev tenant/key in development mode."""
    # Fail fast if PostgreSQL is unreachable
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        logger.critical("Failed to connect to PostgreSQL database: %s", e)
        raise RuntimeError(f"PostgreSQL connection failed. Ternline requires a reachable PostgreSQL database: {e}") from e

    try:
        from backend.models import Tenant, ApiKey
        from backend.core.auth import hash_api_key
        Base.metadata.create_all(bind=engine)
        
        # Security Boundary: Never auto-seed predictable demo keys in production or staging
        if settings.ENVIRONMENT == "development":
            with Session(engine) as session:
                t = session.query(Tenant).filter(Tenant.id == "tenant-alpha").first()
                if not t:
                    session.add(Tenant(id="tenant-alpha", name="Alpha Corp", is_active=True))
                    session.commit()

                raw_key = "ce_live_test_api_key_secret_12345"
                h = hash_api_key(raw_key)
                k = session.query(ApiKey).filter(ApiKey.key_hash == h).first()
                if not k:
                    session.add(ApiKey(
                        id="key-001",
                        tenant_id="tenant-alpha",
                        app_id="payments-api",
                        key_hash=h,
                        key_prefix="ce_live_",
                        is_active=True,
                    ))
                    session.commit()

                from backend.models import TenantDefensePolicyModel
                pol = session.query(TenantDefensePolicyModel).filter(TenantDefensePolicyModel.tenant_id == "tenant-alpha").first()
                if not pol:
                    session.add(TenantDefensePolicyModel(
                        id="pol-alpha-001",
                        tenant_id="tenant-alpha",
                        default_mode="observe",
                        is_active=True,
                        configuration={"default_mode": "observe"},
                    ))
                    session.commit()
            logger.info("Development database initialized with sandbox baseline credentials.")
        else:
            # Production/Staging mode: Safe first-time bootstrap if database is empty
            with Session(engine) as session:
                from backend.models import TenantDefensePolicyModel
                tenant_count = session.query(Tenant).count()
                if tenant_count == 0:
                    tenant_id = settings.INITIAL_TENANT_ID or "tenant-alpha"
                    admin_key = settings.INITIAL_ADMIN_API_KEY
                    auto_generated = False
                    if not admin_key:
                        from backend.core.auth import generate_api_key
                        admin_key, key_hash = generate_api_key(tenant_id, "admin-console")
                        auto_generated = True
                    else:
                        key_hash = hash_api_key(admin_key)

                    t = Tenant(id=tenant_id, name="Default Organization", is_active=True)
                    session.add(t)
                    session.flush()

                    k = ApiKey(
                        id="key-admin-001",
                        tenant_id=tenant_id,
                        app_id="admin-console",
                        key_hash=key_hash,
                        key_prefix="ce_live_",
                        scopes=["*"],
                        is_active=True,
                    )
                    session.add(k)

                    pol = TenantDefensePolicyModel(
                        id="pol-admin-001",
                        tenant_id=tenant_id,
                        default_mode="observe",
                        is_active=True,
                        configuration={"default_mode": "observe"},
                    )
                    session.add(pol)
                    session.commit()

                    if auto_generated:
                        logger.warning(
                            "\n====================================================================\n"
                            "FIRST-TIME INITIALIZATION: No tenants found in database.\n"
                            "Generated Initial Production Admin API Key:\n"
                            f"  Tenant ID: {tenant_id}\n"
                            f"  API Key:   {admin_key}\n"
                            "STORE THIS KEY SECURELY. IT CANNOT BE RETRIEVED AFTER LOGGING.\n"
                            "===================================================================="
                        )
                    else:
                        logger.info("Production bootstrap: Seeded initial organization and admin key from INITIAL_ADMIN_API_KEY.")
                else:
                    logger.info("Production mode: Database verified and operational.")
    except Exception as e:
        logger.warning(f"Database auto-init on startup skipped or deferred: {e}")



@app.get("/", include_in_schema=False)
async def root():
    """
    Serves the Ternline web console and landing page, or returns API navigation metadata.
    """
    index_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({
        "name": "Ternline (CYBER ENGINE) API",
        "version": "0.1.0",
        "documentation": "/docs",
        "health": "/health",
    })


@app.get("/console", include_in_schema=False)
@app.get("/control-room", include_in_schema=False)
@app.get("/ui", include_in_schema=False)
@app.get("/app", include_in_schema=False)
@app.get("/verify-email", include_in_schema=False)
async def control_room():
    """
    Serves the production Ternline Control Room.
    """
    cr_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "TERNLINE_Control_Room_Enhanced.html")
    if os.path.exists(cr_path):
        return FileResponse(cr_path)
    return JSONResponse({"error": "Control Room interface not found"}, status_code=404)


@app.get("/documentation", include_in_schema=False)
@app.get("/guide", include_in_schema=False)
@app.get("/docs/guide", include_in_schema=False)
async def documentation():
    """
    Serves the Ternline Developer Onboarding & SDK Guide.
    """
    doc_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "documentation.html")
    if os.path.exists(doc_path):
        return FileResponse(doc_path)
    return JSONResponse({"error": "Documentation page not found"}, status_code=404)


@app.get("/health", tags=["health"])
@app.get("/api/v1/ops/health", tags=["health"])
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


@app.get("/metrics", tags=["observability"])
def get_root_metrics(db: Session = Depends(get_db)):
    """
    Standard Prometheus exposition format metrics scrape target.
    Exposes ingestion rate, detection latency, finding counters, and rule counts.
    """
    from backend.ops.metrics import metrics_registry
    content = metrics_registry.export_prometheus(db)
    return Response(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")
