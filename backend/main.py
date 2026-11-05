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
from backend.api.workspaces import router as workspaces_router
from backend.api.apps import router as apps_router
from backend.api.assistant import router as assistant_router
from backend.core.auth import AuthContext, Permission, require_permission

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
    docs_url=None if _is_prod else "/swagger",
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
if getattr(settings, "CORS_ALLOW_VERCEL", False):
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
if settings.ENVIRONMENT == 'development' or getattr(settings, 'ALLOW_SIMULATION_API', False):
    app.include_router(simulation_router)
app.include_router(ops_router)
app.include_router(keys_router)
app.include_router(events_router)
app.include_router(defense_router)
app.include_router(incidents_router)
app.include_router(threat_intel_router)
app.include_router(auth_router)
app.include_router(workspaces_router)
app.include_router(apps_router)
app.include_router(assistant_router)

if not _is_prod:
    @app.get("/api/docs", include_in_schema=False)
    async def swagger_docs_alias():
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/swagger")


@app.on_event("startup")
def startup_db_init():
    if getattr(app.state, "_db_initialized", False):
        return

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

    # In production and staging, verify that required Alembic database migrations have succeeded
    if settings.ENVIRONMENT in ("production", "staging"):
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory
        from alembic.config import Config
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        alembic_cfg = Config(os.path.join(base_dir, "alembic.ini"))
        script = ScriptDirectory.from_config(alembic_cfg)
        head_rev = script.get_current_head()
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn)
            curr_rev = ctx.get_current_revision()
            if curr_rev != head_rev:
                logger.critical(
                    "Production startup blocked: database migration head mismatch. "
                    "Current revision is '%s', expected head is '%s'. "
                    "Run 'alembic upgrade head' before starting the application.",
                    curr_rev, head_rev
                )
                raise RuntimeError(
                    f"Production startup blocked: database migration head mismatch. "
                    f"Current revision is '{curr_rev}', expected head is '{head_rev}'. "
                    "Run 'alembic upgrade head' before starting the application."
                )

    try:
        from backend.models import Tenant, ApiKey
        from backend.core.auth import hash_api_key, ALL_PERMISSIONS
        if settings.ENVIRONMENT == "development":
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
                        scopes=list(ALL_PERMISSIONS),
                    ))
                    session.commit()
                else:
                    k.scopes = list(ALL_PERMISSIONS)
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
                    if not admin_key:
                        raise RuntimeError(
                            "INITIAL_ADMIN_API_KEY is required to bootstrap the first production tenant."
                        )
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

                    logger.info("Production bootstrap: Seeded initial organization and admin key.")
                else:
                    logger.info("Production mode: Database verified and operational.")
    except Exception:
        logger.exception("Database initialization failed during startup")
        raise

    app.state._db_initialized = True


@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
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
@app.get("/console/", include_in_schema=False)
@app.get("/console.html", include_in_schema=False)
@app.get("/control-room", include_in_schema=False)
@app.get("/ui", include_in_schema=False)
@app.get("/app", include_in_schema=False)
@app.get("/verify-email", include_in_schema=False)
@app.get("/reset-password", include_in_schema=False)
async def control_room():
    """
    Serves the production Ternline Control Room.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cr_path = os.path.join(base_dir, "console.html")
    if os.path.exists(cr_path):
        return FileResponse(cr_path)
    return JSONResponse({"error": "Control Room interface not found"}, status_code=404)


@app.get("/docs", include_in_schema=False)
@app.get("/docs/", include_in_schema=False)
@app.get("/docs.html", include_in_schema=False)
@app.get("/documentation", include_in_schema=False)
@app.get("/documentation/", include_in_schema=False)
@app.get("/guide", include_in_schema=False)
@app.get("/guide/", include_in_schema=False)
@app.get("/docs/guide", include_in_schema=False)
@app.get("/docs/guide/", include_in_schema=False)
async def documentation():
    """
    Serves the Ternline Developer Onboarding and SDK Guide (docs.html).
    """
    candidate_paths = [
        os.path.join(BASE_DIR, "docs.html"),
        os.path.join(os.getcwd(), "docs.html"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs.html"),
    ]
    for p in candidate_paths:
        abs_p = os.path.abspath(p)
        if os.path.exists(abs_p):
            return FileResponse(abs_p, media_type="text/html")
    return JSONResponse({"error": "Documentation page not found"}, status_code=404)

@app.get("/favicon.ico", include_in_schema=False)
async def favicon_ico():
    p = os.path.join(BASE_DIR, "favicon.ico")
    if os.path.exists(p):
        return FileResponse(p, media_type="image/x-icon")
    return Response(status_code=204)


@app.get("/favicon.svg", include_in_schema=False)
async def favicon_svg():
    p = os.path.join(BASE_DIR, "favicon.svg")
    if os.path.exists(p):
        return FileResponse(p, media_type="image/svg+xml")
    return Response(status_code=204)


@app.get("/favicon.png", include_in_schema=False)
@app.get("/apple-touch-icon.png", include_in_schema=False)
async def favicon_png():
    p = os.path.join(BASE_DIR, "favicon.png")
    if os.path.exists(p):
        return FileResponse(p, media_type="image/png")
    return Response(status_code=204)



@app.get("/health", tags=["health"])
@app.get("/api/v1/ops/health", tags=["health"])
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint verifying backend liveness, database connectivity, and Redis availability.
    """
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error("Health check DB query failure: %s", str(e))
        db_status = "unhealthy"

    redis_status = "not_configured"
    if settings.REDIS_URL:
        try:
            import redis
            r = redis.from_url(settings.REDIS_URL, socket_timeout=1.0)
            if r.ping():
                redis_status = "connected"
            else:
                redis_status = "unhealthy"
        except Exception as e:
            logger.error("Health check Redis ping failure: %s", str(e))
            redis_status = "unhealthy"

    is_db_ok = db_status == "connected"
    is_redis_ok = (redis_status == "connected") if (settings.REDIS_REQUIRED or settings.ENVIRONMENT in ("production", "staging")) else True

    overall_status = "ok" if (is_db_ok and is_redis_ok) else "degraded"
    status_code = status.HTTP_200_OK if overall_status == "ok" else status.HTTP_503_SERVICE_UNAVAILABLE

    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall_status,
            "version": "0.1.0",
            "environment": settings.ENVIRONMENT,
            "database": db_status,
            "redis": redis_status,
        }
    )


@app.get("/metrics", tags=["observability"])
def get_root_metrics(
    auth: AuthContext = Depends(require_permission(Permission.METRICS_READ)),
    db: Session = Depends(get_db),
):
    """
    Standard Prometheus exposition format metrics scrape target.
    Exposes ingestion rate, detection latency, finding counters, and rule counts.
    """
    from backend.ops.metrics import metrics_registry
    content = metrics_registry.export_prometheus(db, tenant_id=auth.tenant_id)
    return Response(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")
