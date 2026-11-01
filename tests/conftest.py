import pytest
import os
import sys
from urllib.parse import urlparse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

# Ensure project root and sdk are in python path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sdk_dir = os.path.join(root_dir, "sdk")
sys.path.insert(0, root_dir)
sys.path.insert(0, sdk_dir)

from backend.config import settings

# Configure test database URL pointing exclusively to PostgreSQL
TEST_DB_URL = os.environ.get("TEST_DATABASE_URL")
if not TEST_DB_URL:
    base_url = settings.DATABASE_URL
    if "/cyber_engine" in base_url and not base_url.endswith("/cyber_engine_test"):
        TEST_DB_URL = base_url.replace("/cyber_engine", "/cyber_engine_test")
    else:
        TEST_DB_URL = "postgresql+psycopg2://postgres:postgres@localhost:5432/cyber_engine_test"

os.environ["DATABASE_URL"] = TEST_DB_URL
settings.DATABASE_URL = TEST_DB_URL


def _ensure_test_database_exists(db_url: str):
    parsed = urlparse(db_url.replace("+psycopg2", ""))
    dbname = parsed.path.lstrip("/")
    if not dbname:
        return
    try:
        import psycopg2
        from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
        conn = psycopg2.connect(
            dbname="postgres",
            user=parsed.username or "postgres",
            password=parsed.password or "postgres",
            host=parsed.hostname or "localhost",
            port=parsed.port or 5432,
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (dbname,))
        if not cur.fetchone():
            cur.execute(f'CREATE DATABASE "{dbname}"')
        cur.close()
        conn.close()
    except Exception:
        pass


_ensure_test_database_exists(TEST_DB_URL)

import backend.db.session as session_module
session_module.engine = session_module.get_engine(TEST_DB_URL)
session_module.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=session_module.engine)

from backend.db.session import Base, get_db
from backend.main import app
from backend.models import Tenant, ApiKey, EventModel, SecurityFinding, InvestigationReport, DeclarativeRuleModel
from backend.core.auth import hash_api_key

TEST_TENANT_ID = "tenant-alpha"
TEST_APP_ID = "payments-api"
RAW_TEST_API_KEY = "ce_live_test_api_key_secret_12345"
API_KEY_HASH = hash_api_key(RAW_TEST_API_KEY)


@pytest.fixture(scope="session", autouse=True)
def db_engine():
    # PostgreSQL test engine
    engine = session_module.engine
    Base.metadata.create_all(bind=engine)
    app.state._db_initialized = True

    # Seed baseline tenant and active API key in session-scoped PostgreSQL database
    with Session(bind=engine) as session:
        if not session.query(Tenant).filter(Tenant.id == TEST_TENANT_ID).first():
            session.add(Tenant(id=TEST_TENANT_ID, name="Alpha Corp", is_active=True))
        if not session.query(Tenant).filter(Tenant.id == "tenant-beta").first():
            session.add(Tenant(id="tenant-beta", name="Beta Corp", is_active=True))
        api_key = session.query(ApiKey).filter(ApiKey.id == "key-001").first()
        if not api_key:
            session.add(ApiKey(
                id="key-001",
                tenant_id=TEST_TENANT_ID,
                app_id=TEST_APP_ID,
                key_hash=API_KEY_HASH,
                key_prefix="ce_live_",
                is_active=True,
                scopes=["admin", "events:ingest", "defense:read", "defense:propose", "defense:approve", "defense:policy:write"],
            ))
        else:
            api_key.scopes = ["admin", "events:ingest", "defense:read", "defense:propose", "defense:approve", "defense:policy:write"]
            session.add(api_key)
        session.commit()

    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    # Seed baseline tenant and active API key safely
    tenant = session.query(Tenant).filter(Tenant.id == TEST_TENANT_ID).first()
    if not tenant:
        session.add(Tenant(id=TEST_TENANT_ID, name="Alpha Corp", is_active=True))
    tenant_beta = session.query(Tenant).filter(Tenant.id == "tenant-beta").first()
    if not tenant_beta:
        session.add(Tenant(id="tenant-beta", name="Beta Corp", is_active=True))
    api_key = session.query(ApiKey).filter(ApiKey.id == "key-001").first()
    if not api_key:
        session.add(ApiKey(
            id="key-001",
            tenant_id=TEST_TENANT_ID,
            app_id=TEST_APP_ID,
            key_hash=API_KEY_HASH,
            key_prefix="ce_live_",
            is_active=True,
            scopes=["admin", "events:ingest", "defense:read", "defense:propose", "defense:approve", "defense:policy:write"],
        ))
    else:
        api_key.scopes = ["admin", "events:ingest", "defense:read", "defense:propose", "defense:approve", "defense:policy:write"]
        session.add(api_key)
    session.commit()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers():
    return {
        "Authorization": f"Bearer {RAW_TEST_API_KEY}"
    }


@pytest.fixture(autouse=True)
def reset_detectors():
    from backend.api.ingest import fast_detectors, _rate_limit_state
    from backend.detection.registry import runtime_rule_registry
    runtime_rule_registry.invalidate()
    _rate_limit_state.clear()
    for d in fast_detectors:
        if hasattr(d, "reset"):
            d.reset()
    yield
    runtime_rule_registry.invalidate()
    _rate_limit_state.clear()
    for d in fast_detectors:
        if hasattr(d, "reset"):
            d.reset()
