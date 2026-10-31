import pytest
import os
import sys
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure project root and sdk are in python path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sdk_dir = os.path.join(root_dir, "sdk")
sys.path.insert(0, root_dir)
sys.path.insert(0, sdk_dir)

from backend.db.session import Base, get_db
from backend.main import app
from backend.models import Tenant, ApiKey, EventModel, SecurityFinding, InvestigationReport, DeclarativeRuleModel
from backend.core.auth import hash_api_key

TEST_TENANT_ID = "tenant-alpha"
TEST_APP_ID = "payments-api"
RAW_TEST_API_KEY = "ce_live_test_api_key_secret_12345"
API_KEY_HASH = hash_api_key(RAW_TEST_API_KEY)


@pytest.fixture(scope="session")
def db_engine():
    # In-memory SQLite engine isolated with StaticPool for fast deterministic tests
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    session_factory = sessionmaker(bind=connection)
    session = session_factory()

    # Seed baseline tenant and active API key
    tenant = Tenant(id=TEST_TENANT_ID, name="Alpha Corp", is_active=True)
    session.add(tenant)
    api_key = ApiKey(
        id="key-001",
        tenant_id=TEST_TENANT_ID,
        app_id=TEST_APP_ID,
        key_hash=API_KEY_HASH,
        key_prefix="ce_live_",
        is_active=True,
    )
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
    from backend.api.ingest import fast_detectors
    from backend.detection.registry import runtime_rule_registry
    runtime_rule_registry.invalidate()
    for d in fast_detectors:
        if hasattr(d, "reset"):
            d.reset()
    yield
    runtime_rule_registry.invalidate()
    for d in fast_detectors:
        if hasattr(d, "reset"):
            d.reset()
