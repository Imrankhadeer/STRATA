"""
Adversarial Verification Suite for Active Defense Authorization Remediation Checkpoint.

Strictly verifies fixes for:
1. FINDING-P1-01 (P1): Elimination of caller-supplied human approver identity.
   - Ordinary ingestion API key passing approver_identity in body -> rejected (403).
   - Fake unverified headers (X-Operator-Principal, X-User-Identity) -> rejected (403).
   - Cryptographic JWT token required for human operator session.
   - Expired or malformed operator tokens -> rejected (401).
   - Cross-tenant operator tokens -> rejected (403).
   - Service account / bot tokens (is_human=False) -> rejected (403).
   - Caller assertion mismatch (token is Alice, body asserts Bob) -> rejected (403).
   - Dual-custody self-approval with verified token -> rejected (403).
   - Distinct verified human operator -> approved (200).
   - Database approved_by and audit log record verified token principal, NEVER caller input.

2. FINDING-P2-01 (P2): API key scopes and RBAC.
   - Newly created keys default to least-privilege ['events:ingest'].
   - Ingestion key denied access to defense actions listing/detail (403).
   - Ingestion key denied access to defense policy read/write (403).
   - Ingestion key denied access to API key creation/revocation/rotation (403).
   - Ingestion key authorized for event ingestion (202).
   - Scoped key enforcement: granular permissions granted and denied as configured.
   - Policy modification records immutable DefenseAuditLogModel entry.

3. PostgreSQL native integrity guarantees & SQLite rejection:
   - SQLite connection URLs rejected fail-fast at startup.
   - Foreign-key constraints natively enforced on PostgreSQL.
   - Defense audit log survives parent action row deletion with action_id set to NULL.
   - Partial unique index enforces deduplication on active defense actions.
"""

import datetime
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from backend.db.session import engine, Base
from backend.main import app
from backend.models import (
    ApiKey,
    DefenseActionModel,
    DefenseAuditLogModel,
    Tenant,
    TenantDefensePolicyModel,
)
from backend.core.auth import (
    ALL_PERMISSIONS,
    Permission,
    create_operator_token,
    generate_api_key,
    hash_api_key,
)
from backend.schemas.defense import (
    ActionScope,
    ActionStatus,
    ActionType,
    ProtectionMode,
    TargetEntityType,
)


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def tenant_fixture():
    tenant_id = f"test-auth-{uuid.uuid4().hex[:6]}"
    with Session(bind=engine) as s:
        s.add(Tenant(id=tenant_id, name=f"Auth Tenant {tenant_id}", is_active=True))
        s.commit()
    return tenant_id


@pytest.fixture
def ingestion_key(tenant_fixture):
    raw_key, h = generate_api_key(tenant_id=tenant_fixture, app_id="payments-api")
    key_id = f"k-ingest-{uuid.uuid4().hex[:8]}"
    with Session(bind=engine) as s:
        s.add(ApiKey(
            id=key_id,
            tenant_id=tenant_fixture,
            app_id="payments-api",
            key_hash=h,
            key_prefix=raw_key[:12],
            is_active=True,
            scopes=[Permission.EVENTS_INGEST],
        ))
        s.commit()
    return raw_key, tenant_fixture


@pytest.fixture
def admin_key(tenant_fixture):
    raw_key, h = generate_api_key(tenant_id=tenant_fixture, app_id="admin-console")
    key_id = f"k-admin-{uuid.uuid4().hex[:8]}"
    with Session(bind=engine) as s:
        s.add(ApiKey(
            id=key_id,
            tenant_id=tenant_fixture,
            app_id="admin-console",
            key_hash=h,
            key_prefix=raw_key[:12],
            is_active=True,
            scopes=[Permission.ADMIN],
        ))
        s.commit()
    return raw_key, tenant_fixture


def _create_sample_action(
    db: Session,
    tenant_id: str,
    requested_by: str = "analyst:alice@corp.internal",
    status: str = ActionStatus.AWAITING_APPROVAL.value,
) -> DefenseActionModel:
    action_id = f"act-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    action = DefenseActionModel(
        action_id=action_id,
        tenant_id=tenant_id,
        action_type=ActionType.TEMPORARY_IP_BLOCK.value,
        scope=ActionScope.TERNLINE_INGEST.value,
        target_entity_type=TargetEntityType.IP_ADDRESS.value,
        target_entity_id="198.51.100.99",
        status=status,
        protection_mode=ProtectionMode.ASSISTED.value,
        deduplication_fingerprint=f"fp-{uuid.uuid4().hex[:12]}",
        parameters={"duration_seconds": 1800},
        ttl_seconds=1800,
        expires_at=now + datetime.timedelta(hours=2),
        requested_by=requested_by,
        created_at=now,
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


# ===========================================================================
# 1. FINDING-P1-01: Operator Authentication & Caller Spoofing Elimination
# ===========================================================================

def test_p1_ingestion_key_submitting_caller_approver_identity_rejected(ingestion_key):
    """
    Jules Reproduced Vulnerability Test:
    An ordinary ingestion API key submits {"approver_identity": "admin:alice@security.corp"}.
    Endpoint MUST reject with 403 Forbidden.
    """
    raw_key, tenant_id = ingestion_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id, requested_by="secops:scanner")
        action_id = action.action_id

    # Ingestion key attempts to approve by passing arbitrary admin identity in body
    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={"Authorization": f"Bearer {raw_key}"},
        json={
            "approver_identity": "admin:alice@security.corp",
            "rationale": "Attempting dual-custody spoofing bypass",
        },
    )

    # Must be rejected with HTTP 403 Forbidden
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert "Forbidden" in detail or "Dual-custody" in detail


def test_p1_fake_unverified_operator_headers_are_ignored(ingestion_key):
    """
    Callers cannot spoof operator identity using unverified headers like
    X-Operator-Principal or X-User-Identity. Only cryptographic JWT tokens are accepted.
    """
    raw_key, tenant_id = ingestion_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id, requested_by="secops:scanner")
        action_id = action.action_id

    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={
            "Authorization": f"Bearer {raw_key}",
            "X-Operator-Principal": "admin:bob@security.corp",
            "X-User-Identity": "admin:bob@security.corp",
        },
        json={
            "approver_identity": "admin:bob@security.corp",
            "rationale": "Header injection spoofing attempt",
        },
    )

    assert resp.status_code == 403


def test_p1_expired_operator_jwt_rejected(admin_key):
    """Expired operator JWT tokens are rejected with HTTP 401 Unauthorized."""
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id)
        action_id = action.action_id

    # Create expired operator token (-10 seconds)
    expired_token = create_operator_token(
        principal="user:alice@corp.internal",
        tenant_id=tenant_id,
        expires_in_seconds=-10,
    )

    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={
            "Authorization": f"Bearer {raw_key}",
            "X-Operator-Token": f"Bearer {expired_token}",
        },
        json={"rationale": "Expired token test"},
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_p1_cross_tenant_operator_jwt_rejected(admin_key):
    """Operator token belonging to Tenant B cannot approve actions in Tenant A."""
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id)
        action_id = action.action_id

    # Create token for different tenant
    cross_tenant_token = create_operator_token(
        principal="user:bob@corp.internal",
        tenant_id="tenant-other-victim",
    )

    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={
            "Authorization": f"Bearer {raw_key}",
            "X-Operator-Token": f"Bearer {cross_tenant_token}",
        },
        json={"rationale": "Cross-tenant approval attempt"},
    )
    assert resp.status_code == 403
    assert "tenant mismatch" in resp.json()["detail"].lower()


def test_p1_service_account_token_rejected_from_human_approval(admin_key):
    """Service account token (is_human=False) is rejected on approval endpoint."""
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id)
        action_id = action.action_id

    bot_token = create_operator_token(
        principal="service:bot-runner",
        tenant_id=tenant_id,
        is_human=False,
    )

    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={
            "Authorization": f"Bearer {raw_key}",
            "X-Operator-Token": f"Bearer {bot_token}",
        },
        json={"rationale": "Bot approval attempt"},
    )
    assert resp.status_code == 403
    assert "human operator" in resp.json()["detail"].lower()


def test_p1_caller_assertion_mismatch_impersonation_rejected(admin_key):
    """
    If caller asserts approver_identity="user:charlie@corp.internal" in body,
    but is cryptographically authenticated as "user:bob@corp.internal",
    endpoint MUST reject impersonation with HTTP 403 Forbidden.
    """
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id, requested_by="user:alice@corp.internal")
        action_id = action.action_id

    bob_token = create_operator_token(
        principal="user:bob@corp.internal",
        tenant_id=tenant_id,
        scopes=[Permission.DEFENSE_ACTIONS_APPROVE],
    )

    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={
            "Authorization": f"Bearer {raw_key}",
            "X-Operator-Token": f"Bearer {bob_token}",
        },
        json={
            "approver_identity": "user:charlie@corp.internal",  # Mismatched assertion!
            "rationale": "Impersonation attempt",
        },
    )
    assert resp.status_code == 403
    assert "mismatch" in resp.json()["detail"].lower()


def test_p1_dual_custody_self_approval_rejected_with_verified_token(admin_key):
    """
    Requester 'user:alice@corp.internal' cannot self-approve even with a valid
    cryptographic operator token.
    """
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id, requested_by="user:alice@corp.internal")
        action_id = action.action_id

    alice_token = create_operator_token(
        principal="user:alice@corp.internal",
        tenant_id=tenant_id,
        scopes=[Permission.DEFENSE_ACTIONS_APPROVE],
    )

    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={
            "Authorization": f"Bearer {raw_key}",
            "X-Operator-Token": f"Bearer {alice_token}",
        },
        json={"rationale": "Self approval attempt"},
    )
    assert resp.status_code == 403
    assert "self" in resp.json()["detail"].lower() or "dual-custody" in resp.json()["detail"].lower()


def test_p1_valid_dual_custody_approval_stores_verified_identity(admin_key):
    """
    Distinct human operator with verified cryptographic token approves action.
    The identity stored in database and audit log is derived STRICTLY from verified token claims.
    """
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id, requested_by="user:alice@corp.internal")
        action_id = action.action_id

    bob_token = create_operator_token(
        principal="user:bob@corp.internal",
        tenant_id=tenant_id,
        scopes=[Permission.DEFENSE_ACTIONS_APPROVE],
    )

    # Approve with verified Bob token and matching assertion
    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={
            "Authorization": f"Bearer {raw_key}",
            "X-Operator-Token": f"Bearer {bob_token}",
        },
        json={
            "approver_identity": "user:bob@corp.internal",
            "rationale": "Valid peer approval by lead analyst",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "approved"
    assert data["approved_by"] == "user:bob@corp.internal"

    # Verify database state and audit log
    with Session(bind=engine) as db:
        db_action = db.query(DefenseActionModel).filter(DefenseActionModel.action_id == action_id).first()
        assert db_action.status == "approved"
        assert db_action.approved_by == "user:bob@corp.internal"

        audit_entry = (
            db.query(DefenseAuditLogModel)
            .filter(DefenseAuditLogModel.action_id == action_id, DefenseAuditLogModel.to_status == "approved")
            .first()
        )
        assert audit_entry is not None
        assert audit_entry.actor == "user:bob@corp.internal"


def test_p1_direct_jwt_bearer_authentication_supported(tenant_fixture):
    """
    Direct operator JWT token passed in Authorization: Bearer <jwt> authenticates cleanly
    without requiring an API key.
    """
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_fixture, requested_by="user:alice@corp.internal")
        action_id = action.action_id

    bob_token = create_operator_token(
        principal="user:bob@corp.internal",
        tenant_id=tenant_fixture,
        scopes=[Permission.DEFENSE_ACTIONS_APPROVE, Permission.DEFENSE_ACTIONS_READ],
    )

    # Direct Bearer <jwt>
    resp = client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"rationale": "Direct JWT bearer approval"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
    assert resp.json()["approved_by"] == "user:bob@corp.internal"


# ===========================================================================
# 2. FINDING-P2-01: API Key Scopes & RBAC Enforcement
# ===========================================================================

def test_p2_new_api_key_defaults_to_events_ingest_scope(admin_key):
    """Newly created API keys default to least-privilege ['events:ingest']."""
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    create_res = client.post(
        "/api/v1/keys",
        headers={"Authorization": f"Bearer {raw_key}"},
        json={"app_id": "sensor-service"},
    )
    assert create_res.status_code == 201
    data = create_res.json()
    assert data["scopes"] == [Permission.EVENTS_INGEST]


def test_p2_ingestion_key_denied_from_listing_defense_actions(ingestion_key):
    """An ingestion key cannot list defense actions (HTTP 403 Forbidden)."""
    raw_key, _ = ingestion_key
    client = TestClient(app)

    resp = client.get("/api/v1/defense/actions", headers={"Authorization": f"Bearer {raw_key}"})
    assert resp.status_code == 403
    assert "missing required permission" in resp.json()["detail"].lower()


def test_p2_ingestion_key_denied_from_reading_defense_action_detail(ingestion_key):
    """An ingestion key cannot read defense action detail (HTTP 403 Forbidden)."""
    raw_key, tenant_id = ingestion_key
    client = TestClient(app)

    with Session(bind=engine) as db:
        action = _create_sample_action(db, tenant_id=tenant_id)
        action_id = action.action_id

    resp = client.get(f"/api/v1/defense/actions/{action_id}", headers={"Authorization": f"Bearer {raw_key}"})
    assert resp.status_code == 403


def test_p2_ingestion_key_denied_from_reading_or_modifying_policy(ingestion_key):
    """An ingestion key cannot read or update defense policy (HTTP 403 Forbidden)."""
    raw_key, _ = ingestion_key
    client = TestClient(app)

    get_resp = client.get("/api/v1/defense/policy", headers={"Authorization": f"Bearer {raw_key}"})
    assert get_resp.status_code == 403

    put_resp = client.put(
        "/api/v1/defense/policy",
        headers={"Authorization": f"Bearer {raw_key}"},
        json={"default_mode": "enforced"},
    )
    assert put_resp.status_code == 403


def test_p2_ingestion_key_denied_from_creating_or_revoking_keys(ingestion_key):
    """An ingestion key cannot create, revoke, or rotate API keys (HTTP 403 Forbidden)."""
    raw_key, _ = ingestion_key
    client = TestClient(app)

    create_resp = client.post(
        "/api/v1/keys",
        headers={"Authorization": f"Bearer {raw_key}"},
        json={"app_id": "rogue-app"},
    )
    assert create_resp.status_code == 403

    revoke_resp = client.post(
        "/api/v1/keys/key-some-target/revoke",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert revoke_resp.status_code == 403

    rotate_resp = client.post(
        "/api/v1/keys/key-some-target/rotate",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert rotate_resp.status_code == 403


def test_p2_ingestion_key_authorized_for_telemetry_ingest(ingestion_key):
    """An ingestion key successfully ingests events."""
    raw_key, tenant_id = ingestion_key
    client = TestClient(app)

    event_payload = {
        "event_id": f"ev-{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "app_id": "payments-api",
        "service_id": "checkout",
        "event_type": "telemetry.ping",
        "severity": "info",
        "attributes": {"status": "ok"},
    }

    resp = client.post(
        "/v1/events",
        headers={"Authorization": f"Bearer {raw_key}"},
        json=event_payload,
    )
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1


def test_p2_invalid_scope_in_key_creation_rejected_400(admin_key):
    """Creating an API key with an invalid/unrecognized scope returns HTTP 400 Bad Request."""
    raw_key, _ = admin_key
    client = TestClient(app)

    resp = client.post(
        "/api/v1/keys",
        headers={"Authorization": f"Bearer {raw_key}"},
        json={"app_id": "test-app", "scopes": ["invalid:nonexistent:scope"]},
    )
    assert resp.status_code == 400
    assert "invalid scope" in resp.json()["detail"].lower()


def test_p2_scoped_key_enforcement(admin_key):
    """
    Verifies that a custom key issued with ['defense:actions:read'] can list actions
    but is denied from reading policy (missing 'defense:policy:read').
    """
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    create_res = client.post(
        "/api/v1/keys",
        headers={"Authorization": f"Bearer {raw_key}"},
        json={"app_id": "audit-tool", "scopes": [Permission.DEFENSE_ACTIONS_READ]},
    )
    assert create_res.status_code == 201
    audit_raw_key = create_res.json()["api_key"]

    # 1. defense:actions:read succeeds
    read_actions = client.get("/api/v1/defense/actions", headers={"Authorization": f"Bearer {audit_raw_key}"})
    assert read_actions.status_code == 200

    # 2. defense:policy:read is denied
    read_policy = client.get("/api/v1/defense/policy", headers={"Authorization": f"Bearer {audit_raw_key}"})
    assert read_policy.status_code == 403


def test_p2_policy_modification_records_immutable_audit_log(admin_key):
    """
    PUT /api/v1/defense/policy records an immutable entry in DefenseAuditLogModel
    with actor, tenant, old policy, new policy, and reason.
    """
    raw_key, tenant_id = admin_key
    client = TestClient(app)

    token = create_operator_token(
        principal="secops:lead@corp.internal",
        tenant_id=tenant_id,
        scopes=[Permission.DEFENSE_POLICY_WRITE, Permission.DEFENSE_POLICY_READ],
    )

    update_res = client.put(
        "/api/v1/defense/policy",
        headers={
            "Authorization": f"Bearer {raw_key}",
            "X-Operator-Token": f"Bearer {token}",
        },
        json={
            "default_mode": "assisted",
            "max_autonomous_ttl_seconds": 1800,
            "reason": "Security hardening policy rollout",
        },
    )
    assert update_res.status_code == 200
    assert update_res.json()["default_mode"] == "assisted"

    # Audit log verification
    with Session(bind=engine) as db:
        audit_row = (
            db.query(DefenseAuditLogModel)
            .filter(
                DefenseAuditLogModel.tenant_id == tenant_id,
                DefenseAuditLogModel.transition_trigger == "defense.policy_updated",
            )
            .order_by(DefenseAuditLogModel.timestamp.desc())
            .first()
        )
        assert audit_row is not None
        assert audit_row.actor == "secops:lead@corp.internal"
        assert audit_row.to_status == "assisted"
        assert audit_row.details["reason"] == "Security hardening policy rollout"
        assert audit_row.details["new_mode"] == "assisted"


# ===========================================================================
# 3. PostgreSQL Native Guarantees & SQLite Startup Rejection
# ===========================================================================

def test_sqlite_database_url_rejected_at_startup():
    """
    Verifies that SQLite database URLs are strictly rejected at startup / engine creation,
    failing fast with an informative error requiring PostgreSQL.
    """
    from backend.db.session import get_engine
    with pytest.raises(RuntimeError, match="SQLite is not supported. Ternline requires PostgreSQL"):
        get_engine("sqlite:///./cyber_engine_dev.db")

    with pytest.raises(RuntimeError, match="SQLite is not supported. Ternline requires PostgreSQL"):
        get_engine("sqlite:///:memory:")


def test_p2_postgres_foreign_key_enforced(db_session):
    """
    Verifies that PostgreSQL natively enforces foreign-key constraints.
    Attempting to insert an audit log referencing a non-existent action_id fails with IntegrityError.
    """
    from sqlalchemy.exc import IntegrityError
    audit = DefenseAuditLogModel(
        log_id=f"log-fk-test-{uuid.uuid4().hex[:6]}",
        action_id="non-existent-action-id-9999",
        tenant_id="tenant-alpha",
        from_status=None,
        to_status=ActionStatus.PROPOSED.value,
        transition_trigger="manual.test",
        actor="system:test",
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_p2_postgres_audit_log_survives_action_deletion(db_session):
    """
    Verifies that on PostgreSQL, deleting a defense action triggers ON DELETE SET NULL
    on defense_audit_log.action_id rather than deleting the audit record or failing.
    """
    action_id = f"act-del-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    action = DefenseActionModel(
        action_id=action_id,
        tenant_id="tenant-alpha",
        action_type=ActionType.TEMPORARY_IP_BLOCK.value,
        scope=ActionScope.TERNLINE_INGEST.value,
        target_entity_type=TargetEntityType.IP_ADDRESS.value,
        target_entity_id="198.51.100.77",
        status=ActionStatus.PROPOSED.value,
        protection_mode=ProtectionMode.OBSERVE.value,
        deduplication_fingerprint=f"fp-del-{uuid.uuid4().hex[:8]}",
        requested_by="system:planner",
        created_at=now,
    )
    db_session.add(action)

    log_id = f"log-del-{uuid.uuid4().hex[:8]}"
    audit = DefenseAuditLogModel(
        log_id=log_id,
        action_id=action_id,
        tenant_id="tenant-alpha",
        from_status=None,
        to_status=ActionStatus.PROPOSED.value,
        transition_trigger="response_planner.propose",
        actor="system:planner",
        timestamp=now,
    )
    db_session.add(audit)
    db_session.commit()

    # Delete the action
    db_session.delete(action)
    db_session.commit()

    # The action must be gone
    deleted_action = db_session.query(DefenseActionModel).filter(DefenseActionModel.action_id == action_id).first()
    assert deleted_action is None

    # The audit log must survive with action_id set to NULL per ON DELETE SET NULL
    surviving_audit = db_session.query(DefenseAuditLogModel).filter(DefenseAuditLogModel.log_id == log_id).first()
    assert surviving_audit is not None
    assert surviving_audit.action_id is None
    assert surviving_audit.tenant_id == "tenant-alpha"


def test_postgres_partial_unique_index_enforced(db_session):
    """
    Verifies PostgreSQL partial unique index enforcement:
    Duplicate active actions with the same deduplication_fingerprint under the same tenant are rejected.
    """
    from sqlalchemy.exc import IntegrityError
    fp = f"fp-dup-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    
    act1 = DefenseActionModel(
        action_id=f"act-1-{uuid.uuid4().hex[:6]}",
        tenant_id="tenant-alpha",
        action_type=ActionType.TEMPORARY_IP_BLOCK.value,
        scope=ActionScope.TERNLINE_INGEST.value,
        target_entity_type=TargetEntityType.IP_ADDRESS.value,
        target_entity_id="198.51.100.88",
        status=ActionStatus.PROPOSED.value,
        protection_mode=ProtectionMode.OBSERVE.value,
        deduplication_fingerprint=fp,
        requested_by="system:planner",
        created_at=now,
    )
    db_session.add(act1)
    db_session.commit()

    # Second active action with identical fingerprint must violate partial unique index
    act2 = DefenseActionModel(
        action_id=f"act-2-{uuid.uuid4().hex[:6]}",
        tenant_id="tenant-alpha",
        action_type=ActionType.TEMPORARY_IP_BLOCK.value,
        scope=ActionScope.TERNLINE_INGEST.value,
        target_entity_type=TargetEntityType.IP_ADDRESS.value,
        target_entity_id="198.51.100.88",
        status=ActionStatus.AWAITING_APPROVAL.value,
        protection_mode=ProtectionMode.OBSERVE.value,
        deduplication_fingerprint=fp,
        requested_by="system:planner",
        created_at=now,
    )
    db_session.add(act2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

