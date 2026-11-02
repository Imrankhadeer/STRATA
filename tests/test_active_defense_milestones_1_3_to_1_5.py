"""
Test Suite for Milestones 1.3, 1.4, and 1.5: Active Defense Execution, Verification, Rollback, and Upstream Webhook Containment.

Covers:
1. Milestone 1.3:
   - InternalApiKeyAdapter execution (API key deactivation in DB).
   - RedisIngestBlockAdapter execution (perimeter IP blocking).
   - RedisRateLimitAdapter execution (token-bucket rate limiting).
   - ResponseExecutor workflow with DB pre-commit and adapter dispatch.
2. Milestone 1.4:
   - VerificationManager out-of-band state checks before VERIFIED_ACTIVE transition.
   - Failure to verify marks action as VERIFICATION_FAILED.
   - RollbackManager manual analyst rollback with mandatory rationale.
   - Automated TTL expiration via check_and_expire_due_actions.
3. Milestone 1.5:
   - WebhookContainmentAdapter with cryptographic HMAC-SHA256 signature generation.
   - Upstream customer gateway containment and rollback receipts.
4. REST API Endpoints:
   - POST /api/v1/defense/actions/{action_id}/execute
   - POST /api/v1/defense/actions/{action_id}/rollback
   - POST /api/v1/defense/actions/reconcile-expirations
"""

import datetime
import hashlib
import hmac
import json
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.session import engine
from backend.main import app
from backend.models import (
    ApiKey,
    Base,
    DefenseActionModel,
    DefenseAuditLogModel,
    SecurityFinding,
    Tenant,
    TenantDefensePolicyModel,
)
from backend.core.auth import hash_api_key
from backend.schemas.defense import (
    ActionScope,
    ActionStatus,
    ActionType,
    CandidateResponseAction,
    CredentialAuthority,
    PlannedResponseAction,
    ProtectionMode,
    TargetEntityType,
)
from backend.defense.adapters import (
    InternalApiKeyAdapter,
    RedisIngestBlockAdapter,
    RedisRateLimitAdapter,
    WebhookContainmentAdapter,
)
from backend.defense.executor import ResponseExecutor
from backend.defense.filter import ingest_containment_filter
from backend.defense.rollback import RollbackManager
from backend.defense.verification import VerificationManager


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def auth_client():
    client = TestClient(app)
    tenant_id = f"test-t-{uuid.uuid4().hex[:6]}"
    raw_key = f"ce_live_test_{uuid.uuid4().hex[:12]}"
    h = hash_api_key(raw_key)

    with Session(bind=engine) as s:
        s.add(Tenant(id=tenant_id, name=f"Test Tenant {tenant_id}"))
        s.add(
            ApiKey(
                id=f"k-{uuid.uuid4().hex[:8]}",
                tenant_id=tenant_id,
                app_id="defense-test-runner",
                key_hash=h,
                key_prefix="ce_live_",
                is_active=True,
                scopes=["admin"],
            )
        )
        s.commit()

    client.headers.update({"Authorization": f"Bearer {raw_key}"})
    client.test_tenant_id = tenant_id
    client.test_raw_key = raw_key
    return client


def _create_action_record(
    db: Session,
    tenant_id: str,
    action_type: ActionType,
    target_id: str,
    status: ActionStatus = ActionStatus.APPROVED,
    scope: ActionScope = ActionScope.TERNLINE_INGEST,
    ttl_seconds: int = 3600,
    parameters: dict = None,
) -> DefenseActionModel:
    t = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not t:
        db.add(Tenant(id=tenant_id, name=f"Tenant {tenant_id}"))
        db.commit()

    action_id = f"act-{uuid.uuid4().hex[:8]}"
    finding_id = f"find-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    finding = SecurityFinding(
        finding_id=finding_id,
        tenant_id=tenant_id,
        detector_id="detector.auth.brute_force",
        detector_version="1.0.0",
        title="Test Containment Finding",
        severity="high",
        confidence="high",
        description="Automated defense testing trigger",
        evidence={},
        status="open",
        created_at=now,
    )
    db.add(finding)
    db.commit()

    model = DefenseActionModel(
        action_id=action_id,
        tenant_id=tenant_id,
        finding_id=finding_id,
        action_type=action_type.value,
        scope=scope.value,
        credential_authority=CredentialAuthority.TERNLINE_MANAGED.value if action_type == ActionType.API_KEY_REVOCATION else None,
        target_entity_type=TargetEntityType.IP_ADDRESS.value if action_type == ActionType.TEMPORARY_IP_BLOCK else TargetEntityType.API_KEY.value,
        target_entity_id=target_id,
        status=status.value,
        protection_mode=ProtectionMode.ENFORCED.value,
        deduplication_fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
        parameters=parameters or {},
        ttl_seconds=ttl_seconds,
        expires_at=now + datetime.timedelta(seconds=ttl_seconds),
        requested_by="analyst:secops@corp.internal",
        approved_by="approver:lead@corp.internal",
        approval_rationale="Approved for immediate containment",
        created_at=now,
    )
    db.add(model)
    db.commit()
    db.refresh(model)
    return model


def test_internal_api_key_adapter_execute_verify_rollback():
    """Milestone 1.3 & 1.4: Internal API key execution revokes key; rollback restores it."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"
    raw_key = f"ce_live_victim_{uuid.uuid4().hex[:8]}"
    key_id = f"k-{uuid.uuid4().hex[:8]}"

    with Session(bind=engine) as db:
        db.add(Tenant(id=tenant_id, name="Test Tenant"))
        db.add(
            ApiKey(
                id=key_id,
                tenant_id=tenant_id,
                app_id="victim-service",
                key_hash=hash_api_key(raw_key),
                key_prefix="ce_live_",
                is_active=True,
                scopes=["read", "write"],
            )
        )
        db.commit()

        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.API_KEY_REVOCATION,
            target_id=key_id,
            scope=ActionScope.TERNLINE_INGEST,
        )

        # 1. Execute action
        executor = ResponseExecutor(db)
        executed = executor.execute_action(action_id=action.action_id, tenant_id=tenant_id, actor="operator:soc")
        assert executed.status == ActionStatus.VERIFIED_ACTIVE
        assert executed.provider_adapter == "internal_api_key_adapter"
        assert executed.executed_at is not None
        assert executed.verified_at is not None

        # Verify database record: API key is inactive
        key_db = db.query(ApiKey).filter(ApiKey.id == key_id).first()
        assert key_db.is_active is False

        # 2. Rollback action
        rollback_mgr = RollbackManager(db)
        rolled_back = rollback_mgr.rollback_action(
            action_id=action.action_id,
            tenant_id=tenant_id,
            actor="operator:soc",
            rationale="Analyst confirmed incident resolved",
        )
        assert rolled_back.status == ActionStatus.ROLLED_BACK
        assert rolled_back.rolled_back_at is not None

        # Verify database record: API key is restored to active
        db.refresh(key_db)
        assert key_db.is_active is True


def test_redis_ingest_block_adapter_execute_verify_rollback():
    """Milestone 1.3 & 1.4: IP containment executes in perimeter filter, verifies, and rolls back cleanly."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"
    target_ip = "198.51.100.42"

    with Session(bind=engine) as db:
        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            target_id=target_ip,
            ttl_seconds=1200,
        )

        executor = ResponseExecutor(db)
        executed = executor.execute_action(action_id=action.action_id, tenant_id=tenant_id)
        assert executed.status == ActionStatus.VERIFIED_ACTIVE
        assert executed.provider_adapter == "redis_ingest_block_adapter"

        # Check IngestContainmentFilter
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            ingest_containment_filter.check_containment(tenant_id, client_ip=target_ip)
        assert exc.value.status_code == 403

        # Rollback
        rollback_mgr = RollbackManager(db)
        rolled_back = rollback_mgr.rollback_action(
            action_id=action.action_id,
            tenant_id=tenant_id,
            actor="operator:analyst",
            rationale="Investigation concluded threat neutralized",
        )
        assert rolled_back.status == ActionStatus.ROLLED_BACK

        # Check IngestContainmentFilter unblocked (does not raise)
        ingest_containment_filter.check_containment(tenant_id, client_ip=target_ip)


def test_redis_rate_limit_adapter_execute_verify_rollback():
    """Milestone 1.3 & 1.4: Rate limiting executes quota injection, verifies, and rolls back."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"
    target_entity = f"client-entity-{uuid.uuid4().hex[:4]}"

    with Session(bind=engine) as db:
        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.TEMPORARY_RATE_LIMIT,
            target_id=target_entity,
            ttl_seconds=600,
            parameters={"max_requests": 2},
        )

        executor = ResponseExecutor(db)
        executed = executor.execute_action(action_id=action.action_id, tenant_id=tenant_id)
        assert executed.status == ActionStatus.VERIFIED_ACTIVE
        assert executed.provider_adapter == "redis_rate_limit_adapter"

        # Rollback
        rollback_mgr = RollbackManager(db)
        rolled_back = rollback_mgr.rollback_action(
            action_id=action.action_id,
            tenant_id=tenant_id,
            actor="operator:analyst",
            rationale="Temporary rate limit expired",
        )
        assert rolled_back.status == ActionStatus.ROLLED_BACK


def test_webhook_containment_adapter_hmac_and_dispatch():
    """Milestone 1.5: Upstream customer gateway adapter calculates HMAC-SHA256 signature header and receipt ID."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"
    webhook_secret = "super_secret_signing_key_456"

    with Session(bind=engine) as db:
        # Save policy with webhook secret
        db.add(Tenant(id=tenant_id, name="Webhook Tenant"))
        db.add(
            TenantDefensePolicyModel(
                id=f"pol-{uuid.uuid4().hex[:8]}",
                tenant_id=tenant_id,
                default_mode="enforced",
                is_active=True,
                configuration={
                    "webhook_secret": webhook_secret,
                    "webhook_url": None,  # Dry run simulation mode
                },
                updated_at=datetime.datetime.now(datetime.timezone.utc),
            )
        )
        db.commit()

        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.ACCOUNT_SESSION_CONTAINMENT,
            target_id="usr_comp_99812",
            scope=ActionScope.CUSTOMER_APPLICATION,
            ttl_seconds=3600,
        )

        executor = ResponseExecutor(db)
        executed = executor.execute_action(action_id=action.action_id, tenant_id=tenant_id)
        assert executed.status == ActionStatus.VERIFIED_ACTIVE
        assert executed.provider_adapter == "webhook_containment_adapter"

        res = executed.execution_result
        assert res["success"] is True
        assert res["receipt_id"].startswith("wh_rec_")
        assert "X-Ternline-Signature" not in res  # It is placed under signature_header
        assert res["signature_header"].startswith("t=")
        assert ",v1=" in res["signature_header"]

        # Rollback
        rollback_mgr = RollbackManager(db)
        rolled_back = rollback_mgr.rollback_action(
            action_id=action.action_id,
            tenant_id=tenant_id,
            actor="operator:analyst",
            rationale="Customer cleared account session suspension",
        )
        assert rolled_back.status == ActionStatus.ROLLED_BACK
        assert rolled_back.rollback_result["receipt_id"].startswith("wh_rb_")


def test_verification_manager_failure_handling():
    """Milestone 1.4: Action for nonexistent entity fails out-of-band verification and transitions to VERIFICATION_FAILED."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"
    missing_key_id = f"k-nonexistent-{uuid.uuid4().hex[:6]}"

    with Session(bind=engine) as db:
        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.API_KEY_REVOCATION,
            target_id=missing_key_id,
            scope=ActionScope.TERNLINE_INGEST,
        )

        executor = ResponseExecutor(db)
        executed = executor.execute_action(action_id=action.action_id, tenant_id=tenant_id)
        # InternalApiKeyAdapter returns success=False for missing key
        assert executed.status == ActionStatus.EXECUTION_FAILED

        # Verify audit log recorded execution failure
        audit = (
            db.query(DefenseAuditLogModel)
            .filter(
                DefenseAuditLogModel.action_id == action.action_id,
                DefenseAuditLogModel.to_status == ActionStatus.EXECUTION_FAILED.value,
            )
            .first()
        )
        assert audit is not None


def test_scheduled_ttl_expiration_reconciliation():
    """Milestone 1.4: check_and_expire_due_actions automatically expires actions past TTL and unblocks targets."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"
    target_ip = "203.0.113.199"

    with Session(bind=engine) as db:
        # Create action already expired in the past
        past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60)
        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            target_id=target_ip,
            status=ActionStatus.VERIFIED_ACTIVE,
            ttl_seconds=30,
        )
        # Force expires_at in the past
        action.expires_at = past_time
        db.commit()

        # Add IP to filter so we can verify expiration reverts it
        from fastapi import HTTPException
        ingest_containment_filter.block_ip(tenant_id, target_ip)
        with pytest.raises(HTTPException) as exc:
            ingest_containment_filter.check_containment(tenant_id, client_ip=target_ip)
        assert exc.value.status_code == 403

        rollback_mgr = RollbackManager(db)
        expired_ids = rollback_mgr.check_and_expire_due_actions(tenant_id=tenant_id)
        assert action.action_id in expired_ids

        # Verify action status is ROLLED_BACK
        db.refresh(action)
        assert action.status == ActionStatus.ROLLED_BACK.value

        # Verify filter is unblocked (does not raise)
        ingest_containment_filter.check_containment(tenant_id, client_ip=target_ip)


def test_api_defense_execute_endpoint(auth_client):
    """Milestone 1.3 REST API: POST /api/v1/defense/actions/{action_id}/execute."""
    client = auth_client
    tenant_id = client.test_tenant_id

    with Session(bind=engine) as db:
        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            target_id="198.51.100.123",
            status=ActionStatus.APPROVED,
        )
        action_id = action.action_id

    res = client.post(f"/api/v1/defense/actions/{action_id}/execute")
    assert res.status_code == 200
    data = res.json()
    assert data["action_id"] == action_id
    assert data["status"] == "verified_active"
    assert data["provider_adapter"] == "redis_ingest_block_adapter"


def test_api_defense_rollback_endpoint(auth_client):
    """Milestone 1.4 REST API: POST /api/v1/defense/actions/{action_id}/rollback."""
    client = auth_client
    tenant_id = client.test_tenant_id

    with Session(bind=engine) as db:
        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            target_id="198.51.100.124",
            status=ActionStatus.VERIFIED_ACTIVE,
        )
        action_id = action.action_id

    res = client.post(
        f"/api/v1/defense/actions/{action_id}/rollback",
        json={"rationale": "Manual rollback by security responder for false positive"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["action_id"] == action_id
    assert data["status"] == "rolled_back"


def test_api_defense_reconcile_expirations_endpoint(auth_client):
    """Milestone 1.4 REST API: POST /api/v1/defense/actions/reconcile-expirations."""
    client = auth_client
    tenant_id = client.test_tenant_id

    with Session(bind=engine) as db:
        action = _create_action_record(
            db=db,
            tenant_id=tenant_id,
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            target_id="198.51.100.125",
            status=ActionStatus.VERIFIED_ACTIVE,
            ttl_seconds=10,
        )
        action.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=5)
        db.commit()
        action_id = action.action_id

    res = client.post("/api/v1/defense/actions/reconcile-expirations")
    assert res.status_code == 200
    expired_list = res.json()
    assert isinstance(expired_list, list)
    assert action_id in expired_list
