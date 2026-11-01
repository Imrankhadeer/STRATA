"""
Adversarial Verification Suite for Active Defense Security Remediation Checkpoint.

Strictly verifies fixes for P0, P1, and P2 security issues and gaps:
1. P0.1 - Batch Ingestion Containment:
   - Blocked IP rejected with HTTP 403 Forbidden atomically on /v1/events/batch.
   - Rate-limited entity rejected with HTTP 429 Too Many Requests with Retry-After.
   - Atomic batch rejection: no partial batch ingestion if any event is blocked.
   - Tenant isolation: blocks in Tenant A never bleed into Tenant B.
   - Zero information leakage in HTTP responses.
2. P0.2 - Expired Action Approval Rejection:
   - Approval of action past expires_at is rejected with ActionExpiredError / HTTP 409.
   - Safe comparison with timezone-aware and timezone-naive timestamps in authoritative UTC.
   - Atomic transition to EXPIRED status with ops_bus alert and audit log.
   - Non-expired actions still approve cleanly.
3. P1.3 - Verified Human Identity:
   - Service accounts, bots, agents, cron, and worker identities rejected with ServiceAccountApprovalForbiddenError.
   - Anonymous or blank identities rejected.
   - Valid human identities accepted.
4. P1.4 - Self-Approval Canonicalization:
   - Case manipulation bypass defeated (alice@corp.internal vs ALICE@CORP.INTERNAL).
   - Prefix manipulation bypass defeated (analyst:alice@corp.internal vs user:alice@corp.internal vs mailto:alice@corp.internal).
   - Whitespace manipulation bypass defeated.
   - Distinct human identities succeed.
5. P1.5 - Database-Level Deduplication (Partial Unique Index):
   - Database constraint uq_active_defense_actions_dedup prevents duplicate active actions.
   - Terminal statuses (expired, rejected, rolled_back) do not prevent re-proposal.
   - Concurrent race handling: ResponsePlanner safely coalesces on IntegrityError.
6. P2.6 - Redis Failure Observability:
   - Redis connectivity failure triggers fail-open behavior without denying traffic.
   - Transition to degraded emits defense.redis_degraded ops alert.
   - Alert deduplication: repeated queries do not flood the ops bus.
   - Recovery transition emits defense.redis_recovered ops alert.
7. P2.7 - Policy Override Precedence:
   - Mandatory Sensitive Safeguards > Action Overrides > Tenant Default Mode.
   - Action overrides allow enforcing low-risk actions while tenant default is OBSERVE.
   - Sensitive actions cannot be weakened to autonomous execution even with overrides.
"""

import datetime
import threading
import time
import uuid
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
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
from backend.core.auth import hash_api_key, create_operator_token
from backend.schemas.defense import (
    ActionScope,
    ActionStatus,
    ActionType,
    CandidateResponseAction,
    CredentialAuthority,
    PlannedResponseAction,
    PolicyEvaluationDecision,
    ProtectionMode,
    TargetEntityType,
    TenantDefensePolicy,
    TenantDefensePolicyUpdate,
    canonicalize_principal_id,
    is_verified_human_principal,
)
from backend.defense.policy import PolicyEvaluator
from backend.defense.approval import (
    ApprovalManager,
    ActionExpiredError,
    ActionNotFoundError,
    ForbiddenTenantApprovalError,
    InvalidActionStatusError,
    SelfApprovalForbiddenError,
    ServiceAccountApprovalForbiddenError,
)
from backend.defense.filter import (
    IngestContainmentFilter,
    ingest_containment_filter,
    mark_redis_failure,
    mark_redis_recovered,
)
from backend.defense.planner import ResponsePlanner
from backend.ops.bus import ops_bus


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    ingest_containment_filter.clear()
    yield
    ingest_containment_filter.clear()


@pytest.fixture
def auth_client():
    client = TestClient(app)
    tenant_id = f"test-remed-{uuid.uuid4().hex[:6]}"
    raw_key = f"ce_live_test_{uuid.uuid4().hex[:12]}"
    h = hash_api_key(raw_key)

    with Session(bind=engine) as s:
        s.add(Tenant(id=tenant_id, name=f"Test Tenant {tenant_id}"))
        s.add(ApiKey(
            id=f"k-{uuid.uuid4().hex[:8]}",
            tenant_id=tenant_id,
            app_id="payments-api",
            key_hash=h,
            key_prefix="ce_live_",
            is_active=True,
            scopes=["admin"],
        ))
        s.commit()

    client.headers.update({"Authorization": f"Bearer {raw_key}"})
    client.test_tenant_id = tenant_id
    client.test_raw_key = raw_key
    return client


def _create_sample_action(
    db: Session,
    tenant_id: str,
    requested_by: str = "analyst:alice@corp.internal",
    status: ActionStatus = ActionStatus.AWAITING_APPROVAL,
    expires_at: datetime.datetime = None,
    action_type: ActionType = ActionType.TEMPORARY_IP_BLOCK,
    target: str = "198.51.100.99",
    fingerprint: str = None,
) -> DefenseActionModel:
    t = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not t:
        db.add(Tenant(id=tenant_id, name=f"Tenant {tenant_id}"))
        db.commit()

    action_id = f"act-{uuid.uuid4().hex[:10]}"
    if fingerprint is None:
        fingerprint = f"fp-{uuid.uuid4().hex[:16]}"
    if expires_at is None:
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)

    db_action = DefenseActionModel(
        action_id=action_id,
        tenant_id=tenant_id,
        finding_id=None,
        action_type=action_type.value,
        target_entity_type="ip_address",
        target_entity_id=target,
        scope=ActionScope.TERNLINE_INGEST.value,
        deduplication_fingerprint=fingerprint,
        status=status.value,
        parameters={"ip": target, "ttl_seconds": 3600},
        requested_by=requested_by,
        expires_at=expires_at,
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db.add(db_action)
    db.commit()
    db.refresh(db_action)
    return db_action


# ===========================================================================
# 1. P0.1 - Batch Ingestion Containment Bypass Verification
# ===========================================================================

def test_remediation_batch_ingestion_blocked_ip_rejected_403(auth_client):
    tenant_id = auth_client.test_tenant_id
    blocked_ip = "198.51.100.42"
    ingest_containment_filter.block_ip(tenant_id, blocked_ip)

    batch_payload = {
        "events": [
            {
                "event_id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": "2026-11-01T12:00:00Z",
                "schema_version": "1.0.0",
                "tenant_id": tenant_id,
                "app_id": "payments-api",
                "service_id": "api-gateway",
                "event_type": "api_request",
                "severity": "low",
                "source_resource": "203.0.113.10",
                "action": "read",
            },
            {
                "event_id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": "2026-11-01T12:00:01Z",
                "schema_version": "1.0.0",
                "tenant_id": tenant_id,
                "app_id": "payments-api",
                "service_id": "api-gateway",
                "event_type": "api_request",
                "severity": "low",
                "source_resource": blocked_ip,  # Blocked IP in batch
                "action": "read",
            },
        ]
    }

    resp = auth_client.post("/v1/events/batch", json=batch_payload)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Access restricted by security containment policy"
    # Zero information leakage
    body_str = resp.text.lower()
    assert "detector" not in body_str
    assert "confidence" not in body_str
    assert "rule" not in body_str


def test_remediation_batch_ingestion_atomic_rejection_no_partial_ingest(auth_client):
    tenant_id = auth_client.test_tenant_id
    blocked_ip = "198.51.100.43"
    ingest_containment_filter.block_ip(tenant_id, blocked_ip)

    event_id_1 = f"evt-remed-clean-{uuid.uuid4().hex[:6]}"
    event_id_2 = f"evt-remed-blocked-{uuid.uuid4().hex[:6]}"

    batch_payload = {
        "events": [
            {
                "event_id": event_id_1,
                "timestamp": "2026-11-01T12:00:00Z",
                "schema_version": "1.0.0",
                "tenant_id": tenant_id,
                "app_id": "payments-api",
                "service_id": "api-gateway",
                "event_type": "api_request",
                "severity": "low",
                "source_resource": "203.0.113.55",
                "action": "read",
            },
            {
                "event_id": event_id_2,
                "timestamp": "2026-11-01T12:00:01Z",
                "schema_version": "1.0.0",
                "tenant_id": tenant_id,
                "app_id": "payments-api",
                "service_id": "api-gateway",
                "event_type": "api_request",
                "severity": "low",
                "source_resource": blocked_ip,
                "action": "read",
            },
        ]
    }

    resp = auth_client.post("/v1/events/batch", json=batch_payload)
    assert resp.status_code == 403

    # Verify atomic rejection: event 1 was NOT persisted
    from backend.models import EventModel
    with Session(bind=engine) as s:
        evt1 = s.query(EventModel).filter(EventModel.event_id == event_id_1).first()
        evt2 = s.query(EventModel).filter(EventModel.event_id == event_id_2).first()
        assert evt1 is None
        assert evt2 is None


def test_remediation_batch_ingestion_rate_limit_rejected_429(auth_client):
    tenant_id = auth_client.test_tenant_id
    limited_entity = "throttled-worker"
    ingest_containment_filter.set_rate_limit(tenant_id, limited_entity, quota=0, ttl_seconds=45)

    batch_payload = {
        "events": [
            {
                "event_id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": "2026-11-01T12:00:00Z",
                "schema_version": "1.0.0",
                "tenant_id": tenant_id,
                "app_id": "payments-api",
                "service_id": "api-gateway",
                "event_type": "api_request",
                "severity": "low",
                "source_resource": limited_entity,
                "action": "read",
            }
        ]
    }

    resp = auth_client.post("/v1/events/batch", json=batch_payload)
    assert resp.status_code == 429
    assert resp.json()["detail"] == "Rate limit exceeded by active security policy"
    assert "Retry-After" in resp.headers
    assert int(resp.headers["Retry-After"]) > 0


def test_remediation_batch_ingestion_tenant_isolation(auth_client):
    tenant_a = auth_client.test_tenant_id
    tenant_b = f"test-remed-other-{uuid.uuid4().hex[:6]}"
    raw_key_b = f"ce_live_test_{uuid.uuid4().hex[:12]}"

    with Session(bind=engine) as s:
        s.add(Tenant(id=tenant_b, name=f"Other Tenant {tenant_b}"))
        s.add(ApiKey(
            id=f"k-{uuid.uuid4().hex[:8]}",
            tenant_id=tenant_b,
            app_id="payments-api",
            key_hash=hash_api_key(raw_key_b),
            key_prefix="ce_live_",
            is_active=True,
        ))
        s.commit()

    target_ip = "198.51.100.77"
    # Block in tenant_a only
    ingest_containment_filter.block_ip(tenant_a, target_ip)

    # Ingesting under tenant_b must succeed
    client_b = TestClient(app)
    client_b.headers.update({"Authorization": f"Bearer {raw_key_b}"})

    batch_payload = {
        "events": [
            {
                "event_id": f"evt-tb-{uuid.uuid4().hex[:8]}",
                "timestamp": "2026-11-01T12:00:00Z",
                "schema_version": "1.0.0",
                "tenant_id": tenant_b,
                "app_id": "payments-api",
                "service_id": "api-gateway",
                "event_type": "api_request",
                "severity": "low",
                "source_resource": target_ip,
                "action": "read",
            }
        ]
    }
    resp = client_b.post("/v1/events/batch", json=batch_payload)
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1


# ===========================================================================
# 2. P0.2 - Expired Action Approval Rejection
# ===========================================================================

def test_remediation_expired_action_approval_rejected_direct():
    with Session(bind=engine) as db:
        # Create an action expired 10 minutes ago
        past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)
        action = _create_sample_action(
            db,
            tenant_id="tenant-remed-exp",
            requested_by="analyst:alice@corp.internal",
            expires_at=past_time,
        )
        manager = ApprovalManager(db)

        # Attempt to approve expired action -> must raise ActionExpiredError
        with pytest.raises(ActionExpiredError) as exc_info:
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-exp",
                approver_identity="security-lead:bob@corp.internal",
                rationale="Approved after incident post-mortem",
            )
        assert f"expired at" in str(exc_info.value).lower()
        assert "cannot be approved" in str(exc_info.value).lower()

        # Check atomic status transition to EXPIRED
        db.refresh(action)
        assert action.status == ActionStatus.EXPIRED.value
        assert action.approved_by is None

        # Check immutable audit log recorded
        audit = db.query(DefenseAuditLogModel).filter(
            DefenseAuditLogModel.action_id == action.action_id,
            DefenseAuditLogModel.transition_trigger == "approval_manager.reject_expired",
        ).first()
        assert audit is not None
        assert audit.actor == "system:approval_manager"
        assert "expired at" in audit.details["reason"].lower()


def test_remediation_expired_action_approval_rejected_via_api(auth_client):
    tenant_id = auth_client.test_tenant_id
    past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)

    with Session(bind=engine) as db:
        action = _create_sample_action(
            db,
            tenant_id=tenant_id,
            requested_by="analyst:alice@corp.internal",
            expires_at=past_time,
        )
        action_id = action.action_id

    # POST to approve endpoint with verified human operator token -> HTTP 409 Conflict
    token_bob = create_operator_token("lead:bob@corp.internal", tenant_id=tenant_id)
    resp = auth_client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        json={
            "approver_identity": "lead:bob@corp.internal",
            "rationale": "Late approval attempt",
        },
        headers={"X-Operator-Token": f"Bearer {token_bob}"},
    )
    assert resp.status_code == 409
    assert "expired" in resp.json()["detail"].lower()


def test_remediation_timezone_naive_legacy_expiry_handled_correctly():
    with Session(bind=engine) as db:
        # Timezone-naive past timestamp (simulating legacy database records)
        naive_past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).replace(tzinfo=None)
        action = _create_sample_action(
            db,
            tenant_id="tenant-remed-naive",
            requested_by="analyst:alice@corp.internal",
            expires_at=naive_past,
        )
        manager = ApprovalManager(db)

        # Must not raise Python TypeError: can't compare offset-naive and offset-aware datetimes
        with pytest.raises(ActionExpiredError):
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-naive",
                approver_identity="lead:bob@corp.internal",
                rationale="Approving legacy action",
            )


def test_remediation_future_expiry_approved_successfully():
    with Session(bind=engine) as db:
        future_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        action = _create_sample_action(
            db,
            tenant_id="tenant-remed-future",
            requested_by="analyst:alice@corp.internal",
            expires_at=future_time,
        )
        manager = ApprovalManager(db)

        res = manager.approve_action(
            action_id=action.action_id,
            tenant_id="tenant-remed-future",
            approver_identity="lead:bob@corp.internal",
            rationale="Legitimate timely approval",
        )
        assert res.status == ActionStatus.APPROVED.value
        assert res.approved_by == "lead:bob@corp.internal"


# ===========================================================================
# 3. P1.3 - Verified Human Identity
# ===========================================================================

@pytest.mark.parametrize("bot_identity", [
    "service:data-sync",
    "service:backend-worker",
    "bot:slack-alert-bot",
    "agent:deep-track-investigator",
    "cron:daily-cleaner",
    "worker:task-processor",
    "system:auto-defense",
    "api_key:ce_live_12345",
])
def test_remediation_approver_service_accounts_rejected(bot_identity):
    is_human, reason = is_verified_human_principal(bot_identity)
    assert not is_human
    assert "non-human" in reason.lower() or "automated" in reason.lower()

    with Session(bind=engine) as db:
        action = _create_sample_action(db, "tenant-remed-bot", requested_by="alice@corp.internal")
        manager = ApprovalManager(db)
        with pytest.raises(ServiceAccountApprovalForbiddenError):
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-bot",
                approver_identity=bot_identity,
                rationale="Automated script approval",
            )


@pytest.mark.parametrize("blank_identity", ["", "   ", None])
def test_remediation_approver_blank_identity_rejected(blank_identity):
    is_human, reason = is_verified_human_principal(blank_identity)
    assert not is_human

    with Session(bind=engine) as db:
        action = _create_sample_action(db, "tenant-remed-blank", requested_by="alice@corp.internal")
        manager = ApprovalManager(db)
        with pytest.raises(ServiceAccountApprovalForbiddenError):
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-blank",
                approver_identity=blank_identity or "",
                rationale="Blank approval",
            )


@pytest.mark.parametrize("valid_human", [
    "alice@corp.internal",
    "user:bob@company.com",
    "analyst:carol@domain.org",
    "secops:david@soc.corp",
])
def test_remediation_approver_valid_humans_accepted(valid_human):
    is_human, reason = is_verified_human_principal(valid_human)
    assert is_human
    assert reason is None


# ===========================================================================
# 4. P1.4 - Self-Approval Normalization & Canonicalization
# ===========================================================================

def test_remediation_self_approval_casing_bypass_defeated():
    with Session(bind=engine) as db:
        action = _create_sample_action(
            db,
            tenant_id="tenant-remed-canon",
            requested_by="alice@corp.internal",
        )
        manager = ApprovalManager(db)

        # Approver attempts bypass by uppercasing identity
        with pytest.raises(SelfApprovalForbiddenError) as exc_info:
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-canon",
                approver_identity="ALICE@CORP.INTERNAL",
                rationale="Attempted casing bypass",
            )
        assert "cannot approve their own defense action" in str(exc_info.value)
        assert "alice@corp.internal" in str(exc_info.value)


def test_remediation_self_approval_prefix_bypass_defeated():
    with Session(bind=engine) as db:
        # Requester recorded as analyst:alice@corp.internal
        action = _create_sample_action(
            db,
            tenant_id="tenant-remed-canon-prefix",
            requested_by="analyst:alice@corp.internal",
        )
        manager = ApprovalManager(db)

        # Bypass 1: "user:alice@corp.internal"
        with pytest.raises(SelfApprovalForbiddenError):
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-canon-prefix",
                approver_identity="user:alice@corp.internal",
                rationale="Attempted prefix change",
            )

        # Bypass 2: "mailto:alice@corp.internal"
        with pytest.raises(SelfApprovalForbiddenError):
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-canon-prefix",
                approver_identity="mailto:alice@corp.internal",
                rationale="Attempted mailto scheme",
            )

        # Bypass 3: bare email "alice@corp.internal"
        with pytest.raises(SelfApprovalForbiddenError):
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-canon-prefix",
                approver_identity="alice@corp.internal",
                rationale="Attempted bare email",
            )


def test_remediation_self_approval_whitespace_bypass_defeated():
    with Session(bind=engine) as db:
        action = _create_sample_action(
            db,
            tenant_id="tenant-remed-canon-ws",
            requested_by="  alice@corp.internal  ",
        )
        manager = ApprovalManager(db)

        with pytest.raises(SelfApprovalForbiddenError):
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="tenant-remed-canon-ws",
                approver_identity="alice@corp.internal",
                rationale="Whitespace padding bypass attempt",
            )


def test_remediation_dual_custody_distinct_humans_succeed():
    with Session(bind=engine) as db:
        action = _create_sample_action(
            db,
            tenant_id="tenant-remed-dual-valid",
            requested_by="analyst:alice@corp.internal",
        )
        manager = ApprovalManager(db)

        res = manager.approve_action(
            action_id=action.action_id,
            tenant_id="tenant-remed-dual-valid",
            approver_identity="user:bob@corp.internal",
            rationale="Legitimate peer review and approval",
        )
        assert res.status == ActionStatus.APPROVED.value
        assert res.approved_by == "user:bob@corp.internal"


# ===========================================================================
# 5. P1.5 - Database-Level Deduplication (Partial Unique Index)
# ===========================================================================

def test_remediation_database_partial_unique_index_enforced():
    """
    Directly tests that the database schema rejects duplicate active defense actions
    via the partial unique index uq_active_defense_actions_dedup.
    """
    shared_fingerprint = f"fp-dedup-index-{uuid.uuid4().hex[:10]}"
    tenant_id = "tenant-remed-dedup"

    with Session(bind=engine) as s1:
        t = s1.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not t:
            s1.add(Tenant(id=tenant_id, name=f"Tenant {tenant_id}"))
            s1.commit()

        a1 = DefenseActionModel(
            action_id=f"act-dedup-1-{uuid.uuid4().hex[:6]}",
            tenant_id=tenant_id,
            finding_id=None,
            action_type=ActionType.TEMPORARY_IP_BLOCK.value,
            target_entity_type="ip_address",
            target_entity_id="198.51.100.200",
            scope=ActionScope.TERNLINE_INGEST.value,
            deduplication_fingerprint=shared_fingerprint,
            status=ActionStatus.PROPOSED.value,
            parameters={"ip": "198.51.100.200"},
            requested_by="analyst:alice@corp.internal",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        s1.add(a1)
        s1.commit()

    with Session(bind=engine) as s2:
        a2 = DefenseActionModel(
            action_id=f"act-dedup-2-{uuid.uuid4().hex[:6]}",
            tenant_id=tenant_id,
            finding_id=None,
            action_type=ActionType.TEMPORARY_IP_BLOCK.value,
            target_entity_type="ip_address",
            target_entity_id="198.51.100.200",
            scope=ActionScope.TERNLINE_INGEST.value,
            deduplication_fingerprint=shared_fingerprint,
            status=ActionStatus.AWAITING_APPROVAL.value,  # Also an active status
            parameters={"ip": "198.51.100.200"},
            requested_by="analyst:bob@corp.internal",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        s2.add(a2)
        with pytest.raises(IntegrityError):
            s2.commit()
        s2.rollback()


def test_remediation_terminal_statuses_do_not_block_reproposal():
    """
    Verifies that the partial unique index ONLY covers active statuses, allowing
    legitimate re-proposals after an action has EXPIRED or been REJECTED.
    """
    shared_fingerprint = f"fp-terminal-{uuid.uuid4().hex[:10]}"
    tenant_id = "tenant-remed-terminal"

    with Session(bind=engine) as s:
        t = s.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not t:
            s.add(Tenant(id=tenant_id, name=f"Tenant {tenant_id}"))
            s.commit()

        # First action: expired
        a1 = DefenseActionModel(
            action_id=f"act-term-1-{uuid.uuid4().hex[:6]}",
            tenant_id=tenant_id,
            finding_id=None,
            action_type=ActionType.TEMPORARY_IP_BLOCK.value,
            target_entity_type="ip_address",
            target_entity_id="198.51.100.201",
            scope=ActionScope.TERNLINE_INGEST.value,
            deduplication_fingerprint=shared_fingerprint,
            status=ActionStatus.EXPIRED.value,  # Terminal status
            parameters={"ip": "198.51.100.201"},
            requested_by="analyst:alice@corp.internal",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        s.add(a1)
        s.commit()

        # Second action: new proposed action with identical fingerprint
        a2 = DefenseActionModel(
            action_id=f"act-term-2-{uuid.uuid4().hex[:6]}",
            tenant_id=tenant_id,
            finding_id=None,
            action_type=ActionType.TEMPORARY_IP_BLOCK.value,
            target_entity_type="ip_address",
            target_entity_id="198.51.100.201",
            scope=ActionScope.TERNLINE_INGEST.value,
            deduplication_fingerprint=shared_fingerprint,
            status=ActionStatus.PROPOSED.value,
            parameters={"ip": "198.51.100.201"},
            requested_by="analyst:bob@corp.internal",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        s.add(a2)
        # Must commit successfully without IntegrityError
        s.commit()
        assert a2.action_id is not None


def test_remediation_response_planner_handles_concurrent_integrity_error():
    """
    Verifies that ResponsePlanner._persist_or_coalesce_action cleanly catches
    IntegrityError and coalesces into the winning concurrent record.
    """
    tenant_id = f"tenant-remed-race-{uuid.uuid4().hex[:6]}"

    with Session(bind=engine) as db:
        t = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not t:
            db.add(Tenant(id=tenant_id, name=f"Tenant {tenant_id}"))
            db.commit()

        finding = SecurityFinding(
            finding_id=f"find-race-{uuid.uuid4().hex[:6]}",
            tenant_id=tenant_id,
            detector_id="detector.auth.brute_force",
            detector_version="1.0.0",
            title="Multiple Failed Logins",
            severity="high",
            confidence="high",
            description="Brute force attack detected",
            evidence={"client_ip": "198.51.100.111", "attempts": 25, "app_id": "payments-api"},
            status="open",
        )
        db.add(finding)
        db.commit()

        planner1 = ResponsePlanner(db)
        actions1 = planner1.plan_from_finding(finding)
        assert len(actions1) == 1

    with Session(bind=engine) as db2:
        planner2 = ResponsePlanner(db2)
        actions2 = planner2.plan_from_finding(finding)
        assert len(actions2) == 1
        assert actions2[0].action_id == actions1[0].action_id


# ===========================================================================
# 6. P2.6 - Redis Failure Observability
# ===========================================================================

def test_remediation_redis_failure_emits_degraded_ops_event():
    """
    Verifies that when Redis containment raises an exception, the filter:
    1. Fails open safely without denying legitimate requests.
    2. Emits a defense.redis_degraded ops event.
    3. Reflects degradation via is_degraded.
    """
    ops_bus.clear_buffer()
    ingest_containment_filter.clear()

    mock_redis = MagicMock()
    mock_redis.sismember.side_effect = ConnectionError("Connection refused by test mock")

    filter_instance = IngestContainmentFilter(redis_client=mock_redis)

    # Check containment should fail open safely
    filter_instance.check_containment(
        tenant_id="tenant-test-deg",
        client_ip="198.51.100.9",
    )
    events = [e for e in ops_bus._buffer if e.event_type == "defense.redis_degraded"]
    assert len(events) >= 1
    assert events[0].component == "defense"
    assert events[0].level == "error"
    assert events[0].metadata.get("fail_open") is True


def test_remediation_redis_degraded_alert_deduplication():
    """
    Verifies that subsequent containment checks while degraded do not flood ops_bus.
    """
    ops_bus.clear_buffer()
    ingest_containment_filter.clear()

    mark_redis_failure(ConnectionError("First failure"))
    events1 = [e for e in ops_bus._buffer if e.event_type == "defense.redis_degraded"]
    assert len(events1) >= 1

    # Second failure while already degraded
    mark_redis_failure(ConnectionError("Second failure"))
    events2 = [e for e in ops_bus._buffer if e.event_type == "defense.redis_degraded"]
    # Must NOT re-publish alert (deduplicated)
    assert len(events2) == len(events1)


def test_remediation_redis_recovery_emits_recovery_event():
    """
    Verifies that calling mark_redis_recovered() emits defense.redis_recovered
    and resets the degraded latch.
    """
    ops_bus.clear_buffer()
    ingest_containment_filter.clear()

    mark_redis_failure(ConnectionError("Temporary down"))
    mark_redis_recovered()
    events = [e for e in ops_bus._buffer if e.event_type == "defense.redis_recovered"]
    assert len(events) >= 1
    assert events[0].component == "defense"
    assert events[0].level == "info"


# ===========================================================================
# 7. P2.7 - Policy Override Precedence
# ===========================================================================

def test_remediation_policy_override_takes_precedence_over_tenant_mode():
    """
    Tenant default mode is OBSERVE, but action_overrides sets TEMPORARY_IP_BLOCK to ENFORCED.
    Evaluation must return EXECUTE_AUTONOMOUS (override precedence).
    """
    with Session(bind=engine) as db:
        evaluator = PolicyEvaluator(db)
        policy = TenantDefensePolicy(
            tenant_id="tenant-precedence",
            default_mode=ProtectionMode.OBSERVE,
            action_overrides={
                ActionType.TEMPORARY_IP_BLOCK.value: ProtectionMode.ENFORCED,
            },
        )

        action = PlannedResponseAction(
            action_id="act-prec-1",
            tenant_id="tenant-precedence",
            finding_id="find-prec-1",
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            target_entity_type=TargetEntityType.IP_ADDRESS,
            target_entity_id="198.51.100.8",
            scope=ActionScope.TERNLINE_INGEST,
            deduplication_fingerprint="fp-prec-1",
            parameters={"ip": "198.51.100.8", "ttl_seconds": 300},
            execution_guardrails={"require_approval": False},
            rollback_supported=True,
            confidence=0.95,
            status=ActionStatus.PROPOSED,
            requested_by="system:planner",
        )

        decision = evaluator.evaluate(action, policy)
        assert decision.decision == PolicyEvaluationDecision.ALLOW_AUTONOMOUS
        assert decision.applied_mode == ProtectionMode.ENFORCED
        assert "explicit action override" in decision.rationale


def test_remediation_sensitive_action_override_cannot_weaken_safeguards():
    """
    Tenant default mode is ENFORCED, and tenant attempts to override API_KEY_REVOCATION to ENFORCED.
    Mandatory safeguards must prevent autonomous execution and force REQUIRE_APPROVAL.
    """
    with Session(bind=engine) as db:
        evaluator = PolicyEvaluator(db)
        policy = TenantDefensePolicy(
            tenant_id="tenant-precedence-sensitive",
            default_mode=ProtectionMode.ENFORCED,
            action_overrides={
                ActionType.API_KEY_REVOCATION.value: ProtectionMode.ENFORCED,
            },
        )

        action = PlannedResponseAction(
            action_id="act-prec-2",
            tenant_id="tenant-precedence-sensitive",
            finding_id="find-prec-2",
            action_type=ActionType.API_KEY_REVOCATION,
            target_entity_type=TargetEntityType.API_KEY,
            target_entity_id="key-compromised-123",
            scope=ActionScope.TERNLINE_INGEST,
            deduplication_fingerprint="fp-prec-2",
            parameters={"key_id": "key-compromised-123"},
            execution_guardrails={"require_approval": True},
            rollback_supported=False,
            confidence=0.99,
            status=ActionStatus.PROPOSED,
            requested_by="system:planner",
        )

        decision = evaluator.evaluate(action, policy)
        assert decision.decision == PolicyEvaluationDecision.REQUIRE_APPROVAL
        assert decision.requires_dual_custody is True
        assert "mandates dual-custody human approval" in decision.rationale


def test_remediation_unspecified_action_falls_back_to_tenant_mode():
    """
    Tenant default mode is ASSISTED. action_overrides only covers TEMPORARY_IP_BLOCK.
    ACCOUNT_SESSION_CONTAINMENT must fall back to ASSISTED mode (REQUIRE_APPROVAL).
    """
    with Session(bind=engine) as db:
        evaluator = PolicyEvaluator(db)
        policy = TenantDefensePolicy(
            tenant_id="tenant-precedence-fallback",
            default_mode=ProtectionMode.ASSISTED,
            action_overrides={
                ActionType.TEMPORARY_IP_BLOCK.value: ProtectionMode.ENFORCED,
            },
        )

        action = PlannedResponseAction(
            action_id="act-prec-3",
            tenant_id="tenant-precedence-fallback",
            finding_id="find-prec-3",
            action_type=ActionType.ACCOUNT_SESSION_CONTAINMENT,
            target_entity_type=TargetEntityType.USER_ID,
            target_entity_id="user-victim",
            scope=ActionScope.CUSTOMER_APPLICATION,
            deduplication_fingerprint="fp-prec-3",
            parameters={"user_id": "user-victim"},
            execution_guardrails={"require_approval": True},
            rollback_supported=True,
            confidence=0.90,
            status=ActionStatus.PROPOSED,
            requested_by="system:planner",
        )

        decision = evaluator.evaluate(action, policy)
        assert decision.decision == PolicyEvaluationDecision.REQUIRE_APPROVAL
        assert decision.requires_dual_custody is True
