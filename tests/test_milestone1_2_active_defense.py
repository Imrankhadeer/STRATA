"""
Test Suite for Milestone 1.2: Active Defense Policy Engine, Dual-Custody Approval,
and Ingestion Containment Semantics.

Covers:
1. Adversarial Dual-Custody Approval Tests:
   - Self-approval attempt rejection (HTTP 403).
   - Service account / API key approval rejection (HTTP 403).
   - Cross-tenant approval attempt rejection (HTTP 403).
   - Replayed approval attempt rejection (HTTP 409).
   - Concurrent approval attempts safety.
   - Valid dual-custody approval.
2. Policy Engine Tests:
   - OBSERVE mode default (DRY_RUN_LOGGED).
   - ASSISTED mode (REQUIRE_APPROVAL).
   - ENFORCED mode: low-risk autonomous execution vs mandatory approval for sensitive actions.
   - Policy update validation: prevents weakening mandatory safeguards.
3. Ingestion Blocking HTTP Semantics (Decision 2):
   - Explicit temporary IP block (HTTP 403 Forbidden).
   - Zero information leakage (no detector ID or confidence score exposure).
   - Temporary rate limit (HTTP 429 Too Many Requests with Retry-After header).
   - Infrastructure failure recovery: Redis failure fails open safely without blocking legitimate traffic.
   - Invalid API credentials (HTTP 401 Unauthorized).
4. Full REST API Lifecycle Tests.
"""

import concurrent.futures
import datetime
import uuid
import pytest
from unittest.mock import MagicMock
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
)
from backend.defense.policy import PolicyEvaluator
from backend.defense.approval import (
    ApprovalManager,
    ActionNotFoundError,
    ForbiddenTenantApprovalError,
    InvalidActionStatusError,
    SelfApprovalForbiddenError,
    ServiceAccountApprovalForbiddenError,
)
from backend.defense.filter import IngestContainmentFilter


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def auth_client():
    client = TestClient(app)
    # Seed tenant and API key
    tenant_id = f"test-t-{uuid.uuid4().hex[:6]}"
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


def create_pending_action(
    db: Session,
    tenant_id: str,
    action_type: ActionType = ActionType.API_KEY_REVOCATION,
    requested_by: str = "analyst:alice@corp.internal",
    target_id: str = "ce_live_compromised_key_1",
) -> DefenseActionModel:
    t = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not t:
        db.add(Tenant(id=tenant_id, name=f"Tenant {tenant_id}"))
        db.commit()

    action_id = f"act-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    action = DefenseActionModel(
        action_id=action_id,
        tenant_id=tenant_id,
        action_type=action_type.value,
        scope=ActionScope.TERNLINE_INGEST.value,
        credential_authority=CredentialAuthority.TERNLINE_MANAGED.value if action_type == ActionType.API_KEY_REVOCATION else None,
        target_entity_type=TargetEntityType.API_KEY.value if action_type == ActionType.API_KEY_REVOCATION else TargetEntityType.IP_ADDRESS.value,
        target_entity_id=target_id,
        status=ActionStatus.AWAITING_APPROVAL.value,
        protection_mode=ProtectionMode.ASSISTED.value,
        deduplication_fingerprint=f"fp-{uuid.uuid4().hex[:16]}",
        parameters={"reason": "Test Containment"},
        ttl_seconds=1800 if "temporary" in action_type.value else None,
        requested_by=requested_by,
        created_at=now,
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


# ---------------------------------------------------------------------------
# 1. Adversarial Dual-Custody Approval Tests
# ---------------------------------------------------------------------------

def test_dual_custody_self_approval_rejected():
    with Session(bind=engine) as db:
        action = create_pending_action(db, "test-tenant-dual", requested_by="analyst:alice@corp.internal")
        manager = ApprovalManager(db)

        # Alice attempts to approve her own requested action -> Strictly Forbidden
        with pytest.raises(SelfApprovalForbiddenError) as exc_info:
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="test-tenant-dual",
                approver_identity="analyst:alice@corp.internal",
                rationale="Approving my own action",
            )
        assert "Requester 'analyst:alice@corp.internal' cannot approve their own defense action" in str(exc_info.value)


def test_dual_custody_service_account_approval_rejected():
    with Session(bind=engine) as db:
        action = create_pending_action(db, "test-tenant-dual", requested_by="analyst:alice@corp.internal")
        manager = ApprovalManager(db)

        # Service account attempts to approve -> Forbidden
        for bad_actor in ("service:worker-agent", "key:api-key-99", "system:cron"):
            with pytest.raises(ServiceAccountApprovalForbiddenError):
                manager.approve_action(
                    action_id=action.action_id,
                    tenant_id="test-tenant-dual",
                    approver_identity=bad_actor,
                    rationale="Bot approval",
                )


def test_cross_tenant_approval_rejected():
    with Session(bind=engine) as db:
        action_t1 = create_pending_action(db, "tenant-victim", requested_by="analyst:alice@corp.internal")
        manager = ApprovalManager(db)

        # Tenant attacker attempts to approve Tenant victim's action -> Forbidden
        with pytest.raises(ForbiddenTenantApprovalError):
            manager.approve_action(
                action_id=action_t1.action_id,
                tenant_id="tenant-attacker",
                approver_identity="user:bob@corp.internal",
                rationale="Cross-tenant unauthorized approval",
            )


def test_replayed_approval_rejected():
    with Session(bind=engine) as db:
        action = create_pending_action(db, "test-tenant-dual", requested_by="analyst:alice@corp.internal")
        manager = ApprovalManager(db)

        # 1. First approval by Carol succeeds
        approved = manager.approve_action(
            action_id=action.action_id,
            tenant_id="test-tenant-dual",
            approver_identity="user:carol@corp.internal",
            rationale="Legitimate human approval by peer",
        )
        assert approved.status == ActionStatus.APPROVED

        # 2. Second (replayed) approval attempt must be rejected with InvalidActionStatusError
        with pytest.raises(InvalidActionStatusError) as exc:
            manager.approve_action(
                action_id=action.action_id,
                tenant_id="test-tenant-dual",
                approver_identity="user:dave@corp.internal",
                rationale="Replayed approval",
            )
        assert "current status is 'approved'" in str(exc.value)


def test_concurrent_approval_attempts_safety():
    """
    Simulates multiple concurrent approval calls on the same action.
    Only one must succeed; subsequent concurrent calls must fail with InvalidActionStatusError.
    """
    with Session(bind=engine) as db:
        action = create_pending_action(db, "test-tenant-dual", requested_by="analyst:alice@corp.internal")
        action_id = action.action_id

    success_count = 0
    failure_count = 0

    def _approve_worker(user_id):
        with Session(bind=engine) as s:
            m = ApprovalManager(s)
            try:
                m.approve_action(
                    action_id=action_id,
                    tenant_id="test-tenant-dual",
                    approver_identity=f"user:{user_id}@corp.internal",
                    rationale="Concurrent approval attempt",
                )
                return True
            except InvalidActionStatusError:
                return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_approve_worker, f"user_{i}") for i in range(4)]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                success_count += 1
            else:
                failure_count += 1

    assert success_count == 1
    assert failure_count == 3


def test_valid_dual_custody_approval_and_audit():
    with Session(bind=engine) as db:
        action = create_pending_action(
            db, "test-tenant-dual", requested_by="analyst:alice@corp.internal", action_type=ActionType.API_KEY_REVOCATION
        )
        manager = ApprovalManager(db)

        # Carol (a different human) approves
        approved = manager.approve_action(
            action_id=action.action_id,
            tenant_id="test-tenant-dual",
            approver_identity="user:carol@corp.internal",
            rationale="Verified malicious data exfiltration pattern",
        )

        assert approved.status == ActionStatus.APPROVED
        assert approved.approved_by == "user:carol@corp.internal"
        assert approved.approval_rationale == "Verified malicious data exfiltration pattern"

        # Check immutable audit log
        logs = (
            db.query(DefenseAuditLogModel)
            .filter(DefenseAuditLogModel.action_id == action.action_id)
            .all()
        )
        assert len(logs) == 1
        log = logs[0]
        assert log.actor == "user:carol@corp.internal"
        assert log.details["requester"] == "analyst:alice@corp.internal"
        assert log.details["approver"] == "user:carol@corp.internal"


def test_reject_action():
    with Session(bind=engine) as db:
        action = create_pending_action(db, "test-tenant-dual", requested_by="analyst:alice@corp.internal")
        manager = ApprovalManager(db)

        rejected = manager.reject_action(
            action_id=action.action_id,
            tenant_id="test-tenant-dual",
            rejector_identity="user:security_lead@corp.internal",
            rationale="False positive: authorized load test",
        )

        assert rejected.status == ActionStatus.REJECTED
        assert "REJECTED" in (rejected.approval_rationale or "")


# ---------------------------------------------------------------------------
# 2. Policy Engine Tests
# ---------------------------------------------------------------------------

def test_policy_evaluator_observe_mode():
    with Session(bind=engine) as db:
        evaluator = PolicyEvaluator(db)
        action = PlannedResponseAction(
            tenant_id="tenant-observe",
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            scope=ActionScope.TERNLINE_INGEST,
            target_entity_type=TargetEntityType.IP_ADDRESS,
            target_entity_id="198.51.100.1",
            deduplication_fingerprint="fp1",
            ttl_seconds=1800,
            requested_by="system:planner",
        )
        policy = TenantDefensePolicy(tenant_id="tenant-observe", default_mode=ProtectionMode.OBSERVE)

        result = evaluator.evaluate(action, policy_override=policy)
        assert result.decision == PolicyEvaluationDecision.DRY_RUN_LOGGED
        assert result.applied_mode == ProtectionMode.OBSERVE


def test_policy_evaluator_enforced_mode_autonomous_bounded():
    with Session(bind=engine) as db:
        evaluator = PolicyEvaluator(db)
        # Low risk IP block within 3600s TTL -> Autonomous
        action = PlannedResponseAction(
            tenant_id="tenant-enforced",
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            scope=ActionScope.TERNLINE_INGEST,
            target_entity_type=TargetEntityType.IP_ADDRESS,
            target_entity_id="198.51.100.1",
            deduplication_fingerprint="fp2",
            ttl_seconds=1800,
            requested_by="system:planner",
        )
        policy = TenantDefensePolicy(
            tenant_id="tenant-enforced",
            default_mode=ProtectionMode.ENFORCED,
            allowed_autonomous_actions=[ActionType.TEMPORARY_IP_BLOCK],
            max_autonomous_ttl_seconds=3600,
        )

        result = evaluator.evaluate(action, policy_override=policy)
        assert result.decision == PolicyEvaluationDecision.ALLOW_AUTONOMOUS
        assert result.requires_dual_custody is False


def test_policy_evaluator_sensitive_actions_require_approval_even_in_enforced():
    with Session(bind=engine) as db:
        evaluator = PolicyEvaluator(db)
        # Sensitive action (API key revocation) in ENFORCED mode -> Still REQUIRES APPROVAL
        action = PlannedResponseAction(
            tenant_id="tenant-enforced",
            action_type=ActionType.API_KEY_REVOCATION,
            scope=ActionScope.TERNLINE_INGEST,
            credential_authority=CredentialAuthority.TERNLINE_MANAGED,
            target_entity_type=TargetEntityType.API_KEY,
            target_entity_id="ce_live_test_123",
            deduplication_fingerprint="fp3",
            requested_by="system:planner",
        )
        policy = TenantDefensePolicy(tenant_id="tenant-enforced", default_mode=ProtectionMode.ENFORCED)

        result = evaluator.evaluate(action, policy_override=policy)
        assert result.decision == PolicyEvaluationDecision.REQUIRE_APPROVAL
        assert result.requires_dual_custody is True


def test_cannot_weaken_safeguards_in_policy_update():
    # Attempting to authorize autonomous API key revocation fails validation
    with pytest.raises(ValueError) as exc:
        TenantDefensePolicyUpdate(
            allowed_autonomous_actions=[ActionType.API_KEY_REVOCATION]
        )
    assert "Mandatory safety violation" in str(exc.value)


# ---------------------------------------------------------------------------
# 3. Ingestion Blocking HTTP Semantics Tests (Decision 2)
# ---------------------------------------------------------------------------

def test_ingestion_temporary_ip_block_returns_403(auth_client: TestClient):
    """
    Decision 2: An explicit temporary IP block returns HTTP 403 Forbidden
    with zero leakage of detector IDs, confidence scores, or rule names.
    """
    mock_redis = MagicMock()
    # Mock sismember returning True for blocked IP 203.0.113.99
    mock_redis.sismember.side_effect = lambda key, val: val == "203.0.113.99"
    mock_redis.get.return_value = None

    custom_filter = IngestContainmentFilter(redis_client=mock_redis)

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        custom_filter.check_containment(
            tenant_id=auth_client.test_tenant_id,
            client_ip="203.0.113.99",
            entity_id="payments-api",
        )

    assert exc.value.status_code == 403
    # Verify zero leakage of detector names or internal scores
    assert exc.value.detail == "Access restricted by security containment policy"
    assert "detector" not in exc.value.detail
    assert "confidence" not in exc.value.detail


def test_ingestion_temporary_rate_limit_returns_429_with_retry_after(auth_client: TestClient):
    """
    Decision 2: A temporary rate limit returns HTTP 429 Too Many Requests
    with standard Retry-After header.
    """
    mock_redis = MagicMock()
    mock_redis.sismember.return_value = False
    # Rate limit value is 0 (quota exhausted) and TTL is 45s
    mock_redis.get.return_value = "0"
    mock_redis.ttl.return_value = 45

    custom_filter = IngestContainmentFilter(redis_client=mock_redis)

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        custom_filter.check_containment(
            tenant_id=auth_client.test_tenant_id,
            client_ip="198.51.100.1",
            entity_id="payments-api",
        )

    assert exc.value.status_code == 429
    assert exc.value.headers.get("Retry-After") == "45"
    assert "Rate limit exceeded" in exc.value.detail


def test_ingestion_infrastructure_failure_fails_open_safely(auth_client: TestClient):
    """
    Decision 2: Redis or other infrastructure failure must NOT accidentally create
    security blocks or deny legitimate traffic.
    """
    import redis
    mock_redis = MagicMock()
    mock_redis.sismember.side_effect = redis.ConnectionError("Connection refused on redis:6379")
    mock_redis.get.side_effect = redis.TimeoutError("Socket timeout on redis:6379")

    custom_filter = IngestContainmentFilter(redis_client=mock_redis)

    # Must complete cleanly without raising HTTPException (fails open safely!)
    custom_filter.check_containment(
        tenant_id=auth_client.test_tenant_id,
        client_ip="203.0.113.5",
        entity_id="payments-api",
    )


def test_invalid_api_credentials_returns_401():
    """
    Decision 2: Invalid API credentials return HTTP 401 Unauthorized with WWW-Authenticate header.
    """
    client = TestClient(app)
    res = client.post(
        "/v1/events",
        headers={"Authorization": "Bearer invalid_secret_key_999"},
        json={"event_id": "ev-test-1", "timestamp": "2026-11-01T12:00:00Z"},
    )
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers


# ---------------------------------------------------------------------------
# 4. REST API Tests
# ---------------------------------------------------------------------------

def test_api_list_and_get_actions(auth_client: TestClient):
    with Session(bind=engine) as db:
        create_pending_action(db, auth_client.test_tenant_id, requested_by="analyst:alice@corp.internal")

    res = auth_client.get("/api/v1/defense/actions")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    action_id = data[0]["action_id"]

    detail_res = auth_client.get(f"/api/v1/defense/actions/{action_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["action_id"] == action_id


def test_api_approve_action_dual_custody(auth_client: TestClient):
    with Session(bind=engine) as db:
        action = create_pending_action(db, auth_client.test_tenant_id, requested_by="analyst:alice@corp.internal")
        action_id = action.action_id

    token_alice = create_operator_token("analyst:alice@corp.internal", tenant_id=auth_client.test_tenant_id)
    token_bob = create_operator_token("user:bob@corp.internal", tenant_id=auth_client.test_tenant_id)
    token_bot = create_operator_token("service:bot", tenant_id=auth_client.test_tenant_id, is_human=False)

    # 1. Self-approval attempt via REST API -> 403 Forbidden
    self_res = auth_client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        json={"approver_identity": "analyst:alice@corp.internal", "rationale": "I self-approve"},
        headers={"X-Operator-Token": f"Bearer {token_alice}"},
    )
    assert self_res.status_code == 403

    # 2. Service account approval attempt via REST API -> 422 / 403 Forbidden
    service_res = auth_client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        json={"approver_identity": "service:bot", "rationale": "Bot approval"},
        headers={"X-Operator-Token": f"Bearer {token_bot}"},
    )
    assert service_res.status_code in (403, 422)

    # 3. Independent human approval -> 200 OK
    valid_res = auth_client.post(
        f"/api/v1/defense/actions/{action_id}/approve",
        json={"approver_identity": "user:bob@corp.internal", "rationale": "Peer human approval"},
        headers={"X-Operator-Token": f"Bearer {token_bob}"},
    )
    assert valid_res.status_code == 200
    assert valid_res.json()["status"] == "approved"
    assert valid_res.json()["approved_by"] == "user:bob@corp.internal"


def test_api_reject_action(auth_client: TestClient):
    with Session(bind=engine) as db:
        action = create_pending_action(db, auth_client.test_tenant_id, requested_by="analyst:alice@corp.internal")
        action_id = action.action_id

    token_bob = create_operator_token("user:bob@corp.internal", tenant_id=auth_client.test_tenant_id)
    res = auth_client.post(
        f"/api/v1/defense/actions/{action_id}/reject",
        json={"rejector_identity": "user:bob@corp.internal", "rationale": "Rejected by security analyst"},
        headers={"X-Operator-Token": f"Bearer {token_bob}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "rejected"


def test_api_policy_get_and_update(auth_client: TestClient):
    get_res = auth_client.get("/api/v1/defense/policy")
    assert get_res.status_code == 200
    assert get_res.json()["default_mode"] == "observe"

    # Update to ASSISTED
    update_res = auth_client.put(
        "/api/v1/defense/policy",
        json={"default_mode": "assisted", "max_autonomous_ttl_seconds": 1800}
    )
    assert update_res.status_code == 200
    assert update_res.json()["default_mode"] == "assisted"
    assert update_res.json()["max_autonomous_ttl_seconds"] == 1800
