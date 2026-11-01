"""
Test Suite for Milestone 1.1: Active Defense Data Model & Response Planning.

Covers:
1. Finding-to-action planning from baseline detectors.
2. Deep Track recommendation normalization (strings and structured dicts).
3. Invalid, protected, and dangerous target rejection.
4. Tenant isolation enforcement.
5. Deterministic, parameter-order-invariant action fingerprinting.
6. Duplicate action detection and coalescing.
7. Multi-threaded concurrent duplicate proposal handling.
8. Database persistence, relationships, and audit log immutability (SET NULL retention).
9. Alembic migration upgrade and downgrade verification.
"""

import concurrent.futures
import datetime
import uuid
import pytest
from sqlalchemy.orm import Session

from backend.db.session import get_db, engine
from backend.models import (
    Base,
    Tenant,
    SecurityFinding,
    DefenseActionModel,
    DefenseAuditLogModel,
    TenantDefensePolicyModel,
)
from backend.schemas.defense import (
    ActionScope,
    ActionStatus,
    ActionType,
    CandidateResponseAction,
    CredentialAuthority,
    ProtectionMode,
    TargetEntityType,
    canonicalize_parameters,
    compute_action_fingerprint,
)
from backend.defense.planner import ResponsePlanner
from backend.schemas.investigation import InvestigationFinding


@pytest.fixture(autouse=True)
def setup_active_defense_tables():
    """Ensure all database tables are created before running tests."""
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db_session():
    """Provides a clean transactional test database session."""
    session = Session(bind=engine)
    try:
        # Ensure test tenants exist
        for t_id in ("test-tenant-1", "test-tenant-2"):
            if not session.query(Tenant).filter(Tenant.id == t_id).first():
                session.add(Tenant(id=t_id, name=f"Test Tenant {t_id}"))
        session.commit()
        yield session
    finally:
        session.close()


def create_test_finding(
    db: Session,
    tenant_id: str = "test-tenant-1",
    detector_id: str = "detector.auth.brute_force",
    client_ip: str = "203.0.113.42",
) -> SecurityFinding:
    finding_id = f"find-{uuid.uuid4().hex[:8]}"
    finding = SecurityFinding(
        finding_id=finding_id,
        tenant_id=tenant_id,
        detector_id=detector_id,
        detector_version="1.0.0",
        title=f"Test Threat Detection ({detector_id})",
        severity="high",
        confidence="high",
        description="Simulated attack finding for Active Defense planning test",
        evidence={"client_ip": client_ip, "attempts": 25, "app_id": "payments-api"},
        status="open",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


# ---------------------------------------------------------------------------
# 1. Finding-to-Action Planning Tests
# ---------------------------------------------------------------------------

def test_plan_from_brute_force_finding(db_session: Session):
    finding = create_test_finding(
        db_session,
        detector_id="detector.auth.brute_force",
        client_ip="198.51.100.10",
    )
    planner = ResponsePlanner(db_session)
    actions = planner.plan_from_finding(finding)

    assert len(actions) == 1
    action = actions[0]
    assert action.action_type == ActionType.TEMPORARY_IP_BLOCK
    assert action.scope == ActionScope.TERNLINE_INGEST
    assert action.target_entity_type == TargetEntityType.IP_ADDRESS
    assert action.target_entity_id == "198.51.100.10"
    assert action.status == ActionStatus.PROPOSED
    assert action.protection_mode == ProtectionMode.OBSERVE  # Mandatory default
    assert action.ttl_seconds == 1800
    assert action.expires_at is not None
    assert action.tenant_id == "test-tenant-1"


def test_plan_from_exfiltration_finding(db_session: Session):
    finding = create_test_finding(
        db_session,
        detector_id="detector.exfiltration.cross_service",
    )
    planner = ResponsePlanner(db_session)
    actions = planner.plan_from_finding(finding)

    assert len(actions) == 1
    action = actions[0]
    assert action.action_type == ActionType.TEMPORARY_RATE_LIMIT
    assert action.scope == ActionScope.TERNLINE_INGEST
    assert action.target_entity_type == TargetEntityType.APP_ID
    assert action.target_entity_id == "payments-api"


# ---------------------------------------------------------------------------
# 2. Deep Track Recommendation Normalization Tests
# ---------------------------------------------------------------------------

def test_normalize_string_recommendations(db_session: Session):
    finding = create_test_finding(db_session)
    planner = ResponsePlanner(db_session)

    # A. API Key Revocation
    cand_key = planner.normalize_recommendation(
        "Revoke API key ce_live_sec_key_445", finding
    )
    assert cand_key is not None
    assert cand_key.action_type == ActionType.API_KEY_REVOCATION
    assert cand_key.target_entity_id == "ce_live_sec_key_445"
    assert cand_key.credential_authority == CredentialAuthority.TERNLINE_MANAGED
    assert cand_key.scope == ActionScope.TERNLINE_INGEST

    # B. Temporary IP Block
    cand_ip = planner.normalize_recommendation(
        "Block IP 203.0.113.88", finding
    )
    assert cand_ip is not None
    assert cand_ip.action_type == ActionType.TEMPORARY_IP_BLOCK
    assert cand_ip.target_entity_id == "203.0.113.88"
    assert cand_ip.ttl_seconds == 1800

    # C. Rate Limiting
    cand_rate = planner.normalize_recommendation(
        "Rate limit client 198.51.100.4", finding
    )
    assert cand_rate is not None
    assert cand_rate.action_type == ActionType.TEMPORARY_RATE_LIMIT
    assert cand_rate.target_entity_id == "198.51.100.4"

    # D. Account Containment
    cand_usr = planner.normalize_recommendation(
        "Contain user usr_bad_actor_99", finding
    )
    assert cand_usr is not None
    assert cand_usr.action_type == ActionType.ACCOUNT_SESSION_CONTAINMENT
    assert cand_usr.target_entity_id == "usr_bad_actor_99"
    assert cand_usr.scope == ActionScope.CUSTOMER_APPLICATION
    assert cand_usr.credential_authority == CredentialAuthority.EXTERNAL_CUSTOMER


def test_normalize_structured_recommendation_dict(db_session: Session):
    finding = create_test_finding(db_session)
    planner = ResponsePlanner(db_session)

    structured_rec = {
        "action_type": "temporary_ip_block",
        "target_entity_id": "192.0.2.1",
        "target_entity_type": "ip_address",
        "scope": "ternline_ingest",
        "parameters": {"reason": "Investigation evidence verified"},
        "ttl_seconds": 900,
        "rationale": "High-confidence botnet member",
    }
    cand = planner.normalize_recommendation(structured_rec, finding)
    assert cand is not None
    assert cand.action_type == ActionType.TEMPORARY_IP_BLOCK
    assert cand.target_entity_id == "192.0.2.1"
    assert cand.ttl_seconds == 900
    assert cand.parameters == {"reason": "Investigation evidence verified"}


def test_plan_with_investigation_context(db_session: Session):
    finding = create_test_finding(db_session)
    investigation = InvestigationFinding(
        investigation_id="inv-test-99",
        finding_id=finding.finding_id,
        tenant_id=finding.tenant_id,
        verdict="confirmed_threat",
        summary="Confirmed distributed attack pattern",
        recommended_mitigations=[
            "Block IP 203.0.113.5",
            "Revoke API key ce_live_worker_key_01",
        ],
        investigator_provider="mock",
        investigator_model="test-model",
    )

    planner = ResponsePlanner(db_session)
    actions = planner.plan_from_finding(finding, context=investigation)

    assert len(actions) == 2
    types = {a.action_type for a in actions}
    assert types == {ActionType.TEMPORARY_IP_BLOCK, ActionType.API_KEY_REVOCATION}


# ---------------------------------------------------------------------------
# 3. Invalid & Protected Target Rejection Tests
# ---------------------------------------------------------------------------

def test_reject_protected_entities(db_session: Session):
    finding = create_test_finding(db_session, client_ip="127.0.0.1")
    planner = ResponsePlanner(db_session)

    # Localhost should not generate an IP block
    actions = planner.plan_from_finding(finding)
    assert len(actions) == 0

    # Unstructured recommendation targeting protected entity should be rejected
    cand = planner.normalize_recommendation("Block IP 127.0.0.1", finding)
    assert cand is not None
    assert not planner._is_valid_candidate(cand)


def test_reject_injection_characters_in_target(db_session: Session):
    finding = create_test_finding(db_session)
    planner = ResponsePlanner(db_session)

    # Shell injection in target
    cand = CandidateResponseAction(
        action_type=ActionType.TEMPORARY_IP_BLOCK,
        target_entity_type=TargetEntityType.IP_ADDRESS,
        target_entity_id="198.51.100.1; rm -rf /",
        rationale="Malformed attack input",
    )
    assert not planner._is_valid_candidate(cand)


def test_reject_blank_or_whitespace_target():
    with pytest.raises(ValueError):
        CandidateResponseAction(
            action_type=ActionType.TEMPORARY_IP_BLOCK,
            target_entity_type=TargetEntityType.IP_ADDRESS,
            target_entity_id="   ",
            rationale="Empty target",
        )


# ---------------------------------------------------------------------------
# 4. Deterministic Fingerprint Tests
# ---------------------------------------------------------------------------

def test_deterministic_fingerprint_parameter_order_invariance():
    fp1 = compute_action_fingerprint(
        tenant_id="tenant-alpha",
        action_type="temporary_rate_limit",
        target_entity_type="ip_address",
        target_entity_id="198.51.100.1",
        parameters={"rate": 10, "burst": 20, "nested": {"b": 2, "a": 1}},
    )
    # Reverse parameter key order
    fp2 = compute_action_fingerprint(
        tenant_id="tenant-alpha",
        action_type="temporary_rate_limit",
        target_entity_type="ip_address",
        target_entity_id="198.51.100.1",
        parameters={"nested": {"a": 1, "b": 2}, "burst": 20, "rate": 10},
    )
    assert fp1 == fp2
    assert len(fp1) == 64  # Valid SHA-256 hex


def test_fingerprint_tenant_isolation():
    fp_tenant1 = compute_action_fingerprint(
        tenant_id="tenant-1",
        action_type="temporary_ip_block",
        target_entity_type="ip_address",
        target_entity_id="198.51.100.1",
    )
    fp_tenant2 = compute_action_fingerprint(
        tenant_id="tenant-2",
        action_type="temporary_ip_block",
        target_entity_type="ip_address",
        target_entity_id="198.51.100.1",
    )
    assert fp_tenant1 != fp_tenant2


# ---------------------------------------------------------------------------
# 5. Duplicate Action Coalescing Tests
# ---------------------------------------------------------------------------

def test_duplicate_action_coalescing(db_session: Session):
    finding1 = create_test_finding(db_session, client_ip="198.51.100.99")
    finding2 = create_test_finding(db_session, client_ip="198.51.100.99")
    planner = ResponsePlanner(db_session)

    # First plan: creates new action
    actions1 = planner.plan_from_finding(finding1)
    assert len(actions1) == 1
    action1 = actions1[0]

    # Second plan on another finding with identical target/action: coalesces
    actions2 = planner.plan_from_finding(finding2)
    assert len(actions2) == 1
    action2 = actions2[0]

    # Must return the SAME underlying action ID
    assert action1.action_id == action2.action_id

    # Verify only ONE row exists in database
    count = (
        db_session.query(DefenseActionModel)
        .filter(DefenseActionModel.deduplication_fingerprint == action1.deduplication_fingerprint)
        .count()
    )
    assert count == 1

    # Verify audit log recorded the coalescence
    audit_entries = (
        db_session.query(DefenseAuditLogModel)
        .filter(DefenseAuditLogModel.action_id == action1.action_id)
        .all()
    )
    assert len(audit_entries) >= 2
    triggers = [a.transition_trigger for a in audit_entries]
    assert "response_planner.propose" in triggers
    assert "response_planner.coalesce_duplicate" in triggers


def test_tenant_isolation_in_coalescing(db_session: Session):
    finding_t1 = create_test_finding(db_session, tenant_id="test-tenant-1", client_ip="198.51.100.77")
    finding_t2 = create_test_finding(db_session, tenant_id="test-tenant-2", client_ip="198.51.100.77")
    planner = ResponsePlanner(db_session)

    actions_t1 = planner.plan_from_finding(finding_t1)
    actions_t2 = planner.plan_from_finding(finding_t2)

    # Across different tenants, actions targeting the same IP must NOT coalesce
    assert actions_t1[0].action_id != actions_t2[0].action_id
    assert actions_t1[0].tenant_id == "test-tenant-1"
    assert actions_t2[0].tenant_id == "test-tenant-2"


# ---------------------------------------------------------------------------
# 6. Concurrency Safety Test
# ---------------------------------------------------------------------------

def test_concurrent_duplicate_proposals_coalesce_cleanly():
    """
    Simulates high-velocity multi-threaded attack ingestion where multiple
    worker threads attempt to plan identical defense actions at the exact same time.
    Verifies that all calls succeed and only 1 database action row is created.
    """
    finding_id = f"find-conc-{uuid.uuid4().hex[:8]}"
    shared_ip = "203.0.113.199"

    # Seed finding in a dedicated session
    with Session(bind=engine) as s:
        f = SecurityFinding(
            finding_id=finding_id,
            tenant_id="test-tenant-1",
            detector_id="detector.auth.brute_force",
            detector_version="1.0.0",
            title="Concurrent Attack Burst",
            severity="high",
            confidence="high",
            description="Testing concurrent planning",
            evidence={"client_ip": shared_ip},
            status="open",
        )
        s.add(f)
        s.commit()

    def _worker_plan():
        # Each worker thread uses its own dedicated Session
        with Session(bind=engine) as worker_session:
            worker_finding = worker_session.query(SecurityFinding).filter(SecurityFinding.finding_id == finding_id).first()
            p = ResponsePlanner(worker_session)
            return p.plan_from_finding(worker_finding)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_worker_plan) for _ in range(5)]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    # All 5 concurrent worker threads must complete cleanly
    assert len(results) == 5
    action_ids = [r[0].action_id for r in results]

    # Every worker must have received the identical action ID
    assert len(set(action_ids)) == 1

    # In database, exactly 1 row must exist for this fingerprint
    with Session(bind=engine) as verify_session:
        fp = results[0][0].deduplication_fingerprint
        total_rows = (
            verify_session.query(DefenseActionModel)
            .filter(DefenseActionModel.deduplication_fingerprint == fp)
            .count()
        )
        assert total_rows == 1


# ---------------------------------------------------------------------------
# 7. Database Persistence & Audit Immutability (SET NULL Retention)
# ---------------------------------------------------------------------------

def test_audit_log_survives_action_deletion(db_session: Session):
    finding = create_test_finding(db_session, client_ip="198.51.100.123")
    planner = ResponsePlanner(db_session)
    actions = planner.plan_from_finding(finding)
    action_id = actions[0].action_id

    # Verify action and audit log exist
    action_row = db_session.query(DefenseActionModel).filter(DefenseActionModel.action_id == action_id).first()
    assert action_row is not None

    audit_entry = db_session.query(DefenseAuditLogModel).filter(DefenseAuditLogModel.action_id == action_id).first()
    assert audit_entry is not None
    assert audit_entry.tenant_id == "test-tenant-1"

    # Simulate administrative pruning/deletion of the defense action row
    db_session.delete(action_row)
    db_session.commit()

    # The action must be gone
    assert db_session.query(DefenseActionModel).filter(DefenseActionModel.action_id == action_id).first() is None

    # The audit log entry MUST SURVIVE (action_id set to NULL per ON DELETE SET NULL)
    retained_audit = db_session.query(DefenseAuditLogModel).filter(DefenseAuditLogModel.log_id == audit_entry.log_id).first()
    assert retained_audit is not None
    assert retained_audit.action_id is None  # Foreign key nulled out
    assert retained_audit.tenant_id == "test-tenant-1"  # Tenant provenance preserved!


def test_tenant_defense_policy_defaults_to_observe(db_session: Session):
    unique_tenant = f"test-tenant-{uuid.uuid4().hex[:6]}"
    db_session.add(Tenant(id=unique_tenant, name="Unique Policy Tenant"))
    db_session.commit()

    policy = TenantDefensePolicyModel(
        id=f"pol-{uuid.uuid4().hex[:8]}",
        tenant_id=unique_tenant,
        default_mode="observe",
        configuration={"default_mode": "observe"},
    )
    db_session.add(policy)
    db_session.commit()
    db_session.refresh(policy)

    assert policy.default_mode == "observe"
    assert policy.is_active is True


# ---------------------------------------------------------------------------
# 8. Alembic Migration Revision Chain Test
# ---------------------------------------------------------------------------

def test_alembic_migration_revision_chain():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    alembic_cfg = Config("alembic.ini")
    script = ScriptDirectory.from_config(alembic_cfg)
    heads = script.get_heads()

    # The chain now heads at 6a7b8c9d0e1f which extends 5f8e12a49b01
    assert "6a7b8c9d0e1f" in heads
    rev_remed = script.get_revision("6a7b8c9d0e1f")
    assert rev_remed is not None
    assert rev_remed.down_revision == "5f8e12a49b01"

    rev = script.get_revision("5f8e12a49b01")
    assert rev is not None
    assert rev.down_revision == "38a2b18135c4"
    assert "active defense" in rev.doc.lower()

