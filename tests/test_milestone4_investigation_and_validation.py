"""
Comprehensive Test Suite for CYBER ENGINE Milestone 4:
Live Investigation and Detector Validation.

Covers:
1. Official Meta API model verification and sensitive data sanitization.
2. Six-scenario reproducible incident evaluation suite.
3. Investigation quality auditing (hallucination detection, citation fidelity, fact vs hypothesis separation).
4. Declarative rule format validation (strict rejection of executable expressions/code).
5. Replay validation engine (TP, FP, TN, FN, precision, recall, F1, zero-FP promotion gate).
6. Human/policy approval gating and activation into Fast Track registry.
7. REST API endpoints and tenant boundary isolation.
8. Opt-in live Meta Model API test (skipped unless credentials are explicitly provided in environment).
"""

import pytest
import os
import json
from unittest.mock import patch, MagicMock, AsyncMock
from pydantic import ValidationError

from tests.conftest import TEST_APP_ID, RAW_TEST_API_KEY, TEST_TENANT_ID
from backend.models import Tenant, ApiKey, DeclarativeRuleModel
from backend.core.auth import hash_api_key
from backend.investigation.meta_verifier import (
    is_genuine_meta_model,
    sanitize_sensitive_data,
    bound_investigation_timeline,
    OFFICIAL_META_MODELS,
)
from backend.investigation.evaluation_suite import (
    build_evaluation_suite,
    EvaluationScenario,
)
from backend.investigation.quality import (
    InvestigationQualityAuditor,
    QualityAuditReport,
)
from backend.investigation.adapters import (
    MockInvestigator,
    MetaModelInvestigator,
)
from backend.schemas.investigation import (
    InvestigationContext,
    InvestigationFinding,
    Hypothesis,
    EvidenceCitation,
    CandidateDetectorRule,
)
from backend.schemas.rules import (
    DeclarativeRule,
    CrossServiceRuleParameters,
    BruteForceRuleParameters,
    ReplayValidationMetrics,
)
from backend.detection.replay import ReplayValidationEngine


# ==============================================================================
# 1. Meta Model Verification and Safeguards
# ==============================================================================

def test_genuine_meta_model_verification():
    # Recognized official Meta models
    assert is_genuine_meta_model("Llama-3.3-70B-Instruct") is True
    assert is_genuine_meta_model("meta-llama/Llama-3.3-70B-Instruct") is True
    assert is_genuine_meta_model("Llama-3.1-405B-Instruct") is True
    assert is_genuine_meta_model("Llama-3.2-3B-Instruct") is True
    assert is_genuine_meta_model("Llama-Guard-3-8B") is True

    # Generic or competitor models MUST be rejected as non-Meta
    assert is_genuine_meta_model("gpt-4o") is False
    assert is_genuine_meta_model("claude-3-5-sonnet") is False
    assert is_genuine_meta_model("mistral-7b") is False
    assert is_genuine_meta_model("") is False


def test_sensitive_data_sanitization():
    payload = {
        "event_id": "ev-100",
        "client_ip": "192.168.1.1",
        "api_key": "ce_live_super_secret_key_12345",
        "nested": {
            "token": "bearer_jwt_token_abcdef",
            "password": "plaintext_password_here",
            "normal_field": "public_data",
        },
        "attributes": [
            {"authorization": "Bearer secret"},
            {"safe_attribute": 42},
        ],
    }

    sanitized = sanitize_sensitive_data(payload)
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["normal_field"] == "public_data"
    assert sanitized["attributes"][0]["authorization"] == "[REDACTED]"
    assert sanitized["attributes"][1]["safe_attribute"] == 42


def test_context_timeline_bounding():
    # Generate 80 synthetic events
    many_events = [{"event_id": f"ev-{i}"} for i in range(80)]
    bounded = bound_investigation_timeline(many_events, max_events=50)

    assert len(bounded) == 50
    # Early signal preserved
    assert bounded[0]["event_id"] == "ev-0"
    assert bounded[9]["event_id"] == "ev-9"
    # Recent escalation preserved
    assert bounded[-1]["event_id"] == "ev-79"


# ==============================================================================
# 2. Reproducible Incident Evaluation Suite
# ==============================================================================

def test_evaluation_suite_completeness():
    suite = build_evaluation_suite(tenant_id=TEST_TENANT_ID)

    required_scenarios = [
        "normal_flow",
        "failed_login_burst",
        "cross_service_exfiltration",
        "legitimate_bulk_export",
        "incomplete_telemetry",
        "suspicious_lookalike",
    ]

    for key in required_scenarios:
        assert key in suite, f"Missing required scenario: {key}"
        sc = suite[key]
        assert len(sc.events) >= 2
        assert sc.expected_verdict in ("confirmed_threat", "likely_benign", "inconclusive")
        assert sc.expected_nature in ("malicious", "benign")

    # Verify ground truth expectations
    assert suite["normal_flow"].ground_truth_threat is False
    assert suite["failed_login_burst"].ground_truth_threat is True
    assert suite["cross_service_exfiltration"].ground_truth_threat is True
    assert suite["legitimate_bulk_export"].ground_truth_threat is False
    assert suite["incomplete_telemetry"].ground_truth_threat is False
    assert suite["suspicious_lookalike"].ground_truth_threat is False


# ==============================================================================
# 3. Investigation Quality Auditing (Hallucination & Fidelity Checks)
# ==============================================================================

@pytest.mark.asyncio
async def test_quality_auditor_passes_on_grounded_report():
    suite = build_evaluation_suite()
    sc = suite["cross_service_exfiltration"]

    context = InvestigationContext(
        finding_id="finding-test-001",
        tenant_id=sc.tenant_id,
        trace_id=sc.trace_id,
        finding_title="Suspicious Multi-Service Exfiltration",
        finding_severity="high",
        finding_evidence={},
        timeline_events=[
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "service_id": e.service_id,
                "event_type": e.event_type,
                "source_resource": e.source_resource,
                "target_resource": e.target_resource,
                "attributes": e.attributes,
            }
            for e in sc.events
        ],
        actors=["10.0.4.15"],
        services=["api-service", "worker-service", "database-service"],
    )

    investigator = MockInvestigator()
    report = await investigator.investigate(context)

    auditor = InvestigationQualityAuditor()
    audit_report = auditor.audit(context, report)

    assert audit_report.overall_passed is True
    assert len(audit_report.hallucinated_event_ids) == 0
    assert len(audit_report.citation_fidelity_errors) == 0
    assert audit_report.score_percentage >= 85.0


def test_quality_auditor_detects_hallucinated_citations():
    context = InvestigationContext(
        finding_id="finding-test-hallucination",
        tenant_id="tenant-alpha",
        trace_id="trace-123",
        finding_title="Test Incident",
        finding_severity="medium",
        finding_evidence={},
        timeline_events=[
            {"event_id": "ev-real-001", "service_id": "api-service", "timestamp": "2026-10-28T12:00:00Z"},
        ],
        actors=["actor-1"],
        services=["api-service"],
    )

    hallucinated_report = InvestigationFinding(
        finding_id=context.finding_id,
        tenant_id=context.tenant_id,
        verdict="confirmed_threat",
        summary="Attacker dumped database via fabricated event IDs.",
        hypotheses=[
            Hypothesis(
                title="Fabricated Exfil",
                description="Attacker compromised worker and database.",
                likelihood="high",
                nature="malicious",
                supporting_evidence=[
                    EvidenceCitation(
                        event_id="ev-real-001",
                        service_id="api-service",
                        timestamp="2026-10-28T12:00:00Z",
                        relevance="Valid event",
                    ),
                    EvidenceCitation(
                        event_id="ev-FABRICATED-999",  # Hallucinated ID
                        service_id="database-service",
                        timestamp="2026-10-28T12:00:05Z",
                        relevance="Does not exist in telemetry context",
                    ),
                ],
            ),
            Hypothesis(
                title="Benign Alternative",
                description="Potential maintenance",
                likelihood="low",
                nature="benign",
            ),
        ],
        candidate_rules=[],
        recommended_mitigations=["Investigate"],
        investigator_provider="meta",
        investigator_model="Llama-3.3-70B-Instruct",
    )

    auditor = InvestigationQualityAuditor()
    audit_report = auditor.audit(context, hallucinated_report)

    # Must FAIL hallucination check
    assert audit_report.overall_passed is False
    assert "ev-FABRICATED-999" in audit_report.hallucinated_event_ids


def test_quality_auditor_detects_service_attribution_mismatch():
    context = InvestigationContext(
        finding_id="finding-test-fidelity",
        tenant_id="tenant-alpha",
        trace_id="trace-123",
        finding_title="Test Incident",
        finding_severity="medium",
        finding_evidence={},
        timeline_events=[
            {"event_id": "ev-real-001", "service_id": "api-service", "timestamp": "2026-10-28T12:00:00Z"},
        ],
        actors=["actor-1"],
        services=["api-service"],
    )

    mismatched_report = InvestigationFinding(
        finding_id=context.finding_id,
        tenant_id=context.tenant_id,
        verdict="confirmed_threat",
        summary="Incident summary",
        hypotheses=[
            Hypothesis(
                title="Mismatched service hypothesis",
                description="Description",
                likelihood="high",
                nature="malicious",
                supporting_evidence=[
                    EvidenceCitation(
                        event_id="ev-real-001",
                        service_id="database-service",  # Wrong service! (real is api-service)
                        timestamp="2026-10-28T12:00:00Z",
                        relevance="Testing attribution error",
                    ),
                ],
            ),
            Hypothesis(title="Benign alt", description="Alt", likelihood="low", nature="benign"),
        ],
        candidate_rules=[],
        recommended_mitigations=["Action"],
        investigator_provider="meta",
        investigator_model="Llama-3.3-70B-Instruct",
    )

    auditor = InvestigationQualityAuditor()
    audit_report = auditor.audit(context, mismatched_report)
    assert audit_report.overall_passed is False
    assert len(audit_report.citation_fidelity_errors) > 0


# ==============================================================================
# 4. Declarative Rule Rejection of Executable Code
# ==============================================================================

def test_declarative_rule_rejects_executable_expressions():
    malicious_inputs = [
        {"time_window_seconds": 300, "sensitive_tables": ["users; DROP TABLE users;--"]},
        {"time_window_seconds": 300, "sensitive_tables": ["__import__('os').system('ls')"]},
        {"time_window_seconds": 300, "internal_prefixes": ["eval('2+2')"]},
        {"time_window_seconds": 300, "sensitive_tables": ["<script>alert(1)</script>"]},
        {"time_window_seconds": 300, "sensitive_tables": ["SELECT * FROM secrets UNION ALL"]},
    ]

    for bad_params in malicious_inputs:
        with pytest.raises((ValueError, ValidationError)):
            DeclarativeRule(
                tenant_id="tenant-alpha",
                target_detector="detector.cross_service.exfiltration",
                title="Injected Rule",
                description="Attempting code injection",
                parameters=bad_params,
            )


def test_declarative_rule_valid_parameters():
    valid_rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.cross_service.exfiltration",
        title="Tightened Exfiltration Rule",
        description="Lowers row threshold to 5000",
        parameters={
            "time_window_seconds": 180.0,
            "bulk_row_threshold": 5000,
            "sensitive_tables": ["users", "credit_cards", "secrets"],
            "internal_prefixes": ["/api/v1/internal/", "/admin/export"],
        },
    )
    assert valid_rule.status == "proposed"
    assert valid_rule.parameters["bulk_row_threshold"] == 5000


# ==============================================================================
# 5. Replay Validation Engine & Promotion Gating
# ==============================================================================

def test_replay_validation_candidate_passes_with_zero_fp():
    engine = ReplayValidationEngine()

    candidate_rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.cross_service.exfiltration",
        title="Production Exfiltration Detector v1",
        description="Evaluates cross-service exfiltration on standard thresholds",
        parameters={
            "time_window_seconds": 300.0,
            "bulk_row_threshold": 1000,
            "sensitive_tables": ["credit_cards", "users", "secrets"],
            "internal_prefixes": ["/api/v1/internal/", "/internal/"],
        },
    )

    metrics = engine.validate_rule(candidate_rule)

    assert metrics.false_positives == 0, "No false positives allowed"
    assert metrics.true_positives >= 1, "Must detect the true exfiltration attack"
    assert metrics.recall >= 1.0
    assert metrics.passed_validation is True
    assert candidate_rule.status == "validated"


def test_replay_validation_overly_broad_candidate_fails_on_benign_lookalike():
    engine = ReplayValidationEngine()

    # An overly broad candidate rule that classifies non-sensitive audit archives as sensitive
    # -> will trigger a False Positive on Scenario 4 (Legitimate compliance backup export)!
    overly_broad_rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.cross_service.exfiltration",
        title="Broken Overly Sensitive Rule",
        description="Fails because it flags legitimate compliance backups",
        parameters={
            "time_window_seconds": 600.0,
            "bulk_row_threshold": 1000,
            "sensitive_tables": ["audit_archives", "credit_cards"],  # audit_archives is benign backup!
            "internal_prefixes": ["/api/v1/internal/"],
        },
    )

    metrics = engine.validate_rule(overly_broad_rule)

    # Must fail validation due to False Positive on Scenario 4
    assert metrics.false_positives > 0
    assert metrics.passed_validation is False
    assert overly_broad_rule.status == "rejected"
    assert any("backup" in reason.lower() or "false positive" in reason.lower() for reason in metrics.failure_reasons)


# ==============================================================================
# 6. Human / Policy Approval Gating and Activation
# ==============================================================================

def test_approval_gate_enforces_validation_precondition():
    engine = ReplayValidationEngine()

    unvalidated_rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.cross_service.exfiltration",
        title="Unvalidated Proposal",
        description="Directly attempting approval",
        parameters={"time_window_seconds": 120.0, "bulk_row_threshold": 2000},
        status="proposed",
    )

    # Attempting to approve an unvalidated rule MUST be rejected
    with pytest.raises(ValueError, match="cannot be approved because its current status is 'proposed'"):
        engine.approve_candidate_rule(
            rule=unvalidated_rule,
            decided_by="admin-user",
            rationale="Trying to bypass validation",
        )

    # Attempting to activate an unapproved rule MUST be rejected
    with pytest.raises(ValueError, match="cannot be activated because its status is 'proposed'"):
        engine.activate_rule(unvalidated_rule)


def test_rule_lifecycle_from_proposal_to_active():
    engine = ReplayValidationEngine()

    rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.cross_service.exfiltration",
        title="Compliant Detector Rule",
        description="Valid detector rule",
        parameters={
            "time_window_seconds": 300.0,
            "bulk_row_threshold": 1000,
            "sensitive_tables": ["credit_cards"],
            "internal_prefixes": ["/api/v1/internal/"],
        },
    )
    assert rule.status == "proposed"

    # Step 1: Replay validation passes
    metrics = engine.validate_rule(rule)
    assert metrics.passed_validation is True
    assert rule.status == "validated"

    # Step 2: Human approval
    approved_rule = engine.approve_candidate_rule(
        rule=rule,
        decided_by="security-lead@company.com",
        rationale="Passed automated validation with 0 FP across all test suites.",
        decision="approved",
    )
    assert approved_rule.status == "approved"
    assert approved_rule.approval.decided_by == "security-lead@company.com"

    # Step 3: Activation into Fast Track
    active_rule = engine.activate_rule(approved_rule)
    assert active_rule.status == "active"


# ==============================================================================
# 7. REST API Endpoints & Tenant Isolation for Rules
# ==============================================================================

def test_rules_api_lifecycle_and_tenant_isolation(client, auth_headers, db_session):
    # 1. Propose candidate rule via API
    propose_payload = {
        "target_detector": "detector.cross_service.exfiltration",
        "title": "API Proposed Rule",
        "description": "Rule proposed via REST API",
        "parameters": {
            "time_window_seconds": 300.0,
            "bulk_row_threshold": 1000,
            "sensitive_tables": ["credit_cards", "tokens"],
            "internal_prefixes": ["/api/v1/internal/"],
        },
    }

    create_res = client.post("/api/v1/rules", json=propose_payload, headers=auth_headers)
    assert create_res.status_code == 201
    rule_data = create_res.json()
    rule_id = rule_data["rule_id"]
    assert rule_data["status"] == "proposed"

    # 2. Run Replay Validation via API
    val_res = client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    assert val_res.status_code == 200
    metrics = val_res.json()
    assert metrics["passed_validation"] is True
    assert metrics["false_positives"] == 0

    # 3. Approve Rule via API
    approval_payload = {
        "decision": "approved",
        "rationale": "Verified in sandbox replay suite.",
    }
    appr_res = client.post(f"/api/v1/rules/{rule_id}/approve", json=approval_payload, headers=auth_headers)
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "approved"

    # 4. Activate Rule via API
    act_res = client.post(f"/api/v1/rules/{rule_id}/activate", headers=auth_headers)
    assert act_res.status_code == 200
    assert act_res.json()["status"] == "active"

    # 5. Tenant Boundary Isolation Check
    tenant_beta = Tenant(id="tenant-beta-rules", name="Beta Rules Tenant", is_active=True)
    db_session.add(tenant_beta)
    raw_beta_key = "ce_live_beta_rules_secret_9999"
    api_key_beta = ApiKey(
        id="key-beta-rules-001",
        tenant_id="tenant-beta-rules",
        app_id="beta-app",
        key_hash=hash_api_key(raw_beta_key),
        key_prefix="ce_live_",
        is_active=True,
    )
    db_session.add(api_key_beta)
    db_session.commit()

    beta_headers = {"Authorization": f"Bearer {raw_beta_key}"}

    # Tenant Beta cannot access Tenant Alpha's rule -> 403 Forbidden
    cross_res = client.get(f"/api/v1/rules/{rule_id}", headers=beta_headers)
    assert cross_res.status_code == 403

    # Tenant Beta listing only sees their own rules
    list_res = client.get("/api/v1/rules", headers=beta_headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) == 0


# ==============================================================================
# 8. Opt-In Real Meta Model Inference Test
# ==============================================================================

from backend.config import settings


@pytest.mark.skipif(
    not (os.getenv("INVESTIGATOR_API_KEY") or settings.INVESTIGATOR_API_KEY)
    or (os.getenv("INVESTIGATOR_PROVIDER", settings.INVESTIGATOR_PROVIDER) != "meta"),
    reason="Live Meta API test is opt-in and requires INVESTIGATOR_API_KEY and INVESTIGATOR_PROVIDER=meta in environment",
)
@pytest.mark.asyncio
async def test_live_meta_model_inference():
    """
    Opt-in live inference test against the real Meta Model API endpoint.
    Executed only when real credentials are configured in the environment.
    """
    api_key = os.getenv("INVESTIGATOR_API_KEY") or settings.INVESTIGATOR_API_KEY
    base_url = os.getenv("INVESTIGATOR_BASE_URL") or settings.INVESTIGATOR_BASE_URL or "https://api.meta.ai/v1"
    model = os.getenv("INVESTIGATOR_MODEL") or settings.INVESTIGATOR_MODEL or "muse-spark-1.3"

    investigator = MetaModelInvestigator(
        api_key=api_key,
        base_url=base_url,
        model=model,
        timeout=45.0,
    )

    suite = build_evaluation_suite()
    sc = suite["cross_service_exfiltration"]

    context = InvestigationContext(
        finding_id="live-finding-eval-001",
        tenant_id=sc.tenant_id,
        trace_id=sc.trace_id,
        finding_title="Suspicious Multi-Service Exfiltration",
        finding_severity="high",
        finding_evidence={},
        timeline_events=[
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "service_id": e.service_id,
                "event_type": e.event_type,
                "source_resource": e.source_resource,
                "target_resource": e.target_resource,
                "attributes": e.attributes,
            }
            for e in sc.events
        ],
        actors=["10.0.4.15"],
        services=["api-service", "worker-service", "database-service"],
    )

    report = await investigator.investigate(context)

    assert report.investigator_provider == "meta"
    assert report.verdict in ("confirmed_threat", "likely_benign", "inconclusive")
    assert len(report.hypotheses) >= 1

    # Audit the real model's output for hallucinations
    auditor = InvestigationQualityAuditor()
    audit_report = auditor.audit(context, report)
    assert audit_report.overall_passed is True
    assert len(audit_report.hallucinated_event_ids) == 0
