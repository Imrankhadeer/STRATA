"""
Reproducible Incident Evaluation Suite for CYBER ENGINE.

Defines the standard benchmark scenarios:
1. Normal API request -> legitimate background job -> database query
2. Failed-login burst from a single source
3. Suspicious API export -> unusual worker job -> bulk access to sensitive records
4. Legitimate bulk export with an approved actor and expected job metadata
5. Out-of-order, incomplete, and missing telemetry
6. Suspicious-looking sequence that has a legitimate explanation (benign lookalike)
"""

import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.schemas.events import CanonicalEvent


class EvaluationScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    tenant_id: str
    trace_id: Optional[str]
    events: List[CanonicalEvent]
    event_id_aliases: Dict[str, str] = Field(default_factory=dict)
    ground_truth_threat: bool
    expected_detector_id: Optional[str] = None
    expected_verdict: str  # "confirmed_threat" | "likely_benign" | "inconclusive"
    expected_nature: str   # "malicious" | "benign"
    mandatory_evidence_event_ids: List[str] = Field(default_factory=list)


def build_evaluation_suite(
    tenant_id: str = "tenant-alpha",
    base_time: Optional[datetime.datetime] = None,
) -> Dict[str, EvaluationScenario]:
    """
    Constructs the 6 standard reproducible evaluation scenarios with deterministic
    event IDs and explicit ground truth outcomes.
    """
    t0 = base_time or datetime.datetime(2026, 10, 28, 12, 0, 0, tzinfo=datetime.timezone.utc)
    scenarios: Dict[str, EvaluationScenario] = {}

    # --------------------------------------------------------------------------
    # Scenario 1: Normal API request followed by legitimate worker & DB access
    # --------------------------------------------------------------------------
    s1_trace = "trace-eval-s1-normal"
    s1_ev1 = CanonicalEvent(
        event_id="ev-s1-api-profile",
        timestamp=t0,
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="api-service",
        event_type="http.request",
        source_resource="198.51.100.12",
        target_resource="/api/v1/profile",
        trace_id=s1_trace,
        attributes={"method": "GET", "client_ip": "198.51.100.12", "status_code": 200},
    )
    s1_ev2 = CanonicalEvent(
        event_id="ev-s1-worker-cache",
        timestamp=t0 + datetime.timedelta(seconds=2),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="worker-service",
        event_type="worker.job_completed",
        trace_id=s1_trace,
        attributes={"job_name": "sync_profile_cache", "payload_size_kb": 4},
    )
    s1_ev3 = CanonicalEvent(
        event_id="ev-s1-db-query",
        timestamp=t0 + datetime.timedelta(seconds=4),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="database-service",
        event_type="db.query",
        trace_id=s1_trace,
        attributes={"table": "user_profiles", "rows_affected": 1, "operation": "SELECT"},
    )
    scenarios["normal_flow"] = EvaluationScenario(
        scenario_id="scenario-1-normal",
        name="Normal User Browsing & Worker Flow",
        description="Routine user profile request triggering a cache sync and single-row DB lookup.",
        tenant_id=tenant_id,
        trace_id=s1_trace,
        events=[s1_ev1, s1_ev2, s1_ev3],
        event_id_aliases={"api": s1_ev1.event_id, "worker": s1_ev2.event_id, "db": s1_ev3.event_id},
        ground_truth_threat=False,
        expected_detector_id=None,
        expected_verdict="likely_benign",
        expected_nature="benign",
        mandatory_evidence_event_ids=[],
    )

    # --------------------------------------------------------------------------
    # Scenario 2: Failed-login burst from a single source (Brute-Force)
    # --------------------------------------------------------------------------
    s2_events = []
    s2_aliases = {}
    attacker_ip = "203.0.113.88"
    for i in range(5):
        eid = f"ev-s2-login-fail-{i+1}"
        s2_aliases[f"fail_{i+1}"] = eid
        s2_events.append(
            CanonicalEvent(
                event_id=eid,
                timestamp=t0 + datetime.timedelta(seconds=i * 2),
                tenant_id=tenant_id,
                app_id="core-app",
                service_id="api-service",
                event_type="auth.login_failed",
                source_resource=attacker_ip,
                target_resource="/api/v1/auth/login",
                trace_id=f"trace-eval-s2-bf-{i}",
                attributes={"username": "admin", "client_ip": attacker_ip, "attempt": i + 1},
            )
        )
    scenarios["failed_login_burst"] = EvaluationScenario(
        scenario_id="scenario-2-brute-force",
        name="Failed-Login Burst",
        description="Five consecutive authentication failures targeting admin from a single untrusted IP.",
        tenant_id=tenant_id,
        trace_id=None,
        events=s2_events,
        event_id_aliases=s2_aliases,
        ground_truth_threat=True,
        expected_detector_id="detector.auth.failed_threshold",
        expected_verdict="confirmed_threat",
        expected_nature="malicious",
        mandatory_evidence_event_ids=[s2_events[-1].event_id],
    )

    # --------------------------------------------------------------------------
    # Scenario 3: Suspicious API export -> unusual worker job -> bulk sensitive DB
    # --------------------------------------------------------------------------
    s3_trace = "trace-eval-s3-exfil"
    s3_ev1 = CanonicalEvent(
        event_id="ev-s3-api-internal-export",
        timestamp=t0,
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="api-service",
        event_type="http.request",
        source_resource="10.0.4.15",
        target_resource="/api/v1/internal/export",
        trace_id=s3_trace,
        attributes={"method": "POST", "endpoint": "/api/v1/internal/export", "client_ip": "10.0.4.15"},
    )
    s3_ev2 = CanonicalEvent(
        event_id="ev-s3-worker-anomaly",
        timestamp=t0 + datetime.timedelta(seconds=5),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="worker-service",
        event_type="worker.job_anomalous",
        trace_id=s3_trace,
        attributes={"job_name": "mass_export_task", "payload_size_kb": 8500, "anomaly_flag": True},
    )
    s3_ev3 = CanonicalEvent(
        event_id="ev-s3-db-bulk-exfil",
        timestamp=t0 + datetime.timedelta(seconds=12),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="database-service",
        event_type="db.bulk_query",
        trace_id=s3_trace,
        attributes={"table": "credit_cards", "rows_affected": 50000, "is_sensitive_table": True},
    )
    scenarios["cross_service_exfiltration"] = EvaluationScenario(
        scenario_id="scenario-3-exfil",
        name="Suspicious Multi-Service Exfiltration",
        description="Coordinated sequence: internal API export endpoint -> anomalous worker task -> bulk dump of credit_cards.",
        tenant_id=tenant_id,
        trace_id=s3_trace,
        events=[s3_ev1, s3_ev2, s3_ev3],
        event_id_aliases={"api": s3_ev1.event_id, "worker": s3_ev2.event_id, "db": s3_ev3.event_id},
        ground_truth_threat=True,
        expected_detector_id="detector.cross_service.exfiltration",
        expected_verdict="confirmed_threat",
        expected_nature="malicious",
        mandatory_evidence_event_ids=[s3_ev1.event_id, s3_ev2.event_id, s3_ev3.event_id],
    )

    # --------------------------------------------------------------------------
    # Scenario 4: Legitimate bulk export with approved actor & expected metadata
    # --------------------------------------------------------------------------
    s4_trace = "trace-eval-s4-legit-export"
    s4_ev1 = CanonicalEvent(
        event_id="ev-s4-api-scheduled-backup",
        timestamp=t0,
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="api-service",
        event_type="http.request",
        source_resource="sa-compliance-nightly",
        target_resource="/api/v1/internal/export",
        trace_id=s4_trace,
        attributes={
            "method": "POST",
            "actor": "sa-compliance-nightly",
            "is_scheduled_task": True,
            "job_id": "cron-compliance-001",
        },
    )
    s4_ev2 = CanonicalEvent(
        event_id="ev-s4-worker-maintenance",
        timestamp=t0 + datetime.timedelta(seconds=10),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="worker-service",
        event_type="worker.job_anomalous",  # Large payload size triggers anomalous flag on worker
        trace_id=s4_trace,
        attributes={"job_name": "scheduled_compliance_backup", "payload_size_kb": 25000, "anomaly_flag": True},
    )
    s4_ev3 = CanonicalEvent(
        event_id="ev-s4-db-backup-query",
        timestamp=t0 + datetime.timedelta(seconds=20),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="database-service",
        event_type="db.bulk_query",
        trace_id=s4_trace,
        attributes={"table": "audit_archives", "rows_affected": 80000, "is_sensitive_table": False},
    )
    scenarios["legitimate_bulk_export"] = EvaluationScenario(
        scenario_id="scenario-4-legitimate-backup",
        name="Legitimate Bulk Compliance Export",
        description="Approved service account performing scheduled compliance backup on non-sensitive archive table.",
        tenant_id=tenant_id,
        trace_id=s4_trace,
        events=[s4_ev1, s4_ev2, s4_ev3],
        event_id_aliases={"api": s4_ev1.event_id, "worker": s4_ev2.event_id, "db": s4_ev3.event_id},
        ground_truth_threat=False,
        expected_detector_id=None,
        expected_verdict="likely_benign",
        expected_nature="benign",
        mandatory_evidence_event_ids=[],
    )

    # --------------------------------------------------------------------------
    # Scenario 5: Out-of-order, incomplete, and missing telemetry
    # --------------------------------------------------------------------------
    s5_trace = "trace-eval-s5-incomplete"
    # Worker and DB events arrive, but the initial API trigger event is missing (dropped by network)
    s5_ev1 = CanonicalEvent(
        event_id="ev-s5-worker-orphan",
        timestamp=t0 + datetime.timedelta(seconds=5),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="worker-service",
        event_type="worker.job_anomalous",
        trace_id=s5_trace,
        attributes={"job_name": "isolated_task", "anomaly_flag": True},
    )
    s5_ev2 = CanonicalEvent(
        event_id="ev-s5-db-bulk",
        timestamp=t0 + datetime.timedelta(seconds=15),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="database-service",
        event_type="db.bulk_query",
        trace_id=s5_trace,
        attributes={"table": "users", "rows_affected": 2000, "is_sensitive_table": True},
    )
    scenarios["incomplete_telemetry"] = EvaluationScenario(
        scenario_id="scenario-5-incomplete",
        name="Incomplete Telemetry Sequence",
        description="Worker and DB stages arrive but the triggering API request is missing entirely.",
        tenant_id=tenant_id,
        trace_id=s5_trace,
        events=[s5_ev1, s5_ev2],
        event_id_aliases={"worker": s5_ev1.event_id, "db": s5_ev2.event_id},
        ground_truth_threat=False,  # Single-service anomalies require multi-stage proof for cross-service exfil
        expected_detector_id=None,
        expected_verdict="inconclusive",
        expected_nature="benign",
        mandatory_evidence_event_ids=[],
    )

    # --------------------------------------------------------------------------
    # Scenario 6: Suspicious-looking sequence that has a legitimate explanation
    # --------------------------------------------------------------------------
    s6_trace = "trace-eval-s6-lookalike"
    # User downloads a legitimate monthly transaction statement PDF via public endpoint
    s6_ev1 = CanonicalEvent(
        event_id="ev-s6-api-monthly-statement",
        timestamp=t0,
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="api-service",
        event_type="http.request",
        source_resource="203.0.113.45",
        target_resource="/api/v1/reports/monthly_statement",  # Public user report, not /internal/
        trace_id=s6_trace,
        attributes={"method": "GET", "endpoint": "/api/v1/reports/monthly_statement", "client_ip": "203.0.113.45"},
    )
    s6_ev2 = CanonicalEvent(
        event_id="ev-s6-worker-pdf",
        timestamp=t0 + datetime.timedelta(seconds=3),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="worker-service",
        event_type="worker.job_completed",
        trace_id=s6_trace,
        attributes={"job_name": "generate_statement_pdf", "payload_size_kb": 1200, "anomaly_flag": False},
    )
    s6_ev3 = CanonicalEvent(
        event_id="ev-s6-db-statement-items",
        timestamp=t0 + datetime.timedelta(seconds=7),
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="database-service",
        event_type="db.bulk_query",
        trace_id=s6_trace,
        attributes={"table": "statement_line_items", "rows_affected": 1500, "is_sensitive_table": False},
    )
    scenarios["suspicious_lookalike"] = EvaluationScenario(
        scenario_id="scenario-6-lookalike",
        name="Benign Lookalike (User Monthly Statement)",
        description="Public PDF statement request with 1,500 line items on statement_line_items table. Lookalike to exfil but benign.",
        tenant_id=tenant_id,
        trace_id=s6_trace,
        events=[s6_ev1, s6_ev2, s6_ev3],
        event_id_aliases={"api": s6_ev1.event_id, "worker": s6_ev2.event_id, "db": s6_ev3.event_id},
        ground_truth_threat=False,
        expected_detector_id=None,
        expected_verdict="likely_benign",
        expected_nature="benign",
        mandatory_evidence_event_ids=[],
    )

    return scenarios
