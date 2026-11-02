"""
FastAPI router for controlled synthetic scenario simulations.

Provides:
- POST /api/v1/simulation/run — Gated synthetic scenario launcher (exfiltration, brute-force, normal)
- GET /api/v1/demo/session — Development-only session bootstrap for the local console
"""

from typing import List, Optional, Literal
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
import uuid
import datetime

from backend.config import settings
from backend.db.session import get_db
from backend.core.auth import get_current_auth, AuthContext
from backend.models import EventModel, SecurityFinding, ApiKey, Tenant
from backend.schemas.events import CanonicalEvent
from backend.api.ingest import fast_detectors
from backend.detection.registry import runtime_rule_registry
from backend.ops.bus import ops_bus
from scenarios.synthetic_services import (
    ApiServiceSimulator,
    WorkerServiceSimulator,
    DatabaseServiceSimulator,
)

router = APIRouter(prefix="/api/v1", tags=["Simulation & Demo"])


class SimulationRequest(BaseModel):
    scenario: Literal["exfiltration", "brute_force", "full_suite", "normal"] = Field(
        default="exfiltration",
        description="Predefined scenario identifier. Arbitrary code or scripts are strictly rejected."
    )


class SimulationResponse(BaseModel):
    run_id: str
    scenario: str
    status: str
    trace_id: Optional[str]
    events_emitted: int
    findings_generated: int
    finding_ids: List[str]
    message: str


class DemoSessionResponse(BaseModel):
    api_key: str
    tenant_id: str
    app_id: str


class _InProcessEngineEmitter:
    """
    Internal SDK-compatible adapter that routes simulated events directly
    through the Fast Track detection pipeline and database session in-process.
    """
    def __init__(self, tenant_id: str, app_id: str, db: Session):
        self.tenant_id = tenant_id
        self.app_id = app_id
        self.db = db
        self.emitted_count = 0
        self.generated_findings: List[SecurityFinding] = []

    def emit(
        self,
        event_type: str,
        attributes: Optional[dict] = None,
        severity: str = "info",
        source_resource: Optional[str] = None,
        target_resource: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        service: Optional[str] = None,
        provenance: Optional[dict] = None,
    ):
        event_id = f"ev-sim-{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc)

        canonical = CanonicalEvent(
            event_id=event_id,
            timestamp=now,
            tenant_id=self.tenant_id,
            app_id=self.app_id,
            service_id=service or "sim-service",
            event_type=event_type,
            severity=severity,
            source_resource=source_resource,
            target_resource=target_resource,
            trace_id=trace_id,
            request_id=request_id,
            attributes=attributes or {},
            provenance=provenance or {"source": "simulation_runner"},
        )

        db_event = EventModel(
            event_id=canonical.event_id,
            schema_version=canonical.schema_version,
            timestamp=canonical.timestamp.replace(tzinfo=None),
            ingested_at=now.replace(tzinfo=None),
            tenant_id=self.tenant_id,
            app_id=self.app_id,
            service_id=canonical.service_id,
            event_type=canonical.event_type,
            severity=canonical.severity,
            source_resource=canonical.source_resource,
            target_resource=canonical.target_resource,
            trace_id=canonical.trace_id,
            request_id=canonical.request_id,
            attributes=canonical.attributes,
            provenance=canonical.provenance,
        )
        self.db.add(db_event)
        self.emitted_count += 1
        ops_bus.publish(
            component="simulation",
            event_type="ingest.event_received",
            level="info",
            message=f"[Simulation] Ingested {canonical.event_type} from {canonical.service_id}",
            tenant_id=self.tenant_id,
            service_id=canonical.service_id,
            trace_id=canonical.trace_id,
            metadata={"severity": canonical.severity.value, "target": canonical.target_resource},
        )

        # 1. Evaluate active declarative rules for this tenant
        rule_findings, covered_families, _, _ = runtime_rule_registry.evaluate_active_rules(canonical, self.db)
        for finding in rule_findings:
            db_finding = SecurityFinding(
                finding_id=finding.finding_id,
                tenant_id=self.tenant_id,
                detector_id=finding.detector_id,
                detector_version=finding.detector_version,
                title=finding.title,
                severity=finding.severity,
                confidence=finding.confidence,
                description=finding.description,
                event_id=finding.event_id,
                evidence=finding.evidence,
            )
            self.db.add(db_finding)
            self.generated_findings.append(db_finding)
            ops_bus.publish(
                component="fast-track",
                event_type="fast_track.rule_triggered",
                level="warn",
                message=f"[Simulation] Active declarative rule '{finding.detector_id}' v{finding.detector_version} fired: {finding.title}",
                tenant_id=self.tenant_id,
                finding_id=finding.finding_id,
                rule_id=finding.detector_id,
                rule_version=int(finding.detector_version) if str(finding.detector_version).isdigit() else 1,
                trace_id=canonical.trace_id,
                service_id=canonical.service_id,
                metadata={"severity": finding.severity},
            )

        # 2. Evaluate Fast Track native detectors for families not covered by active rules
        for detector in fast_detectors:
            family = getattr(detector, "detector_id", "")
            if family in covered_families:
                continue
            finding = detector.evaluate(canonical)
            if finding:
                db_finding = SecurityFinding(
                    finding_id=finding.finding_id,
                    tenant_id=self.tenant_id,
                    detector_id=finding.detector_id,
                    detector_version=finding.detector_version,
                    title=finding.title,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    description=finding.description,
                    event_id=finding.event_id,
                    evidence=finding.evidence,
                )
                self.db.add(db_finding)
                self.generated_findings.append(db_finding)
                ops_bus.publish(
                    component="fast-track",
                    event_type="finding.created",
                    level="warn",
                    message=f"[Simulation] Fast Track native detector '{finding.detector_id}' triggered: {finding.title}",
                    tenant_id=self.tenant_id,
                    finding_id=finding.finding_id,
                    trace_id=canonical.trace_id,
                    service_id=canonical.service_id,
                    metadata={"severity": finding.severity},
                )

        self.db.commit()


@router.post("/simulation/run", response_model=SimulationResponse, status_code=status.HTTP_200_OK)
async def run_simulation(
    payload: SimulationRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Triggers a controlled synthetic attack scenario.
    Security Gate: Disabled in production unless explicitly enabled.
    Reuses existing synthetic services; strictly rejects arbitrary code or shell injection.
    """
    if settings.ENVIRONMENT.lower() == "production" or (settings.ENVIRONMENT != "development" and not getattr(settings, "ALLOW_SIMULATION_API", False)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Simulation API is strictly disabled in production environments.",
        )

    run_id = f"sim-run-{uuid.uuid4().hex[:8]}"
    emitter = _InProcessEngineEmitter(tenant_id=auth.tenant_id, app_id=auth.app_id, db=db)

    api = ApiServiceSimulator(emitter)
    worker = WorkerServiceSimulator(emitter)
    db_service = DatabaseServiceSimulator(emitter)

    main_trace_id = None

    if payload.scenario == "exfiltration":
        main_trace_id = f"trace-exfil-{uuid.uuid4().hex[:8]}"
        api.handle_request(
            endpoint="/api/v1/internal/export",
            client_ip="10.0.4.15",
            method="POST",
            trace_id=main_trace_id,
        )
        worker.process_job(
            job_name="mass_export_task",
            payload_size_kb=8500,
            trace_id=main_trace_id,
            is_suspicious=True,
        )
        db_service.record_access(
            table="credit_cards",
            operation="SELECT",
            rows_affected=50000,
            trace_id=main_trace_id,
            is_bulk_exfil=True,
        )

    elif payload.scenario == "brute_force":
        attacker_ip = "203.0.113.88"
        for i in range(5):
            api.handle_login(
                username="admin",
                client_ip=attacker_ip,
                success=False,
                trace_id=f"trace-bf-{uuid.uuid4().hex[:6]}",
            )

    elif payload.scenario == "normal":
        main_trace_id = f"trace-norm-{uuid.uuid4().hex[:8]}"
        api.handle_login(username="alice", client_ip="198.51.100.12", success=True, trace_id=main_trace_id)
        api.handle_request(endpoint="/api/v1/profile", client_ip="198.51.100.12", trace_id=main_trace_id)
        worker.process_job(job_name="sync_profile_cache", payload_size_kb=4, trace_id=main_trace_id, is_suspicious=False)
        db_service.record_access(table="user_profiles", operation="SELECT", rows_affected=1, trace_id=main_trace_id, is_bulk_exfil=False)

    elif payload.scenario == "full_suite":
        # Normal flow
        norm_trace = f"trace-norm-{uuid.uuid4().hex[:8]}"
        api.handle_login(username="alice", client_ip="198.51.100.12", success=True, trace_id=norm_trace)
        api.handle_request(endpoint="/api/v1/profile", client_ip="198.51.100.12", trace_id=norm_trace)
        worker.process_job(job_name="sync_profile_cache", payload_size_kb=4, trace_id=norm_trace, is_suspicious=False)
        db_service.record_access(table="user_profiles", operation="SELECT", rows_affected=1, trace_id=norm_trace, is_bulk_exfil=False)

        # Brute force flow
        for i in range(5):
            api.handle_login(username="admin", client_ip="203.0.113.88", success=False, trace_id=f"trace-bf-{i}")

        # Exfil flow
        main_trace_id = f"trace-exfil-{uuid.uuid4().hex[:8]}"
        api.handle_request(endpoint="/api/v1/internal/export", client_ip="10.0.4.15", method="POST", trace_id=main_trace_id)
        worker.process_job(job_name="mass_export_task", payload_size_kb=8500, trace_id=main_trace_id, is_suspicious=True)
        db_service.record_access(table="credit_cards", operation="SELECT", rows_affected=50000, trace_id=main_trace_id, is_bulk_exfil=True)

    finding_ids = [f.finding_id for f in emitter.generated_findings]

    # Auto-correlate simulated findings into incident cases
    for f in emitter.generated_findings:
        try:
            from backend.incidents.correlator import IncidentCorrelator
            IncidentCorrelator(db).correlate_finding(f)
        except Exception as e:
            logger.warning("Simulation incident auto-correlation error: %s", e)

    ops_bus.publish(
        component="simulation",
        event_type="simulation.completed",
        level="success",
        message=f"Simulation '{payload.scenario}' completed: {emitter.emitted_count} events, {len(finding_ids)} findings",
        tenant_id=auth.tenant_id,
        trace_id=main_trace_id,
        metadata={"scenario": payload.scenario, "run_id": run_id, "findings_count": len(finding_ids)},
    )

    return SimulationResponse(
        run_id=run_id,
        scenario=payload.scenario,
        status="completed",
        trace_id=main_trace_id,
        events_emitted=emitter.emitted_count,
        findings_generated=len(emitter.generated_findings),
        finding_ids=finding_ids,
        message=f"Simulation '{payload.scenario}' completed. Emitted {emitter.emitted_count} events, generated {len(finding_ids)} security findings.",
    )


@router.get("/demo/session", response_model=DemoSessionResponse)
async def get_demo_session(db: Session = Depends(get_db)):
    """
    Development-only endpoint that returns credentials for the baseline development tenant.
    Allows the browser console to authenticate seamlessly during local testing.
    Strictly blocked in production and staging environments.
    """
    env = settings.ENVIRONMENT.lower()
    if env in ("production", "staging") or env != "development":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo session bootstrap is only permitted in development environments.",
        )

    # Return baseline development credentials matching actual DB state
    from backend.core.auth import hash_api_key
    raw_key = "ce_live_test_api_key_secret_12345"
    key_hash = hash_api_key(raw_key)
    api_key_rec = db.query(ApiKey).filter(ApiKey.key_hash == key_hash, ApiKey.is_active == True).first()
    tenant_id = api_key_rec.tenant_id if api_key_rec else "tenant-alpha"
    app_id = api_key_rec.app_id if api_key_rec else "payments-api"

    return DemoSessionResponse(
        api_key=raw_key,
        tenant_id=tenant_id,
        app_id=app_id,
    )

