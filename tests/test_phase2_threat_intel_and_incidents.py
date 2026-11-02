"""
Comprehensive Test Suite for Phase 2: Threat Intelligence & Incident Management.

Covers:
1. Milestone 2.1: Incident Correlation Engine:
   - Automated creation of new incident cases from SecurityFindings.
   - Merging and correlation of multi-service findings sharing trace IDs or entity IPs.
   - Dynamic composite severity escalation (medium -> critical).
   - Batch aggregation of unassigned findings.
2. Milestone 2.2: Incident Management REST APIs:
   - GET /api/v1/incidents (listing, filtering by status/severity/service).
   - GET /api/v1/incidents/{incident_id} (detail with linked findings and event timeline).
   - POST /api/v1/incidents (manual incident creation).
   - PATCH /api/v1/incidents/{incident_id} (lifecycle state transitions).
   - POST /api/v1/incidents/{incident_id}/contain (orchestrated multi-entity containment via Phase 1 ResponseExecutor).
3. Milestone 2.3: Threat Intelligence & IOC Matcher:
   - Threat intelligence IOC CRUD & deactivation.
   - Telemetry cross-reference matching against stored microservice events.
   - MITRE ATT&CK coverage matrix generation.
4. End-to-End Simulation Integration:
   - Attack simulation automatically correlates into an active multi-service Incident case.
"""

import datetime
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.core.auth import hash_api_key
from backend.db.session import engine
from backend.incidents.correlator import IncidentCorrelator
from backend.main import app
from backend.models import (
    ApiKey,
    Base,
    EventModel,
    IncidentFindingModel,
    IncidentModel,
    SecurityFinding,
    Tenant,
    ThreatIntelIocModel,
)
from backend.schemas.incidents import IncidentSeverity, IncidentStatus
from backend.schemas.threat_intel import IocSeverity, IocType


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
                app_id="phase2-test-runner",
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


def _create_finding(
    db: Session,
    tenant_id: str,
    title: str = "Suspicious Access",
    severity: str = "medium",
    detector_id: str = "detector.auth.brute_force",
    trace_id: str = None,
    client_ip: str = "198.51.100.25",
    service_id: str = "api-service",
) -> SecurityFinding:
    f_id = f"find-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    finding = SecurityFinding(
        finding_id=f_id,
        tenant_id=tenant_id,
        detector_id=detector_id,
        detector_version="1.0.0",
        title=title,
        severity=severity,
        confidence="high",
        description="Automated test finding trigger",
        evidence={
            "trace_id": trace_id or f"trace-{uuid.uuid4().hex[:6]}",
            "source_ip": client_ip,
            "service_id": service_id,
        },
        status="open",
        created_at=now,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def test_incident_correlator_creates_incident():
    """Milestone 2.1: Correlates standalone finding into a newly provisioned Incident."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"

    with Session(bind=engine) as db:
        db.add(Tenant(id=tenant_id, name="Test Tenant"))
        db.commit()

        finding = _create_finding(
            db=db,
            tenant_id=tenant_id,
            title="Credential Spray Anomaly",
            severity="high",
            client_ip="198.51.100.99",
            service_id="auth-gateway",
        )

        correlator = IncidentCorrelator(db)
        incident = correlator.correlate_finding(finding)

        assert incident.incident_id.startswith("INC-")
        assert incident.title == "Credential Spray Anomaly"
        assert incident.severity == "high"
        assert incident.status == "open"
        assert incident.primary_entity_id == "198.51.100.99"
        assert "auth-gateway" in incident.affected_services
        assert incident.finding_count == 1

        # Check junction table
        junction = (
            db.query(IncidentFindingModel)
            .filter(
                IncidentFindingModel.incident_id == incident.incident_id,
                IncidentFindingModel.finding_id == finding.finding_id,
            )
            .first()
        )
        assert junction is not None


def test_incident_correlator_merges_findings_same_trace():
    """Milestone 2.1: Correlates multiple findings on identical trace and escalates severity."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"
    shared_trace = f"trace-shared-{uuid.uuid4().hex[:6]}"

    with Session(bind=engine) as db:
        db.add(Tenant(id=tenant_id, name="Test Tenant"))
        db.commit()

        # Finding 1: Medium severity
        f1 = _create_finding(
            db=db,
            tenant_id=tenant_id,
            title="API Data Export Triggered",
            severity="medium",
            trace_id=shared_trace,
            service_id="api-service",
        )

        correlator = IncidentCorrelator(db)
        inc1 = correlator.correlate_finding(f1)
        inc_id = inc1.incident_id
        assert inc1.severity == "medium"
        assert inc1.finding_count == 1

        # Finding 2: Critical severity on same trace
        f2 = _create_finding(
            db=db,
            tenant_id=tenant_id,
            title="Unauthorized Cross-Service Exfiltration",
            severity="critical",
            detector_id="detector.exfiltration.cross_service",
            trace_id=shared_trace,
            service_id="database-service",
        )

        inc2 = correlator.correlate_finding(f2)
        assert inc2.incident_id == inc_id  # Same incident!
        assert inc2.severity == "critical"  # Escalated!
        assert inc2.finding_count == 2
        assert "api-service" in inc2.affected_services
        assert "database-service" in inc2.affected_services
        assert "T1048" in inc2.mitre_techniques


def test_incident_correlator_aggregates_unassigned():
    """Milestone 2.1: Scans unassigned findings and groups them."""
    tenant_id = f"tenant-{uuid.uuid4().hex[:6]}"

    with Session(bind=engine) as db:
        db.add(Tenant(id=tenant_id, name="Test Tenant"))
        db.commit()

        # 3 findings: two on trace-A (ip 198.51.100.25), one on trace-B (ip 198.51.100.99)
        t_a = f"trace-a-{uuid.uuid4().hex[:4]}"
        t_b = f"trace-b-{uuid.uuid4().hex[:4]}"

        _create_finding(db, tenant_id, "Finding A1", trace_id=t_a, client_ip="198.51.100.25")
        _create_finding(db, tenant_id, "Finding A2", trace_id=t_a, client_ip="198.51.100.25")
        _create_finding(db, tenant_id, "Finding B1", trace_id=t_b, client_ip="198.51.100.99")

        correlator = IncidentCorrelator(db)
        incidents = correlator.aggregate_unassigned_findings(tenant_id)
        assert len(incidents) == 2


def test_list_and_get_incidents_api(auth_client):
    """Milestone 2.2: REST API GET /api/v1/incidents and GET /api/v1/incidents/{id}."""
    client = auth_client
    tenant_id = client.test_tenant_id

    with Session(bind=engine) as db:
        f = _create_finding(db, tenant_id, "API Incident Target", service_id="worker-service")
        correlator = IncidentCorrelator(db)
        inc = correlator.correlate_finding(f)
        inc_id = inc.incident_id

    # 1. List
    res = client.get("/api/v1/incidents")
    assert res.status_code == 200
    items = res.json()
    assert any(i["incident_id"] == inc_id for i in items)

    # 2. Detail
    res_det = client.get(f"/api/v1/incidents/{inc_id}")
    assert res_det.status_code == 200
    det = res_det.json()
    assert det["incident_id"] == inc_id
    assert len(det["findings"]) == 1
    assert det["findings"][0]["finding_id"] == f.finding_id


def test_create_and_update_incident_api(auth_client):
    """Milestone 2.2: REST API POST & PATCH /api/v1/incidents."""
    client = auth_client

    # Create manual incident
    create_payload = {
        "title": "Investigating Anomalous DB Traffic",
        "summary": "Manual incident opened by SOC analyst",
        "severity": "high",
        "primary_entity_type": "service",
        "primary_entity_id": "payments-db",
    }
    res = client.post("/api/v1/incidents", json=create_payload)
    assert res.status_code == 201
    inc = res.json()
    inc_id = inc["incident_id"]
    assert inc["title"] == "Investigating Anomalous DB Traffic"
    assert inc["status"] == "open"

    # Update incident to resolved
    patch_payload = {
        "status": "resolved",
        "summary": "Resolved after rotation of worker credentials",
    }
    res_patch = client.patch(f"/api/v1/incidents/{inc_id}", json=patch_payload)
    assert res_patch.status_code == 200
    updated = res_patch.json()
    assert updated["status"] == "resolved"
    assert updated["resolved_at"] is not None


def test_contain_incident_api(auth_client):
    """Milestone 2.2: Coordinated multi-entity containment via POST /api/v1/incidents/{id}/contain."""
    client = auth_client
    tenant_id = client.test_tenant_id
    attacker_ip = "198.51.100.77"

    with Session(bind=engine) as db:
        f = _create_finding(
            db=db,
            tenant_id=tenant_id,
            title="Brute Force Velocity Breach",
            client_ip=attacker_ip,
        )
        correlator = IncidentCorrelator(db)
        inc = correlator.correlate_finding(f)
        inc_id = inc.incident_id

    contain_payload = {
        "rationale": "Immediate containment of attacker IP during active credential stuffing",
        "contain_ips": True,
        "contain_credentials": True,
    }
    res = client.post(f"/api/v1/incidents/{inc_id}/contain", json=contain_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id
    assert data["status"] == "contained"
    assert data["contained_entities_count"] >= 1
    assert any(a["target"] == attacker_ip for a in data["actions_triggered"])


def test_threat_intel_ioc_crud(auth_client):
    """Milestone 2.3: Threat intelligence IOC registration, listing, retrieval, and deactivation."""
    client = auth_client

    # 1. Create IOC
    ioc_payload = {
        "ioc_type": "ip",
        "value": "203.0.113.199",
        "threat_actor": "APT-SIMULATED",
        "description": "Known malicious egress node",
        "severity": "critical",
        "confidence": "high",
        "mitre_tactics": ["TA0010"],
        "mitre_techniques": ["T1048"],
        "expires_in_days": 30,
    }
    res = client.post("/api/v1/threat-intelligence", json=ioc_payload)
    assert res.status_code == 201
    ioc = res.json()
    ioc_id = ioc["ioc_id"]
    assert ioc["value"] == "203.0.113.199"
    assert ioc["is_active"] is True

    # 2. List IOCs
    res_list = client.get("/api/v1/threat-intelligence")
    assert res_list.status_code == 200
    iocs = res_list.json()
    assert any(i["ioc_id"] == ioc_id for i in iocs)

    # 3. Get single IOC
    res_get = client.get(f"/api/v1/threat-intelligence/{ioc_id}")
    assert res_get.status_code == 200
    assert res_get.json()["ioc_id"] == ioc_id

    # 4. Deactivate IOC
    res_del = client.delete(f"/api/v1/threat-intelligence/{ioc_id}")
    assert res_del.status_code == 200
    assert res_del.json()["is_active"] is False


def test_threat_intel_telemetry_match(auth_client):
    """Milestone 2.3: Cross-reference query against registered IOCs and microservice telemetry."""
    client = auth_client
    tenant_id = client.test_tenant_id
    target_ip = "198.51.100.55"

    with Session(bind=engine) as db:
        # Register IOC
        db.add(
            ThreatIntelIocModel(
                ioc_id=f"ioc-{uuid.uuid4().hex[:8]}",
                tenant_id=tenant_id,
                ioc_type="ip",
                value=target_ip,
                threat_actor="Malicious Botnet",
                severity="high",
                confidence="high",
                mitre_techniques=["T1110"],
                is_active=True,
                source="test",
                created_at=datetime.datetime.now(datetime.timezone.utc),
                updated_at=datetime.datetime.now(datetime.timezone.utc),
            )
        )
        # Record telemetry event
        db.add(
            EventModel(
                event_id=f"ev-{uuid.uuid4().hex[:8]}",
                tenant_id=tenant_id,
                app_id="payments-app",
                trace_id=f"trace-{uuid.uuid4().hex[:6]}",
                service_id="payment-gateway",
                event_type="auth.login_attempt",
                severity="info",
                source_resource=target_ip,
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                attributes={"ip": target_ip, "user_agent": "curl/7.68.0"},
            )
        )
        db.commit()

    match_payload = {
        "query": target_ip,
        "time_window_hours": 24,
    }
    res = client.post("/api/v1/threat-intelligence/match", json=match_payload)
    assert res.status_code == 200
    result = res.json()
    assert len(result["matched_iocs"]) >= 1
    assert result["matched_events_count"] >= 1
    assert "payment-gateway" in result["affected_services"]
    assert "T1110" in result["mitre_techniques"]


def test_mitre_coverage_matrix(auth_client):
    """Milestone 2.3: Real-time MITRE ATT&CK coverage calculation."""
    client = auth_client
    res = client.get("/api/v1/threat-intelligence/mitre-coverage")
    assert res.status_code == 200
    data = res.json()
    assert data["total_techniques_covered"] >= 5
    tech_ids = [t["technique_id"] for t in data["techniques"]]
    assert "T1078" in tech_ids
    assert "T1048" in tech_ids
    assert "T1005" in tech_ids
    assert "T1110" in tech_ids


def test_simulation_auto_correlates_to_incident(auth_client):
    """Milestone 2.4: Attack simulation emits findings that automatically correlate into an active Incident."""
    client = auth_client

    # Run exfiltration scenario
    res = client.post("/api/v1/simulation/run", json={"scenario": "exfiltration"})
    assert res.status_code == 200

    # Query incidents
    res_inc = client.get("/api/v1/incidents")
    assert res_inc.status_code == 200
    incidents = res_inc.json()
    assert len(incidents) >= 1
    # Verify exfiltration incident was created and has correlated findings
    exfil_inc = next((i for i in incidents if "exfiltration" in i["title"].lower() or "T1048" in i["mitre_techniques"]), None)
    assert exfil_inc is not None
    assert exfil_inc["finding_count"] >= 1
