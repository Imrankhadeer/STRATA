from tests.conftest import TEST_APP_ID, RAW_TEST_API_KEY
from cyber_engine import CyberEngine
from scenarios.synthetic_services import (
    ApiServiceSimulator,
    WorkerServiceSimulator,
    DatabaseServiceSimulator
)
from scenarios.run_scenario import run_synthetic_scenario
from backend.models import EventModel, SecurityFinding


def test_synthetic_services_and_scenario_runner(client, db_session):
    """
    Verifies that the synthetic services simulate normal and suspicious traffic,
    emitting through the SDK client and persisting all expected event types.
    """
    sdk = CyberEngine(
        api_key=RAW_TEST_API_KEY,
        app=TEST_APP_ID,
        endpoint="http://testserver",
    )
    sdk._client = client

    # Run the full distributed 3-service scenario
    run_synthetic_scenario(sdk)

    # Verify events persisted across all 3 services
    events = db_session.query(EventModel).all()
    assert len(events) >= 10  # 4 normal + 5 brute force + 3 bulk exfil = 12

    service_names = {e.service_id for e in events}
    assert "api-service" in service_names
    assert "worker-service" in service_names
    assert "database-service" in service_names

    event_types = {e.event_type for e in events}
    assert "auth.login_success" in event_types
    assert "auth.login_failed" in event_types
    assert "http.request" in event_types
    assert "worker.job_completed" in event_types
    assert "worker.job_anomalous" in event_types
    assert "db.bulk_query" in event_types

    # Verify findings produced by the scenarios
    findings = db_session.query(SecurityFinding).all()
    assert len(findings) >= 2

    detector_ids = {f.detector_id for f in findings}
    assert "detector.auth.failed_threshold" in detector_ids
    assert "detector.cross_service.exfiltration" in detector_ids

    # Verify cross-service finding structure
    exfil_finding = next(f for f in findings if f.detector_id == "detector.cross_service.exfiltration")
    assert exfil_finding.severity == "high"
    assert exfil_finding.confidence == "high"
    assert "stages" in exfil_finding.evidence
    stages = exfil_finding.evidence["stages"]
    assert "api_trigger" in stages
    assert "worker_anomaly" in stages
    assert "db_bulk_access" in stages
    assert stages["api_trigger"]["service_id"] == "api-service"
    assert stages["worker_anomaly"]["service_id"] == "worker-service"
    assert stages["db_bulk_access"]["service_id"] == "database-service"
