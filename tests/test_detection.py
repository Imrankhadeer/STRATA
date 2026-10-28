import pytest
import uuid
from backend.detection.baseline import BruteForceLoginDetector
from backend.schemas.events import CanonicalEvent
from backend.models import SecurityFinding
from tests.conftest import TEST_APP_ID, RAW_TEST_API_KEY


def test_detector_threshold_trigger():
    """Verifies baseline detector triggers when failure threshold is reached."""
    detector = BruteForceLoginDetector(failure_threshold=3)
    attacker_ip = "198.51.100.99"

    # 1st failure: below threshold
    e1 = CanonicalEvent(
        tenant_id="tenant-test",
        app_id="auth-app",
        service_id="login",
        event_type="auth.login_failed",
        source_resource=attacker_ip,
    )
    assert detector.evaluate(e1) is None

    # 2nd failure: below threshold
    e2 = CanonicalEvent(
        tenant_id="tenant-test",
        app_id="auth-app",
        service_id="login",
        event_type="auth.login_failed",
        source_resource=attacker_ip,
    )
    assert detector.evaluate(e2) is None

    # 3rd failure: reaches threshold -> triggers Finding
    e3 = CanonicalEvent(
        tenant_id="tenant-test",
        app_id="auth-app",
        service_id="login",
        event_type="auth.login_failed",
        source_resource=attacker_ip,
    )
    finding = detector.evaluate(e3)
    assert finding is not None
    assert finding.detector_id == "detector.auth.failed_threshold"
    assert finding.severity == "medium"
    assert finding.evidence["actor"] == attacker_ip
    assert finding.evidence["attempt_count"] == 3


def test_detector_ignores_benign_events():
    """Verifies non-matching events do not trigger findings or false alerts."""
    detector = BruteForceLoginDetector(failure_threshold=3)
    benign_event = CanonicalEvent(
        tenant_id="tenant-test",
        app_id="auth-app",
        service_id="login",
        event_type="auth.login_success",
        source_resource="198.51.100.99",
    )
    assert detector.evaluate(benign_event) is None


def test_end_to_end_detection_persistence(client, auth_headers, db_session):
    """
    Verifies that fast path events that trigger detection automatically record
    a SecurityFinding in the database with provenance.
    """
    attacker_ip = "203.0.113.44"
    for _ in range(3):
        res = client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": str(uuid.uuid4()),
                "app_id": TEST_APP_ID,
                "service_id": "auth-service",
                "event_type": "auth.login_failed",
                "source_resource": attacker_ip,
            }
        )
        assert res.status_code == 202

    # Check for recorded security finding in DB
    findings = db_session.query(SecurityFinding).filter(
        SecurityFinding.detector_id == "detector.auth.failed_threshold"
    ).all()
    assert len(findings) >= 1
    assert any(attacker_ip in f.description for f in findings)
