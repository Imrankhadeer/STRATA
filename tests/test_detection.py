import pytest
import uuid
import datetime
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


def test_password_spraying_detection():
    """
    Verifies detection of password spraying attacks where multiple distinct source IPs
    target the same user account within the sliding window.
    """
    detector = BruteForceLoginDetector(failure_threshold=5, window_seconds=300.0, spray_threshold=3)
    target_user = "admin_svc"
    t0 = datetime.datetime(2026, 11, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)

    # 2 failed logins from distinct IPs: under spray threshold (3)
    for i in range(1, 3):
        ev = CanonicalEvent(
            event_id=f"ev-spray-{i}",
            tenant_id="tenant-test",
            app_id="auth-app",
            service_id="login",
            event_type="auth.login_failed",
            source_resource=f"198.51.100.{i}",
            timestamp=t0 + datetime.timedelta(seconds=i * 2),
            attributes={"username": target_user},
        )
        assert detector.evaluate(ev) is None

    # 3rd failed login from 3rd distinct IP targets same user: reaches spray threshold!
    ev3 = CanonicalEvent(
        event_id="ev-spray-3",
        tenant_id="tenant-test",
        app_id="auth-app",
        service_id="login",
        event_type="auth.login_failed",
        source_resource="198.51.100.3",
        timestamp=t0 + datetime.timedelta(seconds=6),
        attributes={"username": target_user},
    )
    finding = detector.evaluate(ev3)
    assert finding is not None
    assert finding.detector_id == "detector.auth.password_spray"
    assert finding.evidence["target_user"] == target_user
    assert finding.evidence["distinct_sources_count"] == 3


def test_rolling_window_expiration_prevents_false_positives():
    """
    Verifies that low-and-slow login failures spaced beyond window_seconds
    expire naturally and do NOT trigger a false positive brute force finding.
    """
    detector = BruteForceLoginDetector(failure_threshold=3, window_seconds=60.0)
    attacker_ip = "192.0.2.55"
    t0 = datetime.datetime(2026, 11, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)

    # 1st attempt at t=0
    ev1 = CanonicalEvent(
        event_id="ev-slow-1",
        tenant_id="tenant-test",
        app_id="auth-app",
        service_id="login",
        event_type="auth.login_failed",
        source_resource=attacker_ip,
        timestamp=t0,
    )
    assert detector.evaluate(ev1) is None

    # 2nd attempt at t=30s
    ev2 = CanonicalEvent(
        event_id="ev-slow-2",
        tenant_id="tenant-test",
        app_id="auth-app",
        service_id="login",
        event_type="auth.login_failed",
        source_resource=attacker_ip,
        timestamp=t0 + datetime.timedelta(seconds=30),
    )
    assert detector.evaluate(ev2) is None

    # 3rd attempt at t=95s (>60s after ev1, so ev1 has expired out of the window)
    ev3 = CanonicalEvent(
        event_id="ev-slow-3",
        tenant_id="tenant-test",
        app_id="auth-app",
        service_id="login",
        event_type="auth.login_failed",
        source_resource=attacker_ip,
        timestamp=t0 + datetime.timedelta(seconds=95),
    )
    # Since ev1 rolled off, active attempts in window are now 2 (ev2 + ev3), which is < 3
    assert detector.evaluate(ev3) is None
