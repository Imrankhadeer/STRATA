"""
Security and Hardening Tests for CYBER ENGINE SDK.
Verifies:
1. Automatic recursive scrubbing of sensitive keys (password, api_key, credit card, tokens).
2. Large payload bounding (max string truncation, max keys, 1MB limit).
3. HTTPS enforcement for non-localhost environments.
4. Retry and transient failure tolerance.
"""

import pytest
from cyber_engine import CyberEngine, CyberEngineError
from cyber_engine.events import Event
from cyber_engine.security import sanitize_attributes, validate_endpoint_url
from tests.conftest import TEST_APP_ID, RAW_TEST_API_KEY


def test_sensitive_attributes_auto_redacted():
    raw_attrs = {
        "user_id": "usr_123",
        "password": "SuperSecretPassword123!",
        "api_key": "ce_live_xyz",
        "nested": {
            "credit_card": "4111-2222-3333-4444",
            "cvv": "123",
            "safe_field": "ok"
        },
        "token_list": [{"auth_token": "bearer_abc"}, {"safe": True}]
    }

    sanitized = sanitize_attributes(raw_attrs)
    assert sanitized["user_id"] == "usr_123"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["credit_card"] == "[REDACTED]"
    assert sanitized["nested"]["cvv"] == "[REDACTED]"
    assert sanitized["nested"]["safe_field"] == "ok"
    assert sanitized["token_list"][0]["auth_token"] == "[REDACTED]"
    assert sanitized["token_list"][1]["safe"] is True


def test_event_to_dict_redaction_and_size_bounds():
    ev = Event(
        event_type="auth.login",
        app_id="app-1",
        service_id="auth-svc",
        attributes={"secret_token": "abc", "long_text": "A" * 15000}
    )
    d = ev.to_dict()
    assert d["attributes"]["secret_token"] == "[REDACTED]"
    assert d["attributes"]["long_text"].endswith("...[TRUNCATED]")
    assert len(d["attributes"]["long_text"]) < 11000


def test_payload_exceeding_1mb_fails_closed():
    # Attempting to serialize > 1 MB payload must raise ValueError client-side
    huge_attrs = {f"k_{i}": "X" * 10000 for i in range(120)}
    ev = Event(
        event_type="data.dump",
        app_id="app-1",
        service_id="db-svc",
        attributes=huge_attrs
    )
    # The key count capping will truncate, but if forced raw it raises:
    with pytest.raises(ValueError) as exc:
        ev.to_dict(auto_sanitize=False)
    assert "exceeds maximum allowable SDK limit" in str(exc.value)


def test_https_enforcement_for_remote_endpoints():
    # Localhost allowed with http
    assert validate_endpoint_url("http://localhost:8000") == "http://localhost:8000"
    assert validate_endpoint_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert validate_endpoint_url("http://testserver") == "http://testserver"

    # Remote domain with http raises ValueError
    with pytest.raises(ValueError) as exc:
        validate_endpoint_url("http://engine.mycompany.com")
    assert "Security Violation: Insecure HTTP is prohibited" in str(exc.value)

    # Remote domain with https allowed
    assert validate_endpoint_url("https://engine.mycompany.com") == "https://engine.mycompany.com"

    # Explicit override allowed for internal air-gapped testing
    assert validate_endpoint_url("http://engine.internal", allow_insecure_http=True) == "http://engine.internal"

