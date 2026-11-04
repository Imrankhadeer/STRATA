import uuid
import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.main import app
from backend.config import settings
from backend.db.session import engine
from backend.models import ApiKey, SecurityFinding, DeclarativeRuleModel
from backend.core.auth import hash_api_key, Permission

client = TestClient(app)

TEST_API_KEY = "ce_live_test_api_key_secret_12345"
AUTH_HEADER = {"Authorization": f"Bearer {TEST_API_KEY}"}


def test_assistant_chat_unauthenticated():
    res = client.post("/api/v1/assistant/chat", json={"message": "What is CVE-2024-1234?"})
    assert res.status_code == 401


def test_assistant_chat_cybersecurity_query(monkeypatch):
    monkeypatch.setattr(settings, "INVESTIGATOR_PROVIDER", "mock")
    res = client.post(
        "/api/v1/assistant/chat",
        headers=AUTH_HEADER,
        json={"message": "How does brute force detection work?", "context": {"current_page": "findings"}}
    )
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert "conversation_id" in data
    assert len(data["reply"]) > 0


def test_assistant_chat_refuses_off_topic_bananas(monkeypatch):
    monkeypatch.setattr(settings, "INVESTIGATOR_PROVIDER", "mock")
    res = client.post(
        "/api/v1/assistant/chat",
        headers=AUTH_HEADER,
        json={"message": "how many bananas it need to you to feel good"}
    )
    assert res.status_code == 200
    data = res.json()
    reply = data["reply"]
    assert "strictly a cybersecurity assistant" in reply


def test_assistant_chat_with_ingest_only_key(monkeypatch):
    """Verify that an API key with events:ingest is permitted to chat with the assistant."""
    monkeypatch.setattr(settings, "INVESTIGATOR_PROVIDER", "mock")
    raw_ingest_key = f"ce_live_ingest_{uuid.uuid4().hex[:8]}"
    h = hash_api_key(raw_ingest_key)
    with Session(engine) as session:
        session.add(ApiKey(
            id=f"key-{uuid.uuid4().hex[:6]}",
            tenant_id="tenant-alpha",
            app_id="ingest-worker",
            key_hash=h,
            key_prefix="ce_live_",
            is_active=True,
            scopes=[Permission.EVENTS_INGEST],
        ))
        session.commit()

    res = client.post(
        "/api/v1/assistant/chat",
        headers={"Authorization": f"Bearer {raw_ingest_key}"},
        json={"message": "What is the ingestion pipeline status?"}
    )
    assert res.status_code == 200
    assert "reply" in res.json()


def test_assistant_chat_grounded_findings_fallback(monkeypatch):
    """Verify that when findings exist in the DB, fallback accurately cites them with real IDs and returns validated citations."""
    monkeypatch.setattr(settings, "INVESTIGATOR_PROVIDER", "mock")
    fid = f"fnd-{uuid.uuid4().hex[:8]}"
    with Session(engine) as session:
        session.add(SecurityFinding(
            finding_id=fid,
            tenant_id="tenant-alpha",
            detector_id="detector.cross_service.exfiltration",
            detector_version="1.0.0",
            title="Critical Data Exfiltration Sequence",
            description="A multi-stage exfiltration attack sequence was detected.",
            severity="critical",
            status="confirmed",
            created_at=datetime.now(timezone.utc),
            evidence={"services": ["api-service", "worker-service", "database-service"]},
        ))
        session.commit()

    res = client.post(
        "/api/v1/assistant/chat",
        headers=AUTH_HEADER,
        json={"message": "Are there any active findings or attacks in this workspace?"}
    )
    assert res.status_code == 200
    data = res.json()
    reply = data["reply"]
    assert fid in reply
    assert "No active security findings are currently recorded" not in reply
    # Citation should be validated against DB
    citations = data.get("citations", [])
    assert any(c["id"] == fid and c["verified"] is True for c in citations)


def test_assistant_clear_conversation(monkeypatch):
    monkeypatch.setattr(settings, "INVESTIGATOR_PROVIDER", "mock")
    res = client.post(
        "/api/v1/assistant/chat",
        headers=AUTH_HEADER,
        json={"message": "Explain Fast Track"}
    )
    assert res.status_code == 200
    conv_id = res.json()["conversation_id"]

    del_res = client.delete(f"/api/v1/assistant/chat/{conv_id}", headers=AUTH_HEADER)
    assert del_res.status_code == 204
