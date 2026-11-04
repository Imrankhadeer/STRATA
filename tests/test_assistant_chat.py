import pytest
from starlette.testclient import TestClient
from backend.main import app
from backend.config import settings

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
