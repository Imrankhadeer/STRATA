import uuid
import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import engine
from backend.models import UserModel, Tenant, WorkspaceMemberModel, ApplicationModel, ApiKey
from backend.core.email import email_service

client = TestClient(app)


def test_complete_multi_workspace_and_apps_lifecycle():
    # 1. Register Alice
    alice_email = f"alice_{uuid.uuid4().hex[:8]}@defense.soc"
    alice_pw = "StrongPass123!@#"
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"email": alice_email, "password": alice_pw, "tenant_name": "Alice Primary Workspace"},
    )
    assert reg_resp.status_code == 201

    token = email_service.get_last_sent_email()["metadata"]["token"]
    ver_resp = client.post("/api/v1/auth/verify-email", json={"token": token})
    assert ver_resp.status_code == 200
    alice_jwt = ver_resp.json()["access_token"]
    alice_headers = {"Authorization": f"Bearer {alice_jwt}"}

    # 2. List Workspaces for Alice
    ws_resp = client.get("/api/v1/workspaces", headers=alice_headers)
    assert ws_resp.status_code == 200
    workspaces = ws_resp.json()
    assert len(workspaces) == 1
    assert workspaces[0]["role"] == "owner"
    assert workspaces[0]["is_current"] is True
    primary_ws_id = workspaces[0]["id"]

    # 3. Create a second workspace for Alice
    create_ws_resp = client.post(
        "/api/v1/workspaces",
        headers=alice_headers,
        json={"name": "Alice Secondary Workspace"},
    )
    assert create_ws_resp.status_code == 201
    sec_ws = create_ws_resp.json()
    sec_ws_id = sec_ws["id"]
    assert sec_ws["name"] == "Alice Secondary Workspace"
    assert sec_ws["role"] == "owner"

    # 4. List Workspaces again - should show 2 workspaces
    ws_resp2 = client.get("/api/v1/workspaces", headers=alice_headers)
    assert ws_resp2.status_code == 200
    workspaces2 = ws_resp2.json()
    assert len(workspaces2) == 2

    # 5. Switch workspace context to Secondary Workspace
    switch_resp = client.post(
        "/api/v1/workspaces/switch",
        headers=alice_headers,
        json={"tenant_id": sec_ws_id},
    )
    assert switch_resp.status_code == 200
    switched_data = switch_resp.json()
    new_jwt = switched_data["access_token"]
    sec_headers = {"Authorization": f"Bearer {new_jwt}"}

    # Verify context switched
    ws_resp3 = client.get("/api/v1/workspaces", headers=sec_headers)
    assert ws_resp3.status_code == 200
    for w in ws_resp3.json():
        if w["id"] == sec_ws_id:
            assert w["is_current"] is True
        elif w["id"] == primary_ws_id:
            assert w["is_current"] is False

    # 6. Register an Application in the Secondary Workspace
    app_id = f"checkout-{uuid.uuid4().hex[:6]}"
    create_app_resp = client.post(
        "/api/v1/apps",
        headers=sec_headers,
        json={
            "app_id": app_id,
            "name": "Stripe Checkout Service",
            "environment": "production",
            "description": "High-volume checkout processing",
        },
    )
    assert create_app_resp.status_code == 201
    app_data = create_app_resp.json()
    assert app_data["app"]["app_id"] == app_id
    assert app_data["app"]["name"] == "Stripe Checkout Service"
    assert "api_key" in app_data
    app_key = app_data["api_key"]
    assert app_key.startswith("ce_live_")

    # 7. List Applications in Secondary Workspace
    list_apps_resp = client.get("/api/v1/apps", headers=sec_headers)
    assert list_apps_resp.status_code == 200
    apps = list_apps_resp.json()
    assert len(apps) >= 1
    found_app = next((a for a in apps if a["app_id"] == app_id), None)
    assert found_app is not None
    assert found_app["status"] == "awaiting_telemetry"

    # 8. Ingest telemetry using the provisioned app key
    ingest_resp = client.post(
        "/v1/events",
        headers={"Authorization": f"Bearer {app_key}"},
        json={
            "app_id": app_id,
            "service_id": "checkout-svc",
            "event_type": "checkout.payment.processed",
            "severity": "low",
            "trace_id": f"trace-{uuid.uuid4().hex[:8]}",
            "timestamp": "2026-11-03T00:00:00Z",
            "attributes": {"amount": 100, "currency": "USD"},
        },
    )
    assert ingest_resp.status_code == 202

    # 9. Query events filtered by app_id
    events_resp = client.get(f"/api/v1/events?app_id={app_id}", headers=sec_headers)
    assert events_resp.status_code == 200
    ev_list = events_resp.json()
    assert len(ev_list) == 1
    assert ev_list[0]["app_id"] == app_id

    # 10. Switch back to Primary Workspace and verify app isolation (app_id should NOT exist in primary)
    client.post("/api/v1/workspaces/switch", headers=sec_headers, json={"tenant_id": primary_ws_id})
    pri_apps_resp = client.get("/api/v1/apps", headers=alice_headers)
    assert pri_apps_resp.status_code == 200
    pri_apps = pri_apps_resp.json()
    assert not any(a["app_id"] == app_id for a in pri_apps)


def test_workspace_membership_and_unauthorized_switch_rejected():
    # User Bob
    bob_email = f"bob_{uuid.uuid4().hex[:8]}@defense.soc"
    bob_pw = "BobPassword123!"
    client.post("/api/v1/auth/register", json={"email": bob_email, "password": bob_pw})
    bob_token = email_service.get_last_sent_email()["metadata"]["token"]
    ver = client.post("/api/v1/auth/verify-email", json={"token": bob_token})
    bob_jwt = ver.json()["access_token"]
    bob_headers = {"Authorization": f"Bearer {bob_jwt}"}

    # User Charlie
    charlie_email = f"charlie_{uuid.uuid4().hex[:8]}@defense.soc"
    charlie_pw = "CharliePassword123!"
    client.post("/api/v1/auth/register", json={"email": charlie_email, "password": charlie_pw})
    charlie_token = email_service.get_last_sent_email()["metadata"]["token"]
    ver_c = client.post("/api/v1/auth/verify-email", json={"token": charlie_token})
    charlie_jwt = ver_c.json()["access_token"]
    charlie_ws = client.get("/api/v1/workspaces", headers={"Authorization": f"Bearer {charlie_jwt}"}).json()[0]["id"]

    # Bob attempts to switch to Charlie's workspace without being a member -> 403 Forbidden!
    unauth_switch = client.post(
        "/api/v1/workspaces/switch",
        headers=bob_headers,
        json={"tenant_id": charlie_ws},
    )
    assert unauth_switch.status_code == 403
    assert "authorization denied" in unauth_switch.json()["detail"].lower()


def test_password_forgot_and_reset_flow():
    email = f"david_{uuid.uuid4().hex[:8]}@defense.soc"
    pw = "DavidSecure123!"
    new_pw = "DavidBrandNew456!"

    client.post("/api/v1/auth/register", json={"email": email, "password": pw})
    ver_token = email_service.get_last_sent_email()["metadata"]["token"]
    client.post("/api/v1/auth/verify-email", json={"token": ver_token})

    # 1. Request forgot password
    forgot_resp = client.post("/api/v1/auth/forgot-password", json={"email": email})
    assert forgot_resp.status_code == 200

    # 2. Extract reset token from email
    last_email = email_service.get_last_sent_email()
    assert last_email["to_email"] == email
    reset_link = last_email["metadata"]["reset_link"]
    reset_token = reset_link.split("token=")[-1]
    assert len(reset_token) >= 16

    # 3. Perform reset
    reset_resp = client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": new_pw},
    )
    assert reset_resp.status_code == 200
    assert reset_resp.json()["success"] is True

    # 4. Old password fails, new password succeeds
    bad_login = client.post("/api/v1/auth/login", json={"email": email, "password": pw})
    assert bad_login.status_code == 401

    ok_login = client.post("/api/v1/auth/login", json={"email": email, "password": new_pw})
    assert ok_login.status_code == 200
