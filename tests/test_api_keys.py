"""
Unit and Integration Tests for API Key Lifecycle Management.

Validates:
1. Unauthenticated requests to /api/v1/keys rejected with 401.
2. Key generation returns raw key strictly once with secure prefix.
3. Newly created key can immediately authenticate requests.
4. Key listing enforces strict tenant isolation and hides secrets/hashes.
5. Key rotation deactivates old key and enables new key seamlessly.
6. Key revocation immediately blocks authentication with 401.
7. Tenant boundary: Tenant A cannot see, rotate, or revoke Tenant B keys.
8. Expired keys are rejected server-side.
"""

import pytest
import datetime
from backend.models import ApiKey, Tenant
from backend.core.auth import hash_api_key
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID, RAW_TEST_API_KEY


def test_unauthenticated_keys_access_rejected(client):
    res = client.get("/api/v1/keys")
    assert res.status_code == 401

    res_post = client.post("/api/v1/keys", json={"app_id": "analytics"})
    assert res_post.status_code == 401


def test_create_and_use_api_key(client, auth_headers):
    # 1. Create a new key for 'billing-service'
    payload = {"app_id": "billing-service", "expires_in_days": 30}
    res = client.post("/api/v1/keys", json=payload, headers=auth_headers)
    assert res.status_code == 201
    data = res.json()

    assert "api_key" in data
    new_raw_key = data["api_key"]
    assert new_raw_key.startswith("ce_live_")
    key_id = data["key_id"]
    assert key_id.startswith("key-")
    assert data["app_id"] == "billing-service"
    assert data["tenant_id"] == TEST_TENANT_ID
    assert data["key_prefix"] == new_raw_key[:12]
    assert data["expires_at"] is not None

    # 2. Use newly created key to authenticate an API request
    new_auth_header = {"Authorization": f"Bearer {new_raw_key}"}
    res_list = client.get("/api/v1/keys", headers=new_auth_header)
    assert res_list.status_code == 200
    keys_list = res_list.json()

    # Verify secret is not in listing
    matching = [k for k in keys_list if k["key_id"] == key_id]
    assert len(matching) == 1
    assert matching[0]["key_prefix"] == new_raw_key[:12]
    assert matching[0]["is_active"] is True
    assert "api_key" not in matching[0]
    assert "key_hash" not in matching[0]


def test_rotate_api_key(client, auth_headers):
    # 1. Create an initial key
    create_res = client.post("/api/v1/keys", json={"app_id": "shipping-api"}, headers=auth_headers)
    assert create_res.status_code == 201
    old_key_data = create_res.json()
    old_raw_key = old_key_data["api_key"]
    old_key_id = old_key_data["key_id"]

    # Verify initial key works
    res_check = client.get("/api/v1/keys", headers={"Authorization": f"Bearer {old_raw_key}"})
    assert res_check.status_code == 200

    # 2. Rotate the key
    rot_res = client.post(f"/api/v1/keys/{old_key_id}/rotate", headers=auth_headers)
    assert rot_res.status_code == 200
    rot_data = rot_res.json()

    assert rot_data["old_key_id"] == old_key_id
    assert rot_data["new_key_id"] != old_key_id
    new_raw_key = rot_data["new_api_key"]
    assert new_raw_key.startswith("ce_live_")
    assert new_raw_key != old_raw_key

    # 3. Old key is immediately rejected with 401
    res_old = client.get("/api/v1/keys", headers={"Authorization": f"Bearer {old_raw_key}"})
    assert res_old.status_code == 401

    # 4. New key works seamlessly
    res_new = client.get("/api/v1/keys", headers={"Authorization": f"Bearer {new_raw_key}"})
    assert res_new.status_code == 200


def test_revoke_api_key(client, auth_headers):
    # 1. Create a key to revoke
    create_res = client.post("/api/v1/keys", json={"app_id": "temp-worker"}, headers=auth_headers)
    assert create_res.status_code == 201
    key_data = create_res.json()
    raw_key = key_data["api_key"]
    key_id = key_data["key_id"]

    # 2. Revoke the key
    revoke_res = client.post(f"/api/v1/keys/{key_id}/revoke", headers=auth_headers)
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "revoked"

    # 3. Subsequent authentication attempts fail with 401
    res_blocked = client.get("/api/v1/keys", headers={"Authorization": f"Bearer {raw_key}"})
    assert res_blocked.status_code == 401
    assert "Invalid or revoked API key" in res_blocked.json()["detail"]


def test_api_key_tenant_isolation(client, auth_headers, db_session):
    # Setup Tenant B with an active API key
    tenant_b_id = "tenant-bravo"
    tenant_b = Tenant(id=tenant_b_id, name="Bravo Ltd", is_active=True)
    db_session.add(tenant_b)

    raw_key_b = "ce_live_bravo_secret_998877665544332211"
    key_b_id = "key-bravo-001"
    key_b = ApiKey(
        id=key_b_id,
        tenant_id=tenant_b_id,
        app_id="bravo-core",
        key_hash=hash_api_key(raw_key_b),
        key_prefix="ce_live_brav",
        is_active=True,
        created_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
    )
    db_session.add(key_b)
    db_session.commit()

    # 1. Tenant Alpha lists keys -> Tenant B's key must NOT appear
    res_list = client.get("/api/v1/keys", headers=auth_headers)
    assert res_list.status_code == 200
    alpha_keys = res_list.json()
    assert not any(k["key_id"] == key_b_id for k in alpha_keys)
    assert not any(k["tenant_id"] == tenant_b_id for k in alpha_keys)

    # 2. Tenant Alpha attempts to revoke Tenant B's key -> 404 Not Found
    res_revoke = client.post(f"/api/v1/keys/{key_b_id}/revoke", headers=auth_headers)
    assert res_revoke.status_code == 404

    # 3. Tenant Alpha attempts to rotate Tenant B's key -> 404 Not Found
    res_rotate = client.post(f"/api/v1/keys/{key_b_id}/rotate", headers=auth_headers)
    assert res_rotate.status_code == 404

    # 4. Verify Tenant B's key is still active and untouched
    db_session.refresh(key_b)
    assert key_b.is_active is True


def test_expired_api_key_rejected(client, db_session):
    # Seed an already expired key for TEST_TENANT_ID
    raw_expired_key = "ce_live_expired_key_1122334455667788"
    past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
    key_rec = ApiKey(
        id="key-expired-001",
        tenant_id=TEST_TENANT_ID,
        app_id="legacy-service",
        key_hash=hash_api_key(raw_expired_key),
        key_prefix="ce_live_expi",
        is_active=True,
        created_at=past_time.replace(tzinfo=None),
        expires_at=past_time.replace(tzinfo=None),
    )
    db_session.add(key_rec)
    db_session.commit()

    # Attempting to authenticate with expired key produces 401
    res = client.get("/api/v1/keys", headers={"Authorization": f"Bearer {raw_expired_key}"})
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()

