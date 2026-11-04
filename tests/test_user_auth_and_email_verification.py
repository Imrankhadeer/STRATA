import uuid
import datetime
import pytest
from starlette.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db, engine
from backend.models import UserModel, Tenant
from backend.core.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    auth_rate_limiter,
)
from backend.core.auth import _validate_human_session
from fastapi import HTTPException
from backend.core.email import email_service


client = TestClient(app)


def test_password_change_version_invalidates_existing_human_session(db_session):
    email = f"auth-version-{uuid.uuid4().hex}@test-ternline.io"
    user = UserModel(
        id=f"user-{uuid.uuid4().hex[:12]}",
        tenant_id="tenant-alpha",
        email=email,
        hashed_password="test-hash",
        auth_version=1,
    )
    db_session.add(user)
    db_session.commit()

    revoked_payload = {
        "sub": email,
        "tenant_id": "tenant-alpha",
        "is_human": True,
        "auth_version": 0,
    }
    with pytest.raises(HTTPException) as exc_info:
        _validate_human_session(revoked_payload, db_session)
    assert exc_info.value.status_code == 401

    _validate_human_session({**revoked_payload, "auth_version": 1}, db_session)


@pytest.fixture(autouse=True)
def cleanup_test_users():
    """Ensure test users and test tenants are cleaned up before and after each test."""
    email_service.clear_sent_emails()
    auth_rate_limiter._attempts.clear()
    with Session(engine) as db:
        test_users = db.query(UserModel).filter(UserModel.email.like("%@test-ternline.io")).all()
        tenant_ids = {u.tenant_id for u in test_users}
        for u in test_users:
            db.delete(u)
        for tid in tenant_ids:
            t = db.query(Tenant).filter(Tenant.id == tid).first()
            if t and t.id != "tenant-alpha":
                db.delete(t)
        db.commit()

    yield

    with Session(engine) as db:
        test_users = db.query(UserModel).filter(UserModel.email.like("%@test-ternline.io")).all()
        tenant_ids = {u.tenant_id for u in test_users}
        for u in test_users:
            db.delete(u)
        for tid in tenant_ids:
            t = db.query(Tenant).filter(Tenant.id == tid).first()
            if t and t.id != "tenant-alpha":
                db.delete(t)
        db.commit()


def test_password_hashing_and_verification():
    raw = "TernlineSec#2026!"
    hashed = hash_password(raw)
    assert hashed.startswith("pbkdf2_sha256$600000$")
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(raw, "invalid_hash_string") is False


def test_password_strength_validation():
    # Too short
    ok, err = validate_password_strength("Short1!")
    assert not ok and "at least 8" in err

    # No uppercase
    ok, err = validate_password_strength("nocapitals123!")
    assert not ok and "uppercase" in err

    # No lowercase
    ok, err = validate_password_strength("NOLOWERCASE123!")
    assert not ok and "lowercase" in err

    # No digits or special
    ok, err = validate_password_strength("NoDigitsOrSpecial")
    assert not ok and "digit or special" in err

    # Compliant
    ok, err = validate_password_strength("SecOps_Valid#2026")
    assert ok and err is None


def test_user_registration_flow_and_email_dispatch():
    test_email = "alice@test-ternline.io"
    payload = {
        "email": test_email,
        "password": "StrongSecurityPassword123!",
        "tenant_name": "Alice Cyber Org",
        "full_name": "Alice Operator",
    }
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["success"] is True
    assert "verification email has been sent" in data["message"].lower()

    # Verify email was captured by email delivery service
    last_email = email_service.get_last_sent_email()
    assert last_email is not None
    assert last_email["to_email"] == test_email
    assert "token" in last_email["metadata"]
    token = last_email["metadata"]["token"]
    assert len(token) >= 32

    # Check database state
    with Session(engine) as db:
        user = db.query(UserModel).filter(UserModel.email == test_email).first()
        assert user is not None
        assert user.is_verified is False
        assert user.verification_token == token
        assert user.role == "admin"


def test_unverified_user_cannot_login():
    test_email = "bob@test-ternline.io"
    password = "BobStrongPassword999!"
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"email": test_email, "password": password, "tenant_name": "Bob Org"},
    )
    assert reg_resp.status_code == 201

    # Attempt login before verifying email
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": test_email, "password": password},
    )
    assert login_resp.status_code == 403
    assert "not been verified" in login_resp.json()["detail"]


def test_email_verification_success_and_jwt_generation():
    test_email = "charlie@test-ternline.io"
    password = "CharlieSecurePass456!"
    client.post(
        "/api/v1/auth/register",
        json={"email": test_email, "password": password},
    )
    token = email_service.get_last_sent_email()["metadata"]["token"]

    # Verify email
    ver_resp = client.post("/api/v1/auth/verify-email", json={"token": token})
    assert ver_resp.status_code == 200, ver_resp.text
    data = ver_resp.json()
    assert "access_token" in data
    assert data["user"]["is_verified"] is True
    assert data["user"]["email"] == test_email

    # Verify database state
    with Session(engine) as db:
        user = db.query(UserModel).filter(UserModel.email == test_email).first()
        assert user.is_verified is True
        assert user.verification_token is None

    # Now login succeeds with the verified credentials
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": test_email, "password": password},
    )
    assert login_resp.status_code == 200
    jwt_token = login_resp.json()["access_token"]

    # Call authenticated /me endpoint using the JWT
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {jwt_token}"},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["authenticated"] is True
    assert me_data["principal"] == test_email
    assert me_data["is_human"] is True


def test_invalid_and_expired_verification_token():
    # Bogus token
    resp = client.post("/api/v1/auth/verify-email", json={"token": "completely_bogus_token_1234567890"})
    assert resp.status_code == 400
    assert "invalid or expired" in resp.json()["detail"].lower()

    # Expired token
    test_email = "expired@test-ternline.io"
    client.post(
        "/api/v1/auth/register",
        json={"email": test_email, "password": "ExpiredPass#1234"},
    )
    token = email_service.get_last_sent_email()["metadata"]["token"]

    with Session(engine) as db:
        u = db.query(UserModel).filter(UserModel.email == test_email).first()
        u.verification_token_expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        db.commit()

    exp_resp = client.post("/api/v1/auth/verify-email", json={"token": token})
    assert exp_resp.status_code == 400
    assert "expired" in exp_resp.json()["detail"].lower()


def test_resend_verification_email():
    test_email = "david@test-ternline.io"
    client.post(
        "/api/v1/auth/register",
        json={"email": test_email, "password": "DavidPassword123!"},
    )
    first_token = email_service.get_last_sent_email()["metadata"]["token"]

    # Resend
    resend_resp = client.post("/api/v1/auth/resend-verification", json={"email": test_email})
    assert resend_resp.status_code == 200
    assert resend_resp.json()["success"] is True

    second_token = email_service.get_last_sent_email()["metadata"]["token"]
    assert second_token != first_token

    # Anti-enumeration test for non-existent email
    enum_resp = client.post("/api/v1/auth/resend-verification", json={"email": "nonexistent@test-ternline.io"})
    assert enum_resp.status_code == 200
    assert enum_resp.json()["success"] is True


def test_auth_brute_force_rate_limiting():
    target_email = "victim@test-ternline.io"
    client.post(
        "/api/v1/auth/register",
        json={"email": target_email, "password": "VictimValidPassword123!"},
    )

    # 5 failed login attempts
    for _ in range(5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": "WrongPassword123!"},
        )
        assert resp.status_code == 401

    # 6th attempt should be blocked by rate limiter with 429
    blocked_resp = client.post(
        "/api/v1/auth/login",
        json={"email": target_email, "password": "WrongPassword123!"},
    )
    assert blocked_resp.status_code == 429
    assert "too many" in blocked_resp.json()["detail"].lower()



def test_change_password_flow():
    email = f"operator_{uuid.uuid4().hex[:8]}@defense.soc"
    old_pw = "SecurePassword123!"
    new_pw = "NewSuperSecure456!"

    # 1. Register
    reg_resp = client.post("/api/v1/auth/register", json={"email": email, "password": old_pw})
    assert reg_resp.status_code == 201

    # 2. Verify Email
    token = email_service.get_last_sent_email()["metadata"]["token"]
    ver_resp = client.post("/api/v1/auth/verify-email", json={"token": token})
    assert ver_resp.status_code == 200

    # 3. Login to get session token
    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": old_pw})
    assert login_resp.status_code == 200
    jwt_token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {jwt_token}"}

    # 4. Attempt change with wrong current password -> 400
    bad_resp = client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": "WrongPassword999!", "new_password": new_pw},
    )
    assert bad_resp.status_code == 400

    # 5. Successful change
    good_resp = client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": old_pw, "new_password": new_pw},
    )
    assert good_resp.status_code == 200
    assert good_resp.json()["success"] is True

    # 6. Old password fails, new password succeeds
    fail_login = client.post("/api/v1/auth/login", json={"email": email, "password": old_pw})
    assert fail_login.status_code == 401

    ok_login = client.post("/api/v1/auth/login", json={"email": email, "password": new_pw})
    assert ok_login.status_code == 200
