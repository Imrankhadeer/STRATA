import datetime
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.config import settings
from backend.db.session import get_db
from backend.models import Tenant, UserModel, WorkspaceMemberModel
from backend.core.auth import (
    Permission,
    Role,
    get_role_permissions,
    create_operator_token,
    get_current_auth,
    AuthContext,
)
from backend.core.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    generate_verification_token,
    auth_rate_limiter,
)
from backend.core.email import email_service
from backend.ops.bus import ops_bus
from backend.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    VerifyEmailRequest,
    ResendVerificationRequest,
    UserResponse,
    TokenResponse,
    MessageResponse,
    ChangePasswordRequest,
    PasswordResetRequest,
    PasswordResetConfirmRequest,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & User Management"])


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new operator account and send email verification token",
)
def register_user(
    req: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    email = req.email.strip().lower()

    # 1. Enforce password complexity
    is_strong, err_msg = validate_password_strength(req.password)
    if not is_strong:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg or "Password does not meet complexity requirements.",
        )

    # 2. Check existing user
    existing_user = db.query(UserModel).filter(UserModel.email == email).first()
    if existing_user:
        if existing_user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email address already exists. Please log in.",
            )
        # Unverified user resubmitting: refresh token and resend verification
        token = generate_verification_token()
        token_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS
        )
        existing_user.hashed_password = hash_password(req.password)
        existing_user.verification_token = token
        existing_user.verification_token_expires_at = token_exp
        if req.full_name:
            existing_user.full_name = req.full_name
        db.commit()

        tenant = db.query(Tenant).filter(Tenant.id == existing_user.tenant_id).first()
        tenant_name = tenant.name if tenant else "Ternline Security"
        email_service.send_verification_email(
            to_email=email,
            token=token,
            tenant_name=tenant_name,
        )
        return MessageResponse(
            message="Your account is pending verification. A fresh verification email has been sent.",
            success=True,
        )

    # 3. Provision workspace/tenant for new user
    tenant_name = req.tenant_name.strip() if req.tenant_name else f"{email.split('@')[0].capitalize()} Workspace"
    tenant_id = f"tenant-{uuid.uuid4().hex[:10]}"
    new_tenant = Tenant(
        id=tenant_id,
        name=tenant_name,
        is_active=True,
    )
    db.add(new_tenant)

    # 4. Generate user record and verification token
    token = generate_verification_token()
    token_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS
    )

    new_user = UserModel(
        id=f"user-{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        email=email,
        hashed_password=hash_password(req.password),
        full_name=req.full_name.strip() if req.full_name else None,
        role="admin",  # Retains admin compatibility on UserModel while WorkspaceMember holds owner
        is_active=True,
        is_verified=False,
        verification_token=token,
        verification_token_expires_at=token_exp,
    )
    db.add(new_user)
    db.flush()

    # Create workspace membership
    initial_member = WorkspaceMemberModel(
        id=f"wm-{uuid.uuid4().hex[:10]}",
        tenant_id=tenant_id,
        user_id=new_user.id,
        role="owner",
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db.add(initial_member)
    db.commit()

    # 5. Dispatch email verification
    email_service.send_verification_email(
        to_email=email,
        token=token,
        tenant_name=tenant_name,
    )

    ops_bus.publish(
        component="auth",
        event_type="auth.user_registered",
        level="info",
        message=f"New operator registered: {email} (tenant: {tenant_id})",
    )

    return MessageResponse(
        message="Registration successful. A verification email has been sent to your address. Please verify to activate your account.",
        success=True,
    )


@router.post(
    "/verify-email",
    response_model=TokenResponse,
    summary="Verify user email address using verification token and issue session JWT",
)
def verify_email(
    req: VerifyEmailRequest,
    db: Session = Depends(get_db),
):
    token = req.token.strip()
    user = db.query(UserModel).filter(UserModel.verification_token == token).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token.",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    exp = user.verification_token_expires_at
    if exp:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if exp < now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification token has expired. Please request a new verification email.",
            )

    # Mark user as verified and invalidate token
    user.is_verified = True
    user.verification_token = None
    user.verification_token_expires_at = None
    user.updated_at = now
    db.commit()
    db.refresh(user)

    # Issue operator session JWT
    scopes = get_role_permissions(user.role or "owner")
    access_token = create_operator_token(
        principal=user.email,
        tenant_id=user.tenant_id,
        scopes=scopes,
        is_human=True,
        role=user.role or "owner",
    )

    ops_bus.publish(
        component="auth",
        event_type="auth.email_verified",
        level="info",
        message=f"Operator email verified: {user.email}",
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=3600,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/resend-verification",
    response_model=MessageResponse,
    summary="Resend verification email to unverified account",
)
def resend_verification(
    req: ResendVerificationRequest,
    db: Session = Depends(get_db),
):
    email = req.email.strip().lower()
    user = db.query(UserModel).filter(UserModel.email == email).first()

    # Anti-enumeration safeguard: return generic success even if user not found or already verified
    if user and not user.is_verified and user.is_active:
        token = generate_verification_token()
        token_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS
        )
        user.verification_token = token
        user.verification_token_expires_at = token_exp
        db.commit()

        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        tenant_name = tenant.name if tenant else "Ternline Security"
        email_service.send_verification_email(
            to_email=email,
            token=token,
            tenant_name=tenant_name,
        )

    return MessageResponse(
        message="If an account with this email exists and is pending verification, a new verification link has been dispatched.",
        success=True,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate operator with email and password, issuing session JWT",
)
def login(
    req: UserLoginRequest,
    db: Session = Depends(get_db),
):
    email = req.email.strip().lower()
    rate_limit_key = f"auth:login:{email}"

    if auth_rate_limiter.is_rate_limited(rate_limit_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait 5 minutes before trying again.",
        )

    user = db.query(UserModel).filter(UserModel.email == email).first()

    if not user or not verify_password(req.password, user.hashed_password):
        auth_rate_limiter.record_attempt(rate_limit_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your operator account is currently deactivated. Contact your workspace administrator.",
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email address has not been verified. Please check your inbox or request a new verification email.",
        )

    # Success: reset failed attempts
    auth_rate_limiter.reset(rate_limit_key)

    scopes = get_role_permissions(user.role or "owner")
    access_token = create_operator_token(
        principal=user.email,
        tenant_id=user.tenant_id,
        scopes=scopes,
        is_human=True,
        role=user.role or "owner",
    )

    ops_bus.publish(
        component="auth",
        event_type="auth.login_success",
        level="info",
        message=f"Operator logged in: {user.email} (tenant: {user.tenant_id})",
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=3600,
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    summary="Get current authenticated operator profile and permissions",
)
def get_current_user_profile(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    user = None
    if auth.operator_principal:
        user = db.query(UserModel).filter(UserModel.email == auth.operator_principal).first()

    return {
        "authenticated": True,
        "principal": auth.operator_principal or auth.app_id,
        "tenant_id": auth.tenant_id,
        "app_id": auth.app_id,
        "auth_type": auth.auth_type,
        "is_human": auth.is_human,
        "permissions": sorted(list(auth.permissions)),
        "user": UserResponse.model_validate(user) if user else None,
    }



@router.post(
    "/change-password",
    response_model=MessageResponse,
    summary="Change operator account password",
)
def change_password(
    req: ChangePasswordRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    if not auth.operator_principal:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password modification requires an active human operator session.",
        )
    user = db.query(UserModel).filter(UserModel.email == auth.operator_principal).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Operator account not found.",
        )
    if not verify_password(req.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )
    is_strong, err_msg = validate_password_strength(req.new_password)
    if not is_strong:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg or "New password does not meet complexity requirements.",
        )
    user.hashed_password = hash_password(req.new_password)
    user.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    ops_bus.publish(
        component="auth",
        event_type="auth.password_changed",
        level="info",
        message=f"Operator password rotated: {user.email}",
    )
    return MessageResponse(
        message="Password successfully updated.",
        success=True,
    )


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request a password reset link sent via email",
)
def forgot_password(
    req: PasswordResetRequest,
    db: Session = Depends(get_db),
):
    email = req.email.strip().lower()
    user = db.query(UserModel).filter(UserModel.email == email).first()

    # Anti-enumeration safeguard: always return generic success
    if user and user.is_active:
        token = generate_verification_token()
        token_exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=settings.PASSWORD_RESET_EXPIRE_HOURS
        )
        user.reset_token = token
        user.reset_token_expires_at = token_exp
        db.commit()

        email_service.send_password_reset_email(to_email=email, token=token)

    return MessageResponse(
        message="If an account with this email exists, a password reset link has been dispatched.",
        success=True,
    )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset password using a valid cryptographic reset token",
)
def reset_password(
    req: PasswordResetConfirmRequest,
    db: Session = Depends(get_db),
):
    token = req.token.strip().split("&")[0]
    user = db.query(UserModel).filter(UserModel.reset_token == token).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    exp = user.reset_token_expires_at
    if exp:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if exp < now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password reset token has expired. Please request a new link.",
            )

    is_strong, err_msg = validate_password_strength(req.new_password)
    if not is_strong:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg or "New password does not meet complexity requirements.",
        )

    user.hashed_password = hash_password(req.new_password)
    user.reset_token = None
    user.reset_token_expires_at = None
    user.updated_at = now
    db.commit()

    ops_bus.publish(
        component="auth",
        event_type="auth.password_reset_success",
        level="info",
        message=f"Operator password reset: {user.email}",
    )

    return MessageResponse(
        message="Password successfully reset. You can now sign in with your new credentials.",
        success=True,
    )
