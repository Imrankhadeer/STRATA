import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserRegisterRequest(BaseModel):
    email: EmailStr = Field(description="Operator or administrator email address")
    password: str = Field(min_length=8, max_length=128, description="Strong account password")
    tenant_name: Optional[str] = Field(default=None, max_length=128, description="Company or organization workspace name")
    full_name: Optional[str] = Field(default=None, max_length=128, description="Full name of operator")


class UserLoginRequest(BaseModel):
    email: EmailStr = Field(description="Registered email address")
    password: str = Field(description="Account password")


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=16, description="Cryptographic email verification token")


class ResendVerificationRequest(BaseModel):
    email: EmailStr = Field(description="Email address to resend verification token to")


class PasswordResetRequest(BaseModel):
    email: EmailStr = Field(description="Email address for password reset")


class PasswordResetConfirmRequest(BaseModel):
    token: str = Field(min_length=16, description="Cryptographic password reset token")
    new_password: str = Field(min_length=8, max_length=128, description="New strong password")


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime.datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class MessageResponse(BaseModel):
    message: str
    success: bool = True

