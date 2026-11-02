import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class CreateAppRequest(BaseModel):
    app_id: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Application identifier (e.g. checkout-api, auth-svc)"
    )
    name: str = Field(min_length=2, max_length=128, description="Human-friendly application name")
    description: Optional[str] = Field(default=None, max_length=512)
    environment: str = Field(default="production", pattern="^(production|staging|development)$")


class AppResponse(BaseModel):
    app_id: str
    name: str
    description: Optional[str] = None
    environment: str
    is_active: bool
    created_at: datetime.datetime
    updated_at: datetime.datetime
    event_count: int = 0
    last_event_at: Optional[datetime.datetime] = None
    active_key_prefix: Optional[str] = None
    status: str = "awaiting_telemetry"  # live_ingesting, awaiting_telemetry, inactive


class CreateAppResponse(BaseModel):
    app: AppResponse
    api_key: str
    key_prefix: str
    message: str = "Application registered and ingestion API key provisioned."

