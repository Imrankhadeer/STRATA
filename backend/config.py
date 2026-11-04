from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import Optional


class Settings(BaseSettings):
    ENVIRONMENT: str = Field(default="development", description="App environment")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    SECRET_KEY: str = Field(
        default="cyber-engine-dev-insecure-secret-key-32chars",
        description="Internal signing/auth secret"
    )

    DATABASE_URL: str = Field(
        default="postgresql+psycopg2://postgres:postgres@localhost:5432/cyber_engine",
        description="Database connection string (PostgreSQL exclusively)"
    )

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v or "sqlite" in v.lower():
            raise ValueError(
                "SQLite is prohibited in Ternline. DATABASE_URL must be a valid PostgreSQL connection string "
                "(e.g. postgresql+psycopg2://user:password@host:port/dbname)."
            )
        if not (v.startswith("postgresql://") or v.startswith("postgresql+") or v.startswith("postgres://")):
            raise ValueError(
                f"Unsupported database scheme in DATABASE_URL: {v}. Ternline requires PostgreSQL."
            )
        # Normalize cloud provider URL schemes (e.g. Render, Railway, Supabase default to postgres://)
        if v.startswith("postgres://"):
            v = v.replace("postgres://", "postgresql+psycopg2://", 1)
        elif v.startswith("postgresql://") and not v.startswith("postgresql+"):
            v = v.replace("postgresql://", "postgresql+psycopg2://", 1)
        return v

    MAX_PAYLOAD_BYTES: int = 1_048_576  # 1 MB
    MAX_EVENTS_PER_BATCH: int = 100
    INGESTION_RATE_LIMIT_PER_MINUTE: int = 1200

    # Deployment Architecture Constraint:
    # Single-worker per process instance (`uvicorn --workers 1`) is the supported deployment mode
    # for in-memory sliding trace correlation windows, with PostgreSQL backing persistent finding
    # and rule state across restarts. Multi-process clustering requires distributed stream correlation.
    WORKERS: int = 1

    # Distributed Correlation State Configuration
    REDIS_URL: Optional[str] = Field(default=None, description="Redis connection URL (e.g. redis://localhost:6379/0)")
    REDIS_REQUIRED: bool = Field(default=False, description="Require Redis for distributed state; fails startup if unavailable in production")
    REDIS_STATE_TIMEOUT_MS: int = Field(default=500, description="Redis operation timeout in milliseconds")
    REDIS_MAX_CONNECTIONS: int = Field(default=50, description="Max Redis connection pool size")

    # Production Bootstrap Configuration
    INITIAL_ADMIN_API_KEY: Optional[str] = Field(
        default=None,
        description="Secure initial administrative API key provisioned on first startup in production"
    )
    INITIAL_TENANT_ID: str = Field(
        default="tenant-alpha",
        description="Initial tenant ID provisioned if INITIAL_ADMIN_API_KEY is provided"
    )

    # Deep-Investigation Configuration
    INVESTIGATOR_PROVIDER: str = Field(default="muse", description="Investigator provider: muse | meta | openai_compatible | mock")
    INVESTIGATOR_BASE_URL: str = Field(default="https://api.meta.ai/v1", description="Investigator API base URL")
    INVESTIGATOR_API_KEY: str = Field(default="", description="Investigator API Key")
    INVESTIGATOR_MODEL: str = Field(default="muse-spark-1.3", description="Investigator Model Identifier")
    INVESTIGATOR_TIMEOUT_SECONDS: float = Field(default=30.0, description="Investigator timeout in seconds")

    ALLOW_SIMULATION_API: bool = Field(default=False, description="Allow simulation API strictly when explicitly enabled (disabled in production)")
    ALLOWED_CORS_ORIGINS: str = Field(default="http://localhost:8000,http://127.0.0.1:8000", description="Comma-separated CORS allowlist")
    CORS_ALLOW_VERCEL: bool = Field(default=False, description="Allow requests from *.vercel.app domains")
    FRONTEND_URL: str = Field(default="http://localhost:8000", description="Base URL of frontend (e.g. https://ternline.vercel.app)")
    
    # Email Delivery Configuration (AWS SES / SMTP)
    SMTP_HOST: Optional[str] = Field(default=None, description="SMTP server host")
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    SMTP_USER: Optional[str] = Field(default=None, description="SMTP username")
    SMTP_PASSWORD: Optional[str] = Field(default=None, description="SMTP password")
    SMTP_FROM_EMAIL: str = Field(default="noreply@ternline.io", description="Sender email address")
    SMTP_TLS: bool = Field(default=True, description="Use TLS for SMTP")
    AWS_REGION: str = Field(default="us-east-1", description="AWS Region for SES and CloudWatch")
    AWS_SES_SOURCE: Optional[str] = Field(default=None, description="Verified AWS SES sender email")
    EMAIL_VERIFICATION_EXPIRE_HOURS: int = Field(default=24, description="Email verification token lifetime in hours")
    PASSWORD_RESET_EXPIRE_HOURS: int = Field(default=1, description="Password reset token lifetime in hours")

    ASYNC_INGESTION_ENABLED: bool = Field(default=False, description="Decouple ingestion from detection via async queue")
    ASYNC_QUEUE_KEY: str = Field(default="cyber_engine:telemetry_queue", description="Redis queue key for async telemetry")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()


def validate_production_settings() -> None:
    """Fail closed when insecure defaults are present or required distributed state is missing."""
    if "sqlite" in settings.DATABASE_URL.lower():
        raise RuntimeError("SQLite is prohibited in Ternline. Set DATABASE_URL to a valid PostgreSQL connection string.")
    if settings.ENVIRONMENT.lower() in ("production", "staging"):
        insecure = "cyber-engine-dev-insecure-secret-key-32chars"
        if (
            settings.SECRET_KEY == insecure
            or "generate_with_" in settings.SECRET_KEY.lower()
            or len(settings.SECRET_KEY) < 32
        ):
            raise RuntimeError("SECRET_KEY must be set to a strong value (>=32 chars) in production/staging.")
        if (settings.REDIS_REQUIRED or settings.WORKERS > 1) and not settings.REDIS_URL:
            raise RuntimeError(
                "Distributed correlation requires REDIS_URL in production when REDIS_REQUIRED=true or WORKERS > 1. "
                "In-memory state cannot correlate telemetry across multiple workers."
            )
        if settings.ALLOW_SIMULATION_API:
            raise RuntimeError("ALLOW_SIMULATION_API must be false in production/staging.")
        if settings.CORS_ALLOW_VERCEL:
            raise RuntimeError(
                "CORS_ALLOW_VERCEL must be false in production/staging; configure explicit ALLOWED_CORS_ORIGINS."
            )
        if settings.INVESTIGATOR_PROVIDER == "mock":
            raise RuntimeError("INVESTIGATOR_PROVIDER cannot be 'mock' in production/staging. Configure 'muse', 'meta', or 'openai_compatible'.")
        if not settings.INVESTIGATOR_API_KEY or "your_" in settings.INVESTIGATOR_API_KEY.lower():
            raise RuntimeError("INVESTIGATOR_API_KEY must be configured in production/staging.")
        db_url_lower = settings.DATABASE_URL.lower()
        insecure_db_patterns = [
            "postgres_prod_password_change_me",
            ":password@",
            ":changeme@",
            ":123456@",
            ":admin@",
            ":secret@",
        ]
        if any(pat in db_url_lower for pat in insecure_db_patterns):
            raise RuntimeError("DATABASE_URL contains an insecure default or placeholder password.")
        if settings.INITIAL_ADMIN_API_KEY:
            admin_key_lower = settings.INITIAL_ADMIN_API_KEY.lower()
            if (
                "replace_me" in admin_key_lower
                or "change_me" in admin_key_lower
                or "test_api_key" in admin_key_lower
                or settings.INITIAL_ADMIN_API_KEY == "ce_live_test_api_key_secret_12345"
                or len(settings.INITIAL_ADMIN_API_KEY) < 32
            ):
                raise RuntimeError("INITIAL_ADMIN_API_KEY must be a non-placeholder value of at least 32 characters and cannot use test defaults.")
