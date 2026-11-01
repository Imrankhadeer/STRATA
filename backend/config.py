from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
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
        description="Database connection string"
    )
    ALLOW_SQLITE_TEST_FALLBACK: bool = Field(
        default=True,
        description="Allow SQLite fallback for testing environments without PostgreSQL"
    )

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

    # Deep-Investigation Configuration
    INVESTIGATOR_PROVIDER: str = Field(default="mock", description="Investigator provider: mock | meta | openai_compatible")
    INVESTIGATOR_BASE_URL: str = Field(default="https://api.llama.com/v1", description="Investigator API base URL")
    INVESTIGATOR_API_KEY: str = Field(default="", description="Investigator API Key")
    INVESTIGATOR_MODEL: str = Field(default="Llama-3.3-70B-Instruct", description="Investigator Model Identifier")
    INVESTIGATOR_TIMEOUT_SECONDS: float = Field(default=30.0, description="Investigator timeout in seconds")

    ALLOW_SIMULATION_API: bool = Field(default=False, description="Allow simulation API outside development when explicitly enabled")
    ALLOWED_CORS_ORIGINS: str = Field(default="http://localhost:8000,http://127.0.0.1:8000", description="Comma-separated CORS allowlist")
    ASYNC_INGESTION_ENABLED: bool = Field(default=False, description="Decouple ingestion from detection via async queue")
    ASYNC_QUEUE_KEY: str = Field(default="cyber_engine:telemetry_queue", description="Redis queue key for async telemetry")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()


def validate_production_settings() -> None:
    """Fail closed in production when insecure defaults are present or required distributed state is missing."""
    if settings.ENVIRONMENT.lower() in ("production", "staging"):
        insecure = "cyber-engine-dev-insecure-secret-key-32chars"
        if settings.SECRET_KEY == insecure or len(settings.SECRET_KEY) < 32:
            raise RuntimeError("SECRET_KEY must be set to a strong value (>=32 chars) in production/staging.")
        if (settings.REDIS_REQUIRED or settings.WORKERS > 1) and not settings.REDIS_URL:
            raise RuntimeError(
                "Distributed correlation requires REDIS_URL in production when REDIS_REQUIRED=true or WORKERS > 1. "
                "In-memory state cannot correlate telemetry across multiple workers."
            )
