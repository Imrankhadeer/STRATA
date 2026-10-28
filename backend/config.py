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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
