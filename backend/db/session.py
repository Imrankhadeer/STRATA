from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.config import settings
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()

def get_engine(db_url: str | None = None):
    url = db_url or settings.DATABASE_URL
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        return create_engine(url, echo=False, pool_pre_ping=True, connect_args=connect_args)
    elif "postgresql" in url or "postgres" in url:
        connect_args["options"] = "-c timezone=utc"

    eng = create_engine(url, echo=False, pool_pre_ping=True, connect_args=connect_args)
    if settings.ALLOW_SQLITE_TEST_FALLBACK and settings.ENVIRONMENT.lower() in ("development", "testing"):
        try:
            with eng.connect() as conn:
                pass
        except Exception as e:
            logger.warning(
                "Primary database (%s) unreachable (%s). Auto-fallback to local SQLite (ALLOW_SQLITE_TEST_FALLBACK=True).",
                url.split("@")[-1] if "@" in url else url,
                e,
            )
            fallback_url = "sqlite:///./cyber_engine_dev.db"
            return create_engine(fallback_url, echo=False, pool_pre_ping=True, connect_args={"check_same_thread": False})
    return eng

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """FastAPI dependency for database sessions."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
