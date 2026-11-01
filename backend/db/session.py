from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.config import settings
import logging

logger = logging.getLogger(__name__)

Base = declarative_base()


def get_engine(db_url: str | None = None):
    """
    Creates and returns a SQLAlchemy Engine bound to PostgreSQL.
    SQLite is strictly rejected; PostgreSQL is the sole supported database.
    """
    url = db_url or settings.DATABASE_URL
    if not url or "sqlite" in url.lower():
        raise RuntimeError("SQLite is not supported. Ternline requires PostgreSQL.")
    if not (url.startswith("postgresql://") or url.startswith("postgresql+") or url.startswith("postgres://")):
        raise RuntimeError(f"Unsupported database scheme: {url}. Ternline requires PostgreSQL.")

    connect_args = {"options": "-c timezone=utc"}
    return create_engine(url, echo=False, pool_pre_ping=True, connect_args=connect_args)

engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """FastAPI dependency for database sessions."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
