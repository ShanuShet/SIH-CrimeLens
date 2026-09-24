import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    # Vercel / production PostgreSQL
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
    )
else:
    # Local development
    BASE_DIR = Path(__file__).resolve().parent.parent
    DB_PATH = BASE_DIR / "crimelens.db"

    engine = create_engine(
        f"sqlite:///{DB_PATH}",
        connect_args={"check_same_thread": False},
    )

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
