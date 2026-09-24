import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
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


def migrate_case_fields():
    """
    Apply small compatibility migrations that SQLAlchemy's
    create_all() does not perform on an existing database.

    The current CrimeLens Case model requires a stable reference_id.
    This migration is safe for both SQLite and PostgreSQL.
    """

    inspector = inspect(engine)

    if "cases" not in inspector.get_table_names():
        # The table will be created by Base.metadata.create_all()
        # before this function is called.
        return

    columns = {
        column["name"]
        for column in inspector.get_columns("cases")
    }

    # Add reference_id to older CrimeLens databases that were
    # created before case reference IDs were introduced.
    if "reference_id" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE cases "
                    "ADD COLUMN reference_id VARCHAR(120)"
                )
            )

    # Keep reference IDs unique.
    #
    # NULL values are allowed for legacy rows. The startup
    # backfill in main.py assigns unique CL-LEGACY-XXX values
    # to those rows afterward.
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "ix_cases_reference_id "
                "ON cases (reference_id)"
            )
        )
