from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import DATABASE_URL


connect_args = (
    {"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
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
    Small SQLite-compatible migration for the CrimeLens prototype.

    Adds case reference IDs and case ownership fields to existing
    databases without deleting existing evidence.
    """

    if not DATABASE_URL.startswith("sqlite"):
        return

    with engine.begin() as conn:

        # --------------------------------------------------
        # CASES
        # --------------------------------------------------

        case_columns = {
            row[1]
            for row in conn.execute(
                text("PRAGMA table_info(cases)")
            )
        }

        if "reference_id" not in case_columns:
            conn.execute(
                text(
                    "ALTER TABLE cases "
                    "ADD COLUMN reference_id VARCHAR(120)"
                )
            )

        # --------------------------------------------------
        # DOCUMENTS
        # --------------------------------------------------

        document_columns = {
            row[1]
            for row in conn.execute(
                text("PRAGMA table_info(documents)")
            )
        }

        if "case_id" not in document_columns:
            conn.execute(
                text(
                    "ALTER TABLE documents "
                    "ADD COLUMN case_id INTEGER"
                )
            )

        # --------------------------------------------------
        # RELATIONSHIPS
        # --------------------------------------------------

        relationship_columns = {
            row[1]
            for row in conn.execute(
                text("PRAGMA table_info(relationships)")
            )
        }

        if "case_id" not in relationship_columns:
            conn.execute(
                text(
                    "ALTER TABLE relationships "
                    "ADD COLUMN case_id INTEGER"
                )
            )

        # --------------------------------------------------
        # ENTITIES
        # --------------------------------------------------

        entity_columns = {
            row[1]
            for row in conn.execute(
                text("PRAGMA table_info(entities)")
            )
        }

        new_entity_fields = {
            "case_id": "INTEGER",
            "phone": "VARCHAR(50)",
            "email": "VARCHAR(120)",
            "account": "VARCHAR(100)",
            "vehicle": "VARCHAR(100)",
            "identifier": "VARCHAR(100)",
            "resolution_status": "VARCHAR(50)",
            "match_reason": "VARCHAR(255)",
        }

        for col_name, col_type in new_entity_fields.items():
            if col_name not in entity_columns:
                conn.execute(
                    text(f"ALTER TABLE entities ADD COLUMN {col_name} {col_type}")
                )