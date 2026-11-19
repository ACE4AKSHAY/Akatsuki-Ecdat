"""
Database setup for ECDAT using SQLAlchemy.
Supports SQLite (default) and PostgreSQL seamlessly.
"""
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.config import DATABASE_URL

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """FastAPI dependency for database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

_ADDED_COLUMNS = {
    "assets": {
        "usage_context": "VARCHAR(64)",
        "artifact_type": "VARCHAR(32)",
        "classical_status": "VARCHAR(32)",
        "quantum_status": "VARCHAR(32)",
        "standards_maturity": "VARCHAR(32)",
        "migration_action": "VARCHAR(32)",
        "migration_phase": "VARCHAR(32)",
        "readiness_score": "INTEGER",
        "readiness_tier": "VARCHAR(32)",
        "hndl_tier": "VARCHAR(32)",
    },
    "recommendations": {
        "action": "VARCHAR(32)",
        "phase": "VARCHAR(32)",
        "candidates_json": "TEXT",
        "playbook_json": "TEXT",
        "blockers_json": "TEXT",
        "assumptions_json": "TEXT",
    },
}


def _add_missing_columns():
    """Additive, idempotent migration for databases created before the migration-plan fields."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        for table, columns in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue
            present = {column["name"] for column in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in present:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def init_db():
    """Initializes tables in the configured database."""
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
