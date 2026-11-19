"""
Database setup for ECDAT using SQLAlchemy.
Supports SQLite (default) and PostgreSQL seamlessly.
"""
import logging

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.config import DATABASE_URL

log = logging.getLogger(__name__)

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """WAL and enforced foreign keys make SQLite safe for concurrent readers."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
    finally:
        cursor.close()


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

# Indexes the dashboard and roadmap queries rely on. Created idempotently so
# that databases created before this release get them on startup.
_INDEXES = (
    ("idx_asset_scan_name", "assets", "scan_id, name"),
    ("idx_asset_scan_action", "assets", "scan_id, migration_action"),
    ("idx_asset_scan_tier", "assets", "scan_id, risk_tier"),
    ("idx_asset_context", "assets", "scan_id, usage_context"),
    ("idx_recommendation_asset", "recommendations", "asset_id"),
    ("idx_audit_asset", "audit_events", "asset_id, created_at"),
)


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


def _create_missing_indexes():
    """Create operational indexes without touching existing ones."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        for name, table, columns in _INDEXES:
            if table not in existing_tables:
                continue
            connection.execute(text(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})"))


def init_db():
    """Initializes tables in the configured database."""
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
    _create_missing_indexes()
