"""Database administration: backup, stats and vacuum for the SQLite store.

    python scripts/db_admin.py stats
    python scripts/db_admin.py backup --output work/backups/ecdat-2026-11-19.db
    python scripts/db_admin.py vacuum

Backup uses the SQLite online-backup API, which is safe against a running
API because it copies a consistent snapshot including WAL content. Only
SQLite databases are supported; `DATABASE_URL` must be a `sqlite:///` URL or
omitted (the default applies).
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path


def sqlite_path(database_url: str | None) -> Path:
    url = database_url or os.getenv("DATABASE_URL", "sqlite:///./ecdat.db")
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        sys.exit("db_admin supports SQLite only; DATABASE_URL is not a sqlite:/// URL.")
    path = Path(url[len(prefix):])
    if not path.is_file():
        sys.exit(f"Database file not found: {path}")
    return path


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path))
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def cmd_stats(path: Path) -> int:
    connection = _connect(path)
    try:
        size_mib = path.stat().st_size / (1024 * 1024)
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        fk_violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        print(f"database      {path}")
        print(f"size          {size_mib:.2f} MiB")
        print(f"journal mode  {journal}")
        print(f"fk violations {len(fk_violations)}")
        for row in fk_violations[:5]:
            print(f"  - {row}")
        print()
        print(f"{'table':<20}{'rows':>10}")
        known = ("scans", "scan_jobs", "assets", "recommendations", "audit_events")
        present = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        for table in known:
            if table not in present:
                continue
            count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"{table:<20}{count:>10,}")
    finally:
        connection.close()
    return 0


def cmd_backup(path: Path, output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    source = _connect(path)
    target = sqlite3.connect(str(output))
    try:
        with target:
            source.backup(target)
    finally:
        source.close()
        target.close()
    copied = output.stat().st_size / (1024 * 1024)
    print(f"backed up {path} -> {output} ({copied:.2f} MiB)")
    return 0


def cmd_vacuum(path: Path) -> int:
    connection = _connect(path)
    try:
        before = path.stat().st_size / (1024 * 1024)
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("VACUUM")
        after = path.stat().st_size / (1024 * 1024)
        print(f"vacuumed {path}: {before:.2f} MiB -> {after:.2f} MiB")
    finally:
        connection.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("backup", "stats", "vacuum"))
    parser.add_argument("--output", type=Path, help="Backup destination file (backup only)")
    args = parser.parse_args()

    path = sqlite_path(os.getenv("DATABASE_URL"))
    if args.command == "stats":
        return cmd_stats(path)
    if args.command == "backup":
        if not args.output:
            parser.error("backup requires --output")
        return cmd_backup(path, args.output)
    return cmd_vacuum(path)


if __name__ == "__main__":
    raise SystemExit(main())
