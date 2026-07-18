"""
BugKit v4 — Schema Migration System

Lightweight, Alembic-inspired migration runner that works with the
existing SQLAlchemy setup but requires NO external Alembic install.

How it works:
  1. A `_schema_version` table tracks applied migrations by number.
  2. Each migration is a plain function that receives a sqlite3 connection.
  3. `migrate()` is called at startup — idempotent, safe to run repeatedly.
  4. New migrations are added to the MIGRATIONS list below.

Usage (called automatically from db/queries.py on first get_db()):
    from db.migrations import migrate
    migrate(str(settings.db_path))
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable, List, Tuple

from core import logger


# ── Migration registry ─────────────────────────────────────────────────
# Each entry: (version_number, description, migration_fn)
# migration_fn receives a sqlite3.Connection.  Use execute() directly.
# NEVER remove or reorder existing entries — only append.

MigrationFn = Callable[[sqlite3.Connection], None]


def _m001_initial_schema(conn: sqlite3.Connection) -> None:
    """Create all v4.0.0 tables if they don't exist yet."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            domain     TEXT    NOT NULL UNIQUE,
            base_url   TEXT,
            scope      TEXT,
            tech       TEXT,
            notes      TEXT,
            created_at TEXT    DEFAULT (datetime('now')),
            updated_at TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS identities (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            name       TEXT    NOT NULL,
            role       TEXT    NOT NULL DEFAULT 'user',
            secrets    TEXT,
            note       TEXT,
            verified   INTEGER NOT NULL DEFAULT 0,
            created_at TEXT    DEFAULT (datetime('now')),
            UNIQUE (target_id, name)
        );

        CREATE TABLE IF NOT EXISTS endpoints (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            url           TEXT    NOT NULL,
            method        TEXT    NOT NULL DEFAULT 'GET',
            params        TEXT,
            auth_required INTEGER,
            status_code   INTEGER,
            content_type  TEXT,
            source        TEXT,
            first_seen    TEXT    DEFAULT (datetime('now')),
            last_seen     TEXT    DEFAULT (datetime('now')),
            UNIQUE (target_id, url, method)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            module       TEXT    NOT NULL,
            title        TEXT    NOT NULL,
            severity     TEXT    NOT NULL,
            confidence   TEXT    NOT NULL DEFAULT 'medium',
            url          TEXT    NOT NULL,
            method       TEXT,
            parameter    TEXT,
            payload      TEXT,
            evidence     TEXT,
            raw_request  TEXT,
            raw_response TEXT,
            curl_poc     TEXT,
            repro_steps  TEXT,
            detail       TEXT,
            impact       TEXT,
            remediation  TEXT,
            cwe          TEXT,
            cvss         REAL,
            tags         TEXT,
            screenshot   TEXT,
            duplicate_of INTEGER REFERENCES findings(id),
            created_at   TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            module      TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'running',
            findings_n  INTEGER NOT NULL DEFAULT 0,
            started_at  TEXT    DEFAULT (datetime('now')),
            ended_at    TEXT,
            meta        TEXT
        );

        CREATE TABLE IF NOT EXISTS snapshots (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            url        TEXT    NOT NULL,
            sha256     TEXT    NOT NULL,
            body_size  INTEGER NOT NULL,
            status     INTEGER NOT NULL,
            headers    TEXT,
            taken_at   TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS workflows (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL,
            description TEXT,
            steps       TEXT,
            created_at  TEXT    DEFAULT (datetime('now')),
            UNIQUE (target_id, name)
        );

        CREATE TABLE IF NOT EXISTS objects (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            kind       TEXT    NOT NULL,
            object_id  TEXT    NOT NULL,
            owner      TEXT,
            url        TEXT,
            meta       TEXT,
            created_at TEXT    DEFAULT (datetime('now'))
        );
    """)


def _m002_add_confidence_index(conn: sqlite3.Connection) -> None:
    """Add performance index on findings(target_id, severity, confidence)."""
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_findings_target_sev
        ON findings (target_id, severity, confidence)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_endpoints_target_url
        ON endpoints (target_id, url)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_snapshots_target_url
        ON snapshots (target_id, url, taken_at)
    """)


def _m003_add_oauth_tokens_table(conn: sqlite3.Connection) -> None:
    """Add oauth_flows table for OAuth/OIDC test session tracking."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oauth_flows (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id     INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            identity_name TEXT    NOT NULL,
            flow_type     TEXT    NOT NULL,   -- authorization_code | implicit | pkce
            state         TEXT,
            nonce         TEXT,
            code          TEXT,
            access_token  TEXT,
            refresh_token TEXT,
            id_token      TEXT,
            redirect_uri  TEXT,
            created_at    TEXT DEFAULT (datetime('now'))
        )
    """)


def _m004_add_massassign_fields(conn: sqlite3.Connection) -> None:
    """Add mass_assignment_results table."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS massassign_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            url         TEXT    NOT NULL,
            method      TEXT    NOT NULL,
            field_name  TEXT    NOT NULL,
            field_value TEXT,
            accepted    INTEGER NOT NULL DEFAULT 0,
            response_snippet TEXT,
            tested_at   TEXT DEFAULT (datetime('now'))
        )
    """)


def _m005_add_ratelimit_results(conn: sqlite3.Connection) -> None:
    """Add ratelimit_results table for structured rate limit findings."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ratelimit_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            url          TEXT    NOT NULL,
            identity     TEXT,
            burst_size   INTEGER NOT NULL,
            hit_429      INTEGER NOT NULL DEFAULT 0,
            threshold    INTEGER,
            tested_at    TEXT DEFAULT (datetime('now'))
        )
    """)


# ── Master registry ────────────────────────────────────────────────────

MIGRATIONS: List[Tuple[int, str, MigrationFn]] = [
    (1, "initial schema",           _m001_initial_schema),
    (2, "add performance indexes",  _m002_add_confidence_index),
    (3, "add oauth_flows table",    _m003_add_oauth_tokens_table),
    (4, "add massassign_results",   _m004_add_massassign_fields),
    (5, "add ratelimit_results",    _m005_add_ratelimit_results),
]


# ── Runner ─────────────────────────────────────────────────────────────

def migrate(db_path: str) -> None:
    """
    Apply all pending migrations to the database at `db_path`.
    Safe to call on every startup — skips already-applied migrations.
    """
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # Create version tracking table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS _schema_version (
            version     INTEGER PRIMARY KEY,
            description TEXT,
            applied_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()

    # Find current version
    current = conn.execute(
        "SELECT COALESCE(MAX(version), 0) FROM _schema_version"
    ).fetchone()[0]

    applied = 0
    for version, description, fn in MIGRATIONS:
        if version <= current:
            continue
        try:
            fn(conn)
            conn.execute(
                "INSERT INTO _schema_version (version, description) VALUES (?, ?)",
                (version, description),
            )
            conn.commit()
            applied += 1
            logger.debug(f"Migration {version} applied: {description}")
        except Exception as e:
            conn.rollback()
            logger.err(f"Migration {version} failed: {e}")
            raise

    conn.close()

    if applied:
        logger.ok(f"Database migrated: {applied} migration(s) applied (schema v{current + applied}).")
    else:
        logger.debug(f"Database schema up to date (v{current}).")


def current_version(db_path: str) -> int:
    """Return the current schema version of the database."""
    try:
        conn = sqlite3.connect(db_path)
        v = conn.execute(
            "SELECT COALESCE(MAX(version), 0) FROM _schema_version"
        ).fetchone()[0]
        conn.close()
        return v
    except Exception:
        return 0
