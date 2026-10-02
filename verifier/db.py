"""SQLite access bound to the Flask application context.

Every connection opened here is closed when the request context tears down,
which is what stops the file-descriptor leak the previous implementation had.
"""
import sqlite3
from datetime import datetime, timezone, timedelta

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    totp_secret  TEXT,
    cert_pem     TEXT,
    serial       TEXT,
    p12_b64      TEXT,
    revoked      INTEGER DEFAULT 0,
    created_at   TEXT,
    totp_last_step INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    code        TEXT PRIMARY KEY,
    user_a      TEXT,
    user_b      TEXT,
    a_verified  INTEGER DEFAULT 0,
    b_verified  INTEGER DEFAULT 0,
    a_name      TEXT,
    b_name      TEXT,
    a_method    TEXT,
    b_method    TEXT,
    created_at  TEXT,
    expires_at  TEXT
);
CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS download_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    used       INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket     TEXT NOT NULL,
    identifier TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_serial ON users(serial);
CREATE INDEX IF NOT EXISTS idx_rl_lookup ON rate_limits(bucket, identifier, attempted_at);
CREATE INDEX IF NOT EXISTS idx_nonces_created ON nonces(created_at);
CREATE INDEX IF NOT EXISTS idx_dt_user ON download_tokens(user_id);
"""


def utcnow():
    return datetime.now(timezone.utc)


def parse_ts(raw):
    """Parse a stored timestamp, tolerating naive values written by old code."""
    if raw is None:
        return None
    value = datetime.fromisoformat(raw)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def get_db():
    """Return the connection for this request, opening it on first use."""
    if "db" not in g:
        g.db = connect(current_app.config["VERIFIER"].db_path)
    return g.db


def close_db(exc=None):
    conn = g.pop("db", None)
    if conn is None:
        return
    try:
        if exc is None:
            conn.commit()
        else:
            conn.rollback()
    finally:
        conn.close()


# Columns added after the first release. Each is applied only when missing, so
# a populated production database upgrades in place.
_ADDED_COLUMNS = (
    ("users", "totp_last_step", "INTEGER"),
)


def init_db(path):
    """Create tables if absent. Additive only, safe against a populated database."""
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        for table, column, decl in _ADDED_COLUMNS:
            have = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            if column not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        conn.commit()
    finally:
        conn.close()


def purge_expired(conn, nonce_ttl_seconds):
    """Delete rows that are past their useful life. Keeps the tables bounded."""
    now = utcnow()
    conn.execute(
        "DELETE FROM nonces WHERE created_at < ?",
        ((now - timedelta(seconds=nonce_ttl_seconds)).isoformat(),),
    )
    conn.execute(
        "DELETE FROM rate_limits WHERE attempted_at < ?",
        ((now - timedelta(hours=24)).isoformat(),),
    )
    conn.execute(
        "DELETE FROM sessions WHERE expires_at < ?",
        ((now - timedelta(days=1)).isoformat(),),
    )
    # The private-key bundle is only needed until the one-time link is spent or
    # lapses. Keeping it longer just leaves a second copy of every user's key
    # in the database and in every backup of it.
    conn.execute(
        "UPDATE users SET p12_b64=NULL WHERE p12_b64 IS NOT NULL AND NOT EXISTS ("
        "  SELECT 1 FROM download_tokens t WHERE t.user_id=users.id "
        "  AND t.used=0 AND t.expires_at >= ?)",
        (now.isoformat(),),
    )
