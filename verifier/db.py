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
    expires_at  TEXT,
    a_token_hash TEXT,
    b_token_hash TEXT,
    a_pub       TEXT,
    b_pub       TEXT,
    a_commit    TEXT,
    b_commit    TEXT,
    video_state TEXT,
    video_by    TEXT,
    video_at    TEXT,
    closed_at   TEXT,
    a_seen_at   TEXT,
    b_seen_at   TEXT
);
CREATE TABLE IF NOT EXISTS room_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code       TEXT NOT NULL,
    from_slot  TEXT NOT NULL,
    iv         TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL
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
CREATE INDEX IF NOT EXISTS idx_room_items_code ON room_items(code);
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
    ("sessions", "a_token_hash", "TEXT"),
    ("sessions", "b_token_hash", "TEXT"),
    ("sessions", "a_pub", "TEXT"),
    ("sessions", "b_pub", "TEXT"),
    ("sessions", "video_state", "TEXT"),
    ("sessions", "video_by", "TEXT"),
    ("sessions", "video_at", "TEXT"),
    ("sessions", "closed_at", "TEXT"),
    ("sessions", "a_seen_at", "TEXT"),
    ("sessions", "b_seen_at", "TEXT"),
    ("sessions", "a_commit", "TEXT"),
    ("sessions", "b_commit", "TEXT"),
)


def init_db(path):
    """Create tables if absent. Additive only, safe against a populated database.

    Several gunicorn workers run this at the same moment. The write lock makes
    the first one do the work while the rest wait (busy_timeout), and each
    re-reads the columns once it holds the lock. Should two still collide, a
    "duplicate column" is the other worker having finished first, not an error:
    at the 2026-10-16 deploy that exact collision killed two of three workers.
    """
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.execute("BEGIN IMMEDIATE")
        for table, column, decl in _ADDED_COLUMNS:
            have = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            if column in have:
                continue
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
        conn.commit()
    finally:
        conn.close()


# Everything a room knows about the people in it. Closing a room, and a room
# running out of time, both blank all of this and keep only a bare tombstone
# (code and timestamps), so a late visitor is told "closed" instead of finding a
# stale record, and a code is not reissued while its tombstone exists.
_SCRUB = (
    "user_a=NULL, user_b=NULL, a_verified=0, b_verified=0, a_name=NULL, b_name=NULL, "
    "a_method=NULL, b_method=NULL, a_token_hash=NULL, b_token_hash=NULL, "
    "a_pub=NULL, b_pub=NULL, a_commit=NULL, b_commit=NULL, "
    "video_state=NULL, video_by=NULL, video_at=NULL, "
    "a_seen_at=NULL, b_seen_at=NULL"
)


def close_room(conn, code):
    """Delete everything in a room. Safe to call twice."""
    conn.execute("DELETE FROM room_items WHERE code=?", (code,))
    conn.execute(
        f"UPDATE sessions SET {_SCRUB}, closed_at=COALESCE(closed_at, ?) WHERE code=?",
        (utcnow().isoformat(), code),
    )


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
    # A room that has run out of time is closed exactly like one closed by hand:
    # nothing about it survives except a tombstone. This does not wait for
    # anyone to open the room again.
    conn.execute(
        f"UPDATE sessions SET {_SCRUB}, closed_at=? "
        "WHERE expires_at < ? AND closed_at IS NULL",
        (now.isoformat(), now.isoformat()),
    )
    conn.execute(
        "DELETE FROM room_items WHERE code IN "
        "(SELECT code FROM sessions WHERE closed_at IS NOT NULL) "
        "OR code NOT IN (SELECT code FROM sessions)"
    )
    # Tombstones go a day later.
    conn.execute(
        "DELETE FROM sessions WHERE expires_at < ? OR closed_at < ?",
        ((now - timedelta(days=1)).isoformat(),) * 2,
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
