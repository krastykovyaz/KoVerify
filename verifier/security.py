"""Authentication helpers: constant-time comparison and durable rate limiting."""
import hmac
from datetime import timedelta
from functools import wraps

from flask import current_app, jsonify, redirect, request, session, url_for

from .db import get_db, utcnow


def constant_time_equals(a, b):
    if a is None or b is None:
        return False
    return hmac.compare_digest(str(a).encode(), str(b).encode())


def client_ip():
    """The caller's address.

    X-Forwarded-For is only honoured when the immediate peer is a trusted
    proxy, so a hostile client cannot forge its own rate-limit identity.
    """
    cfg = current_app.config["VERIFIER"]
    peer = request.remote_addr or "unknown"
    if peer in cfg.trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return peer


def rate_limit(bucket, identifier, limit_spec):
    """Record an attempt and report whether the caller is over the limit.

    Returns (allowed, retry_after_seconds).
    """
    max_attempts, window_seconds = limit_spec
    conn = get_db()
    now = utcnow()
    cutoff = (now - timedelta(seconds=window_seconds)).isoformat()

    conn.execute(
        "DELETE FROM rate_limits WHERE bucket=? AND identifier=? AND attempted_at < ?",
        (bucket, identifier, cutoff),
    )
    row = conn.execute(
        "SELECT COUNT(*) AS n, MIN(attempted_at) AS oldest FROM rate_limits "
        "WHERE bucket=? AND identifier=?",
        (bucket, identifier),
    ).fetchone()

    if row["n"] >= max_attempts:
        oldest = row["oldest"]
        retry = window_seconds
        if oldest:
            from .db import parse_ts
            elapsed = (now - parse_ts(oldest)).total_seconds()
            retry = max(1, int(window_seconds - elapsed))
        return False, retry

    conn.execute(
        "INSERT INTO rate_limits (bucket, identifier, attempted_at) VALUES (?,?,?)",
        (bucket, identifier, now.isoformat()),
    )
    conn.commit()
    return True, 0


def clear_rate_limit(bucket, identifier):
    conn = get_db()
    conn.execute(
        "DELETE FROM rate_limits WHERE bucket=? AND identifier=?", (bucket, identifier)
    )
    conn.commit()


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            if request.path.startswith("/admin/api/"):
                return jsonify({"ok": False, "reason": "требуется вход"}), 401
            return redirect(url_for("admin.admin_login"))
        return f(*args, **kwargs)

    return decorated
