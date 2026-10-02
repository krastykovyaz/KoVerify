"""Authentication helpers: constant-time comparison and durable rate limiting."""
import hmac
import ipaddress
import time
from datetime import timedelta
from functools import wraps

from flask import current_app, jsonify, redirect, request, session, url_for

from .db import get_db, utcnow


def constant_time_equals(a, b):
    if a is None or b is None:
        return False
    return hmac.compare_digest(str(a).encode(), str(b).encode())


def _proxy_vouched_for(cfg):
    """True when the request provably came through our own nginx.

    Over TCP that means a configured proxy address. Over a unix socket there
    is no peer address at all, so the shared secret that only nginx knows is
    the proof; with no secret configured, socket permissions are the control.
    """
    peer = request.remote_addr or ""
    if peer:
        return peer in cfg.trusted_proxies
    if not cfg.proxy_shared_secret:
        return True
    return constant_time_equals(
        request.headers.get("X-Proxy-Auth"), cfg.proxy_shared_secret
    )


def client_ip():
    """The caller's address, for rate limiting.

    Behind the unix socket REMOTE_ADDR is empty, so without this every caller
    shared one "unknown" bucket and a single stranger could lock everyone out.
    nginx overwrites X-Real-IP with the true address; it is believed only when
    the request provably came through nginx. X-Forwarded-For is never used: a
    client can prepend its own entry to it even through a trusted proxy.
    """
    cfg = current_app.config["VERIFIER"]
    peer = request.remote_addr or ""
    if _proxy_vouched_for(cfg):
        candidate = request.headers.get("X-Real-IP", "").strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    return peer or "unknown"


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
        cfg = current_app.config["VERIFIER"]
        started = session.get("admin_at")
        fresh = (
            session.get("is_admin")
            and isinstance(started, int)
            and 0 <= time.time() - started <= cfg.admin_session_minutes * 60
        )
        if not fresh:
            session.clear()
            if request.path.startswith("/admin/api/"):
                return jsonify({"ok": False, "reason": "требуется вход"}), 401
            return redirect(url_for("admin.admin_login"))
        return f(*args, **kwargs)

    return decorated
