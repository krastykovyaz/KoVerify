"""Resource handling: connections must not accumulate across requests."""
import gc
import os

import pytest


def _open_db_handles(db_path):
    target = os.path.realpath(db_path)
    count = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            resolved = os.path.realpath(f"/proc/self/fd/{fd}")
        except OSError:
            continue
        # WAL and shared-memory side files count as part of the connection.
        if resolved.startswith(target):
            count += 1
    return count


@pytest.mark.parametrize("path,method", [
    ("/api/session/create", "post"),
    ("/api/nonce", "get"),
    ("/", "get"),
])
def test_requests_do_not_leak_database_handles(client, cfg, path, method):
    """The previous implementation opened a connection per call and closed none."""
    gc.disable()
    try:
        getattr(client, method)(path)          # warm up
        baseline = _open_db_handles(cfg.db_path)
        for _ in range(60):
            getattr(client, method)(path)
        after = _open_db_handles(cfg.db_path)
    finally:
        gc.enable()
    assert after <= baseline, f"leaked {after - baseline} handles over 60 requests"


def test_handles_are_released_when_a_request_raises(app, cfg):
    @app.route("/boom")
    def boom():
        from verifier.db import get_db
        get_db().execute("SELECT 1")
        raise RuntimeError("deliberate")

    client = app.test_client()
    gc.disable()
    try:
        baseline = _open_db_handles(cfg.db_path)
        for _ in range(30):
            try:
                client.get("/boom")
            except RuntimeError:
                pass
        after = _open_db_handles(cfg.db_path)
    finally:
        gc.enable()
    assert after <= baseline


def test_nonces_do_not_accumulate_forever(client, cfg):
    import sqlite3
    from datetime import datetime, timedelta, timezone

    for _ in range(5):
        client.get("/api/nonce")
    conn = sqlite3.connect(cfg.db_path)
    stale = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn.execute("UPDATE nonces SET created_at=?", (stale,))
    conn.commit()
    conn.close()

    client.get("/api/nonce")          # triggers the purge

    conn = sqlite3.connect(cfg.db_path)
    remaining = conn.execute("SELECT COUNT(*) FROM nonces").fetchone()[0]
    conn.close()
    assert remaining == 1, "expired nonces were not purged"
