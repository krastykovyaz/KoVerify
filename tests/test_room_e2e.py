"""Two browsers' worth of real client crypto against a live server.

Needs Node.js (WebCrypto). Skipped where it is missing, so the suite still runs
on a bare host.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import threading

import pytest
from werkzeug.serving import make_server

NODE = os.environ.get("NODE") or shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


@pytest.fixture
def live(app, admin):
    users = []
    for uid, name in (("alice-001", "Alice"), ("bob-001", "Bob")):
        payload = admin.post("/admin/api/register", json={"user_id": uid, "name": name}).get_json()
        users.append({"id": uid, "secret": payload["totp_secret"]})
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", users
    server.shutdown()


def test_two_browsers_exchange_secrets_the_server_cannot_read(live, cfg):
    base, users = live
    result = subprocess.run(
        [NODE, "tests/js/room_e2e.js"], capture_output=True, text=True, timeout=60,
        env={**os.environ, "BASE": base, "USERS": json.dumps(users)},
    )
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert "error" not in report, report.get("error")
    failed = [name for name, passed in report["checks"].items() if not passed]
    assert not failed, failed
    assert len(report["checks"]) >= 35

    conn = sqlite3.connect(cfg.db_path)
    dump = "\n".join(conn.iterdump())
    conn.close()
    for secret in report["secrets"]:
        assert secret not in dump, f"{secret!r} reached the database in the clear"
    # The shared items did reach it, as ciphertext.
    assert "room_items" in dump
