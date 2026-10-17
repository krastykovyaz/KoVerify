"""The room pages, driven in simulated browsers against a live server.

Covers the real HTML and scripts with a real DOM and real WebCrypto: sharing,
video verification, closing, notifications and the seat token. It needs Node.js
(24+, for node:sqlite) and jsdom; without them it is skipped, so the suite still
runs on a bare host. To enable:

    cd tests/js && npm install
"""
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from verifier.db import utcnow

NODE = os.environ.get("NODE") or shutil.which("node")
JSDOM = os.environ.get("JSDOM_DIR") or str(Path("tests/js/node_modules/jsdom").resolve())

pytestmark = pytest.mark.skipif(
    NODE is None or not Path(JSDOM).exists(),
    reason="needs node and jsdom (cd tests/js && npm install)",
)

SCENARIOS = ["ui_verify.js", "ui_sharing.js", "ui_video.js", "ui_close.js", "ui_notify.js", "ui_tamper.js"]


@pytest.fixture
def live(app, admin, cfg, tmp_path):
    users = []
    for uid, name in (("maria-001", "Maria"), ("ivan-001", "Ivan")):
        payload = admin.post("/admin/api/register", json={"user_id": uid, "name": name}).get_json()
        users.append({"id": uid, "secret": payload["totp_secret"]})
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Lets a script ask for a room to be expired, without the script needing sqlite.
    flag, done = tmp_path / "expire.flag", tmp_path / "expire.done"

    def expirer():
        while not flag.exists():
            time.sleep(0.1)
        conn = sqlite3.connect(cfg.db_path, timeout=10)
        conn.execute("UPDATE sessions SET expires_at=? WHERE code=?",
                     ((utcnow() - timedelta(minutes=1)).isoformat(), flag.read_text().strip()))
        conn.commit(); conn.close()
        done.write_text("1")

    threading.Thread(target=expirer, daemon=True).start()
    env = {**os.environ, "BASE": f"http://127.0.0.1:{server.server_port}", "USERS": json.dumps(users),
           "JSDOM_DIR": JSDOM, "DB_PATH": cfg.db_path, "EXPIRE_FLAG": str(flag), "EXPIRE_DONE": str(done)}
    yield env
    server.shutdown()


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_page_scenario(live, scenario):
    result = subprocess.run([NODE, "--no-warnings", f"tests/js/{scenario}"], capture_output=True,
                            text=True, env=live, timeout=150)
    lines = [l for l in result.stdout.splitlines() if l.startswith(("PASS ", "FAIL ", "ERROR"))]
    failures = [l for l in lines if not l.startswith("PASS ")]
    assert not failures, "\n".join(failures)
    assert result.returncode == 0, result.stderr[-800:]
    assert sum(l.startswith("PASS ") for l in lines) >= 4, "scenario ran too few checks"
