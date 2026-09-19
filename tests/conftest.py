import base64
import os
import sqlite3
import sys

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from verifier import create_app                      # noqa: E402
from verifier.ca import generate_ca                  # noqa: E402
from verifier.config import Config                   # noqa: E402

ADMIN_PASSWORD = "test-admin-password-1234"
PROXY_SECRET = "test-proxy-shared-secret-value"


def make_config(tmp_path, **overrides):
    env = {
        "VERIFIER_HOME": str(tmp_path),
        "DB_PATH": str(tmp_path / "db.sqlite"),
        "CA_DIR": str(tmp_path / "ca"),
        "FLASK_SECRET": "t" * 64,
        "ADMIN_SECRET": ADMIN_PASSWORD,
        "PROXY_SHARED_SECRET": PROXY_SECRET,
    }
    env.update({k: str(v) for k, v in overrides.items()})
    return Config(env=env, testing=True)


@pytest.fixture
def cfg(tmp_path):
    config = make_config(tmp_path)
    generate_ca(config)
    return config


@pytest.fixture
def app(cfg):
    return create_app(cfg, testing=True)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin(client):
    """A client session already logged into the admin panel."""
    response = client.post("/admin/login", data={"password": ADMIN_PASSWORD})
    assert response.status_code in (302, 303)
    return client


class User:
    def __init__(self, payload, private_key):
        self.payload = payload
        self.private_key = private_key
        self.id = payload["user_id"]
        self.name = payload["name"]
        self.cert_pem = payload["cert_pem"]
        self.download_url = payload["download_url"]
        self.token = payload["download_url"].rsplit("/", 1)[-1]

    def sign(self, nonce):
        signature = self.private_key.sign(
            nonce.encode(), padding.PKCS1v15(), hashes.SHA256()
        )
        return base64.b64encode(signature).decode()


def register(admin_client, db_path, user_id="alice-001", name="Alice Example"):
    response = admin_client.post(
        "/admin/api/register", json={"user_id": user_id, "name": name}
    )
    payload = response.get_json()
    assert payload["ok"], payload
    # Recover the private key from the stored bundle, the way the enrolled
    # device would after installing it. Read from the database directly so the
    # one-time download link stays unspent for the tests that exercise it.
    conn = sqlite3.connect(db_path)
    blob = base64.b64decode(
        conn.execute("SELECT p12_b64 FROM users WHERE id=?", (user_id,)).fetchone()[0]
    )
    conn.close()
    key, _cert, _chain = pkcs12.load_key_and_certificates(
        blob, payload["p12_password"].encode()
    )
    return User(payload, key)


@pytest.fixture
def user(admin, cfg):
    return register(admin, cfg.db_path)


@pytest.fixture
def session_code(client):
    return client.post("/api/session/create").get_json()["code"]


def nonce_for(client):
    return client.get("/api/nonce").get_json()["nonce"]


def pem_of(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()
