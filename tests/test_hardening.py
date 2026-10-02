"""Regressions for the defects found in the 2026-10-02 audit."""
import base64
import re
import sqlite3
import time

import pyotp
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from conftest import ADMIN_PASSWORD, PROXY_SECRET, make_config, register
from verifier import ConfigError, create_app
from verifier.ca import generate_ca
from verifier.db import init_db, purge_expired, utcnow
from verifier.totp import match_step

# gunicorn on a unix socket reports an empty peer address.
UNIX = {"REMOTE_ADDR": ""}
NGINX = {"X-Proxy-Auth": PROXY_SECRET}


def rl_identities(cfg):
    conn = sqlite3.connect(cfg.db_path)
    rows = conn.execute("SELECT DISTINCT identifier FROM rate_limits").fetchall()
    conn.close()
    return {r[0] for r in rows}


# ── client address behind the unix socket ──────────────────────────────

def test_each_client_gets_its_own_rate_limit_identity(app, cfg):
    """Every caller used to share the single identity 'unknown'."""
    for ip in ("198.51.100.7", "203.0.113.9"):
        app.test_client().post(
            "/api/session/create", environ_base=UNIX,
            headers={**NGINX, "X-Real-IP": ip},
        )
    assert rl_identities(cfg) == {"198.51.100.7", "203.0.113.9"}


def test_forged_forwarded_for_cannot_pick_the_identity(app, cfg):
    """nginx used to append to X-Forwarded-For, so its first entry was the
    client's own claim. It is never read now."""
    app.test_client().post(
        "/api/session/create", environ_base=UNIX,
        headers={**NGINX, "X-Real-IP": "198.51.100.7",
                 "X-Forwarded-For": "192.0.2.99, 198.51.100.7"},
    )
    assert rl_identities(cfg) == {"198.51.100.7"}


def test_real_ip_is_ignored_without_the_proxy_secret(app, cfg):
    app.test_client().post(
        "/api/session/create", environ_base=UNIX, headers={"X-Real-IP": "192.0.2.50"},
    )
    assert rl_identities(cfg) == {"unknown"}


def test_real_ip_is_ignored_from_an_untrusted_peer(app, cfg):
    app.test_client().post(
        "/api/session/create", environ_base={"REMOTE_ADDR": "203.0.113.9"},
        headers={**NGINX, "X-Real-IP": "192.0.2.50"},
    )
    assert rl_identities(cfg) == {"203.0.113.9"}


def test_garbage_real_ip_falls_back_instead_of_being_stored(app, cfg):
    app.test_client().post(
        "/api/session/create", environ_base=UNIX,
        headers={**NGINX, "X-Real-IP": "not-an-ip'; DROP TABLE users;--"},
    )
    assert rl_identities(cfg) == {"unknown"}


def test_a_stranger_cannot_lock_the_admin_out(app):
    attacker, owner = app.test_client(), app.test_client()
    for _ in range(6):
        attacker.post("/admin/login", data={"password": "wrong"},
                      environ_base=UNIX, headers={**NGINX, "X-Real-IP": "198.51.100.7"})
    response = owner.post("/admin/login", data={"password": ADMIN_PASSWORD},
                          environ_base=UNIX, headers={**NGINX, "X-Real-IP": "203.0.113.9"})
    assert response.status_code == 302


def test_nginx_snippet_overwrites_client_address_headers():
    snippet = open("deploy/nginx-proxy-headers.conf").read()
    assert "proxy_add_x_forwarded_for" not in snippet.replace("# ", "").split("\n\n", 1)[1]
    assert re.search(r"proxy_set_header X-Real-IP\s+\$remote_addr;", snippet)
    assert re.search(r"proxy_set_header X-Forwarded-For\s+\$remote_addr;", snippet)


# ── TOTP replay ────────────────────────────────────────────────────────

def test_match_step_reports_the_step_and_honours_the_window():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    now = 1_800_000_000
    code = totp.at(now)
    assert match_step(secret, code, now=now) == now // 30
    assert match_step(secret, code, now=now + 30) == now // 30
    assert match_step(secret, code, now=now + 90) is None
    assert match_step(secret, "000000", now=now) in (None, now // 30)
    assert match_step(secret, "", now=now) is None


def test_a_totp_code_works_once(app, user):
    secret = user.payload["totp_secret"]
    client = app.test_client()
    first = client.post("/api/session/create").get_json()["code"]
    second = client.post("/api/session/create").get_json()["code"]
    code = pyotp.TOTP(secret).now()
    ok = client.post(f"/api/session/{first}/verify/totp",
                     json={"user_id": user.id, "code": code}).get_json()
    replay = client.post(f"/api/session/{second}/verify/totp",
                         json={"user_id": user.id, "code": code}).get_json()
    assert ok["ok"] is True
    assert replay["ok"] is False and "использован" in replay["reason"]


def test_an_older_code_cannot_follow_a_newer_one(app, user):
    secret = user.payload["totp_secret"]
    totp = pyotp.TOTP(secret)
    now = time.time()
    client = app.test_client()
    codes = [client.post("/api/session/create").get_json()["code"] for _ in range(2)]
    newer, older = totp.at(now + 30), totp.at(now - 30)
    assert client.post(f"/api/session/{codes[0]}/verify/totp",
                       json={"user_id": user.id, "code": newer}).get_json()["ok"]
    assert not client.post(f"/api/session/{codes[1]}/verify/totp",
                           json={"user_id": user.id, "code": older}).get_json()["ok"]


def test_existing_database_gains_the_replay_column(tmp_path):
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, "
                 "totp_secret TEXT, cert_pem TEXT, serial TEXT, p12_b64 TEXT, "
                 "revoked INTEGER DEFAULT 0, created_at TEXT)")
    conn.execute("INSERT INTO users (id, name) VALUES ('keep', 'Kept User')")
    conn.commit(); conn.close()
    init_db(str(path)); init_db(str(path))          # idempotent
    conn = sqlite3.connect(path)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(users)")]
    assert "totp_last_step" in cols
    assert conn.execute("SELECT name FROM users").fetchone()[0] == "Kept User"


# ── private keys are not kept ──────────────────────────────────────────

def stored_bundle(cfg, user_id):
    conn = sqlite3.connect(cfg.db_path)
    value = conn.execute("SELECT p12_b64 FROM users WHERE id=?", (user_id,)).fetchone()[0]
    conn.close()
    return value


def test_private_key_is_wiped_once_delivered(client, user, cfg):
    assert stored_bundle(cfg, user.id)
    assert client.get(f"/download/{user.token}/p12").status_code == 200
    assert stored_bundle(cfg, user.id) is None


def test_private_key_is_wiped_after_the_profile_download_too(client, user, cfg):
    assert client.get(f"/download/{user.token}/mobileconfig").status_code == 200
    assert stored_bundle(cfg, user.id) is None


def test_expired_unspent_links_lose_their_bundle(client, user, cfg):
    conn = sqlite3.connect(cfg.db_path)
    conn.execute("UPDATE download_tokens SET expires_at='2000-01-01T00:00:00+00:00'")
    conn.commit(); conn.close()
    client.post("/api/session/create")               # runs the purge
    assert stored_bundle(cfg, user.id) is None


def test_a_live_unspent_link_keeps_its_bundle(client, user, cfg):
    client.post("/api/session/create")
    assert stored_bundle(cfg, user.id)


# ── reissue ────────────────────────────────────────────────────────────

def load_key(cfg, user_id, password):
    blob = base64.b64decode(stored_bundle(cfg, user_id))
    return pkcs12.load_key_and_certificates(blob, password.encode())[0]


def challenge(client, session, cert_pem, key, user_id=None):
    nonce = client.get("/api/nonce").get_json()["nonce"]
    sig = base64.b64encode(key.sign(nonce.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()
    return client.post(f"/api/session/{session}/verify/cert", json={
        "user_id": user_id, "cert_pem": cert_pem, "nonce": nonce, "signature_b64": sig,
    }).get_json()


def test_reissue_replaces_the_certificate_and_kills_the_old_one(admin, user, cfg, client):
    # The delivery "failed": the link was spent and the key wiped.
    client.get(f"/download/{user.token}/p12")
    assert stored_bundle(cfg, user.id) is None

    fresh = admin.post("/admin/api/reissue", json={"user_id": user.id}).get_json()
    assert fresh["ok"] and fresh["serial"] != user.payload["serial"]
    assert fresh["totp_secret"] == user.payload["totp_secret"]
    assert fresh["download_url"] != user.download_url
    new_key = load_key(cfg, user.id, fresh["p12_password"])

    session = client.post("/api/session/create").get_json()["code"]
    old = challenge(client, session, user.cert_pem, user.private_key, user.id)
    assert old["ok"] is False
    session2 = client.post("/api/session/create").get_json()["code"]
    assert challenge(client, session2, fresh["cert_pem"], new_key, user.id)["ok"] is True


def test_reissue_retires_the_previous_download_link(admin, user, client):
    fresh = admin.post("/admin/api/reissue", json={"user_id": user.id}).get_json()
    assert client.get(f"/download/{user.token}/p12").status_code == 410
    assert client.get(fresh["download_url"].rsplit("/", 1)[-1].join(["/download/", "/p12"])).status_code == 200


def test_reissue_needs_a_known_unrevoked_user_and_an_admin(admin, user, client):
    assert admin.post("/admin/api/reissue", json={"user_id": "nobody"}).status_code == 404
    admin.post("/admin/api/revoke", json={"user_id": user.id})
    assert admin.post("/admin/api/reissue", json={"user_id": user.id}).get_json()["ok"] is False
    assert app_client_without_login(client).status_code == 401


def app_client_without_login(client):
    fresh = client.application.test_client()
    return fresh.post("/admin/api/reissue", json={"user_id": "x"})


# ── names, sessions, pages ─────────────────────────────────────────────

@pytest.mark.parametrize("name", ["<img src=x onerror=alert(1)>", "a<b", "tab\there", "bell\x07"])
def test_register_refuses_markup_and_control_characters(admin, name):
    assert admin.post("/admin/api/register",
                      json={"user_id": "xss-1", "name": name}).get_json()["ok"] is False


def test_register_still_accepts_ordinary_names(admin):
    for i, name in enumerate(["O'Brien", "Алиса Иванова", "Zoë Müller-Smith"]):
        assert admin.post("/admin/api/register",
                          json={"user_id": f"ok-{i}", "name": name}).get_json()["ok"], name


def test_admin_login_expires_server_side(admin):
    assert admin.get("/admin/").status_code == 200
    with admin.session_transaction() as sess:
        sess["admin_at"] = int(time.time()) - 24 * 3600
    assert admin.get("/admin/api/user/x").status_code == 401
    assert admin.get("/admin/").status_code == 302


def test_old_cookie_without_a_timestamp_is_not_an_admin_session(client):
    with client.session_transaction() as sess:
        sess["is_admin"] = True
    assert client.get("/admin/api/user/x").status_code == 401


def test_logout_is_post_only(admin):
    assert admin.get("/admin/logout").status_code == 405
    assert admin.post("/admin/logout").status_code == 302
    assert admin.get("/admin/api/user/x").status_code == 401


@pytest.mark.parametrize("path", [
    "/session/short", "/session/ABCD234", "/session/ABCD23456",
    "/session/abcd2345", "/session/ABCD234O", "/session/AB%5C%0Aalert(1)",
    "/result/short",
])
def test_malformed_session_codes_are_rejected_not_rendered(client, path):
    response = client.get(path)
    assert response.status_code == 404
    assert "const CODE" not in response.get_data(as_text=True)


def test_well_formed_codes_render_with_a_json_encoded_value(client):
    body = client.get("/session/ABCD2345").get_data(as_text=True)
    assert 'const CODE = "ABCD2345"' in body


def test_templates_escape_names_before_using_innerhtml():
    for path in ("templates/verify.html", "templates/admin.html"):
        text = open(path).read()
        assert "function esc(" in text, path
    assert "<strong>${data.name}</strong>" not in open("templates/verify.html").read()
    admin_html = open("templates/admin.html").read()
    assert '<div class="user-name">${data.name}</div>' not in admin_html
    assert '<div class="user-id">${data.user_id}</div>' not in admin_html


# ── CA health at startup ───────────────────────────────────────────────

def test_app_refuses_to_start_on_a_ca_that_cannot_validate_itself(tmp_path):
    cfg = make_config(tmp_path)
    key, cert = generate_ca(cfg)
    subject = cert.subject
    wrong_issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)])
    broken = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(wrong_issuer)
        .public_key(key.public_key()).serial_number(cert.serial_number)
        .not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(cfg.ca_cert_path, "wb") as f:
        f.write(broken.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(ConfigError, match="issuer does not match"):
        create_app(cfg, testing=True)


def test_app_refuses_a_key_that_does_not_belong_to_the_certificate(tmp_path):
    cfg = make_config(tmp_path)
    generate_ca(cfg)
    other = make_config(tmp_path / "other")
    (tmp_path / "other").mkdir()
    generate_ca(other)
    with open(other.ca_key_path, "rb") as src, open(cfg.ca_key_path, "wb") as dst:
        dst.write(src.read())
    with pytest.raises(ConfigError, match="does not belong"):
        create_app(cfg, testing=True)


def test_a_healthy_ca_starts_normally(tmp_path):
    cfg = make_config(tmp_path)
    generate_ca(cfg)
    assert create_app(cfg, testing=True) is not None


def test_a_passphrase_that_does_not_fit_the_key_is_a_clear_startup_error(tmp_path):
    cfg = make_config(tmp_path)
    generate_ca(cfg)                                   # key written unencrypted
    mismatched = make_config(tmp_path, CA_PASSPHRASE="a-passphrase-the-key-does-not-have")
    with pytest.raises(ConfigError, match="CA_PASSPHRASE"):
        create_app(mismatched, testing=True)


def test_an_encrypted_ca_key_works_with_its_passphrase(tmp_path):
    cfg = make_config(tmp_path, CA_PASSPHRASE="correct horse battery staple")
    generate_ca(cfg)
    assert b"ENCRYPTED" in open(cfg.ca_key_path, "rb").read()
    assert create_app(cfg, testing=True) is not None
    wrong = make_config(tmp_path, CA_PASSPHRASE="wrong")
    with pytest.raises(ConfigError, match="CA_PASSPHRASE"):
        create_app(wrong, testing=True)
