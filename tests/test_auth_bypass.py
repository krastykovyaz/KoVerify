"""The reported vulnerability: authenticating with only a forged header.

A certificate is public information. Holding a copy must never be enough to
verify as its owner, and a header from an untrusted client must never be
treated as the outcome of a TLS handshake.

nginx forwards the certificate percent-encoded via $ssl_client_escaped_cert,
so that is the encoding an attacker would imitate.
"""
from urllib.parse import quote

import pytest

from conftest import PROXY_SECRET, make_config, register
from verifier import create_app
from verifier.ca import generate_ca

# An address that is not in TRUSTED_PROXIES: an ordinary client on the internet.
OUTSIDE = {"REMOTE_ADDR": "203.0.113.9"}
BEHIND_PROXY = {"REMOTE_ADDR": "127.0.0.1"}


def _app_with(tmp_path, **overrides):
    cfg = make_config(tmp_path, **overrides)
    generate_ca(cfg)
    return create_app(cfg, testing=True), cfg


def _enrol(app, cfg, user_id="alice-001"):
    client = app.test_client()
    client.post("/admin/login", data={"password": "test-admin-password-1234"})
    return register(client, cfg.db_path, user_id=user_id)


def _encodings(pem):
    """Every plausible way an attacker could squeeze a PEM into a header."""
    return {
        "percent-encoded": quote(pem),
        "newlines-stripped": pem.replace("\n", ""),
        "literal-escapes": pem.replace("\n", "\\n"),
    }


@pytest.mark.parametrize("mode", ["off", "proxy", "direct"])
def test_outside_caller_cannot_authenticate_with_a_stolen_certificate(tmp_path, mode):
    """The exact payload that defeated the previous implementation."""
    app, cfg = _app_with(tmp_path, MTLS_MODE=mode, TRUSTED_PROXIES="127.0.0.1")
    user = _enrol(app, cfg)
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]

    for label, encoded in _encodings(user.cert_pem).items():
        for header in ("X-SSL-Client-Cert", "SSL-CLIENT-CERT", "X-Ssl-Client-Cert"):
            body = client.post(
                f"/api/session/{code}/verify/mtls",
                headers={header: encoded, "X-SSL-Client-Verify": "SUCCESS"},
                json={}, environ_base=OUTSIDE,
            ).get_json()
            assert body["ok"] is False, f"{header}/{label} authenticated in mode {mode}"

    status = client.get(f"/api/session/{code}/status").get_json()
    assert status["side_a"]["verified"] is False
    assert status["side_b"]["verified"] is False


@pytest.mark.parametrize("mode", ["off", "proxy", "direct"])
def test_verify_header_alone_never_authenticates(tmp_path, mode):
    """No certificate at all, just the 'handshake succeeded' assertion."""
    app, cfg = _app_with(tmp_path, MTLS_MODE=mode, TRUSTED_PROXIES="127.0.0.1")
    _enrol(app, cfg)
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]

    body = client.post(f"/api/session/{code}/verify/mtls", json={}, headers={
        "X-SSL-Client-Verify": "SUCCESS",
        "X-SSL-Client-S-DN": "SERIALNUMBER=alice-001,CN=Alice Example",
        "X-SSL-Client-Serial": "00",
    }, environ_base=BEHIND_PROXY).get_json()
    assert body["ok"] is False


def test_proxy_reporting_no_handshake_is_refused(tmp_path):
    """nginx sets Verify to NONE on public routes. That must end the attempt.

    This is the path a real attacker takes: their headers reach the app from
    the proxy's address, but the proxy has overwritten the verdict.
    """
    app, cfg = _app_with(tmp_path, MTLS_MODE="proxy", TRUSTED_PROXIES="127.0.0.1")
    user = _enrol(app, cfg)
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]

    body = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "NONE",
                 "X-SSL-Client-Cert": quote(user.cert_pem)},
        json={}, environ_base=BEHIND_PROXY,
    ).get_json()
    assert body["ok"] is False


def test_proxy_headers_rejected_from_untrusted_peer(tmp_path):
    app, cfg = _app_with(tmp_path, MTLS_MODE="proxy", TRUSTED_PROXIES="10.1.2.3")
    user = _enrol(app, cfg)
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]

    body = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "SUCCESS",
                 "X-SSL-Client-Cert": quote(user.cert_pem)},
        json={}, environ_base=OUTSIDE,
    ).get_json()
    assert body["ok"] is False
    assert "доверенного прокси" in body["reason"]


def test_proxy_mode_accepts_a_genuine_handshake(tmp_path):
    """The legitimate path still works: trusted peer, SUCCESS, valid cert."""
    app, cfg = _app_with(tmp_path, MTLS_MODE="proxy", TRUSTED_PROXIES="127.0.0.1")
    user = _enrol(app, cfg)
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]

    body = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "SUCCESS",
                 "X-SSL-Client-Cert": quote(user.cert_pem),
                 "X-Proxy-Auth": PROXY_SECRET},
        json={}, environ_base=BEHIND_PROXY,
    ).get_json()
    assert body["ok"] is True, body
    assert body["name"] == user.name


def test_proxy_mode_rejects_certificate_from_another_ca(tmp_path):
    """A self-signed lookalike carrying the right subject must not be accepted."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    app, cfg = _app_with(tmp_path, MTLS_MODE="proxy", TRUSTED_PROXIES="127.0.0.1")
    user = _enrol(app, cfg)

    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user.name),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, user.id),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    rogue = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
        .sign(rogue_key, hashes.SHA256())
    )
    rogue_pem = rogue.public_bytes(serialization.Encoding.PEM).decode()

    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]
    body = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "SUCCESS",
                 "X-SSL-Client-Cert": quote(rogue_pem),
                 "X-Proxy-Auth": PROXY_SECRET},
        json={}, environ_base=BEHIND_PROXY,
    ).get_json()
    assert body["ok"] is False


def test_revoked_user_cannot_use_mtls(tmp_path):
    app, cfg = _app_with(tmp_path, MTLS_MODE="proxy", TRUSTED_PROXIES="127.0.0.1")
    admin_client = app.test_client()
    admin_client.post("/admin/login", data={"password": "test-admin-password-1234"})
    user = register(admin_client, cfg.db_path)
    admin_client.post("/admin/api/revoke", json={"user_id": user.id})

    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]
    body = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "SUCCESS",
                 "X-SSL-Client-Cert": quote(user.cert_pem),
                 "X-Proxy-Auth": PROXY_SECRET},
        json={}, environ_base=BEHIND_PROXY,
    ).get_json()
    assert body["ok"] is False


def test_off_mode_disables_the_endpoint(tmp_path):
    app, cfg = _app_with(tmp_path, MTLS_MODE="off", TRUSTED_PROXIES="127.0.0.1")
    user = _enrol(app, cfg)
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]
    body = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "SUCCESS",
                 "X-SSL-Client-Cert": quote(user.cert_pem)},
        json={}, environ_base=BEHIND_PROXY,
    ).get_json()
    assert body["ok"] is False


def test_loopback_is_not_trusted_when_the_proxy_is_elsewhere(tmp_path):
    """Proves TRUSTED_PROXIES is honoured rather than assumed to be loopback."""
    app, cfg = _app_with(tmp_path, MTLS_MODE="proxy", TRUSTED_PROXIES="10.9.9.9")
    assert cfg.trusted_proxies == ["10.9.9.9"]
    user = _enrol(app, cfg)
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]

    body = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "SUCCESS",
                 "X-SSL-Client-Cert": quote(user.cert_pem)},
        json={}, environ_base=BEHIND_PROXY,
    ).get_json()
    assert body["ok"] is False
    assert "доверенного прокси" in body["reason"]


def test_reaching_the_socket_directly_is_not_enough(tmp_path):
    """A local process that bypasses nginx must not be able to impersonate.

    Other services share this host's loopback interface. Being able to open
    the upstream socket is not evidence that a mutual-TLS handshake happened,
    so the proxy must prove itself with a shared secret nginx alone holds.
    """
    app, cfg = _app_with(tmp_path, MTLS_MODE="proxy", TRUSTED_PROXIES="127.0.0.1")
    user = _enrol(app, cfg)
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]

    body = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "SUCCESS",
                 "X-SSL-Client-Cert": quote(user.cert_pem)},
        json={}, environ_base=BEHIND_PROXY,
    ).get_json()
    assert body["ok"] is False, "loopback access alone authenticated a user"

    wrong = client.post(
        f"/api/session/{code}/verify/mtls",
        headers={"X-SSL-Client-Verify": "SUCCESS",
                 "X-SSL-Client-Cert": quote(user.cert_pem),
                 "X-Proxy-Auth": "not-the-real-secret"},
        json={}, environ_base=BEHIND_PROXY,
    ).get_json()
    assert wrong["ok"] is False

    status = client.get(f"/api/session/{code}/status").get_json()
    assert status["side_a"]["verified"] is False
