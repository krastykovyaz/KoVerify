"""Every way a client certificate or an mTLS assertion must be refused."""
import base64
import datetime as dt
import sqlite3
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from conftest import PROXY_SECRET, make_config, register
from verifier import create_app
from verifier.ca import generate_ca, load_ca
from verifier.certs import (CertError, authenticate_by_challenge, consume_nonce,
                            lookup_user, parse_pem, verify_chain,
                            verify_proof_of_possession)
from verifier.db import utcnow
from verifier.mtls import authenticated_client_cert

NOW = lambda: dt.datetime.now(dt.timezone.utc)


def name(cn, **extra):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if "serial" in extra:
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, extra["serial"]))
    return x509.Name(attrs)


def leaf(ca_key, issuer, cn="Leaf", key=None, start=None, end=None, algorithm=None, **extra):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder().subject_name(name(cn, **extra)).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start or NOW() - dt.timedelta(days=1))
        .not_valid_after(end or NOW() + dt.timedelta(days=30))
        .sign(ca_key, algorithm if algorithm is not False else None)
    )
    return cert, key


@pytest.fixture
def ca(cfg):
    return load_ca(cfg)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ── chain verification ─────────────────────────────────────────────────

def test_a_valid_certificate_passes(ca):
    cert, _ = leaf(ca[0], ca[1].subject, algorithm=hashes.SHA256())
    assert verify_chain(cert, ca[1]) is True


def test_unknown_issuer_is_refused(ca):
    cert, _ = leaf(ca[0], name("SomeOtherCA"), algorithm=hashes.SHA256())
    with pytest.raises(CertError, match="неизвестным"):
        verify_chain(cert, ca[1])


def test_same_issuer_name_but_different_key_is_refused(ca):
    impostor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert, _ = leaf(impostor, ca[1].subject, algorithm=hashes.SHA256())
    with pytest.raises(CertError, match="подпись сертификата недействительна"):
        verify_chain(cert, ca[1])


def test_expired_and_not_yet_valid_are_refused(ca):
    old, _ = leaf(ca[0], ca[1].subject, start=NOW() - dt.timedelta(days=60),
                  end=NOW() - dt.timedelta(days=1), algorithm=hashes.SHA256())
    with pytest.raises(CertError, match="просрочен"):
        verify_chain(old, ca[1])
    future, _ = leaf(ca[0], ca[1].subject, start=NOW() + dt.timedelta(days=1),
                     end=NOW() + dt.timedelta(days=60), algorithm=hashes.SHA256())
    with pytest.raises(CertError, match="ещё не действителен"):
        verify_chain(future, ca[1])


def test_the_ca_certificate_cannot_be_used_to_log_in(ca):
    with pytest.raises(CertError, match="CA не может"):
        verify_chain(ca[1], ca[1])


def test_unsupported_issuer_key_types_are_refused_cleanly(ca):
    ed = ed25519.Ed25519PrivateKey.generate()
    ed_name = name("EdCA")
    ed_ca = (x509.CertificateBuilder().subject_name(ed_name).issuer_name(ed_name)
             .public_key(ed.public_key()).serial_number(1)
             .not_valid_before(NOW() - dt.timedelta(days=1)).not_valid_after(NOW() + dt.timedelta(days=9))
             .sign(ed, None))
    cert, _ = leaf(ed, ed_name, algorithm=False)
    with pytest.raises(CertError, match="неподдерживаемый"):
        verify_chain(cert, ed_ca)


def test_elliptic_curve_issuers_are_supported():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_name = name("EcCA")
    ec_ca = (x509.CertificateBuilder().subject_name(ec_name).issuer_name(ec_name)
             .public_key(ec_key.public_key()).serial_number(1)
             .not_valid_before(NOW() - dt.timedelta(days=1)).not_valid_after(NOW() + dt.timedelta(days=9))
             .sign(ec_key, hashes.SHA256()))
    cert, _ = leaf(ec_key, ec_name, algorithm=hashes.SHA256())
    assert verify_chain(cert, ec_ca) is True


def test_garbage_is_not_a_certificate():
    for junk in (None, "", "not a pem", b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"):
        with pytest.raises(CertError):
            parse_pem(junk)


# ── user lookup ────────────────────────────────────────────────────────

def test_lookup_resolves_a_live_user_and_rejects_the_rest(app, user, cfg):
    cert = parse_pem(user.cert_pem)
    with app.app_context():
        assert lookup_user(cert)["id"] == user.id
        assert lookup_user(cert, expected_user_id=user.id)["id"] == user.id
        with pytest.raises(CertError, match="другому пользователю"):
            lookup_user(cert, expected_user_id="somebody-else")

    conn = sqlite3.connect(cfg.db_path)
    conn.execute("UPDATE users SET id='renamed' WHERE id=?", (user.id,))
    conn.commit()
    with app.app_context():
        with pytest.raises(CertError, match="не соответствует учётной записи"):
            lookup_user(cert)
    conn.execute("UPDATE users SET id=?, revoked=1 WHERE id='renamed'", (user.id,))
    conn.commit()
    with app.app_context():
        with pytest.raises(CertError, match="отозван"):
            lookup_user(cert)
    conn.execute("UPDATE users SET serial='deadbeef'")
    conn.commit(); conn.close()
    with app.app_context():
        with pytest.raises(CertError, match="не найден"):
            lookup_user(cert)


# ── nonces and proof of possession ─────────────────────────────────────

def test_nonce_rules(app, cfg):
    with app.app_context():
        from verifier.db import get_db
        conn = get_db()
        with pytest.raises(CertError, match="не предоставлен"):
            consume_nonce("", 300)
        with pytest.raises(CertError, match="уже использован"):
            consume_nonce("never-issued", 300)
        conn.execute("INSERT INTO nonces VALUES (?,?)",
                     ("stale", (utcnow() - dt.timedelta(hours=1)).isoformat()))
        conn.commit()
        with pytest.raises(CertError, match="истёк"):
            consume_nonce("stale", 300)
        conn.execute("INSERT INTO nonces VALUES (?,?)", ("fresh", utcnow().isoformat()))
        conn.commit()
        assert consume_nonce("fresh", 300) is True
        with pytest.raises(CertError):
            consume_nonce("fresh", 300)            # single use


def test_proof_of_possession_rules(user):
    cert = parse_pem(user.cert_pem)
    with pytest.raises(CertError, match="не предоставлена"):
        verify_proof_of_possession(cert, "n", b"")
    with pytest.raises(CertError, match="недействительна"):
        verify_proof_of_possession(cert, "n", b"x" * 256)
    with pytest.raises(CertError, match="недействительна"):
        verify_proof_of_possession(cert, "n", b"short")
    good = base64.b64decode(user.sign("hello"))
    assert verify_proof_of_possession(cert, "hello", good) is True
    with pytest.raises(CertError):
        verify_proof_of_possession(cert, "different", good)


def test_challenge_response_end_to_end_and_with_a_stolen_certificate(app, cfg, user):
    with app.app_context():
        from verifier.db import get_db
        conn = get_db()
        conn.execute("INSERT INTO nonces VALUES (?,?)", ("n1", utcnow().isoformat()))
        conn.execute("INSERT INTO nonces VALUES (?,?)", ("n2", utcnow().isoformat()))
        conn.commit()
        ca_cert = load_ca(cfg)[1]
        ok = authenticate_by_challenge(cfg, ca_cert, user.cert_pem, "n1",
                                       base64.b64decode(user.sign("n1")), user.id)
        assert ok["id"] == user.id
        attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        from cryptography.hazmat.primitives.asymmetric import padding
        forged = attacker.sign(b"n2", padding.PKCS1v15(), hashes.SHA256())
        with pytest.raises(CertError, match="подпись nonce недействительна"):
            authenticate_by_challenge(cfg, ca_cert, user.cert_pem, "n2", forged, user.id)


# ── the mTLS trust decision ────────────────────────────────────────────

@pytest.fixture
def proxy(tmp_path):
    """An app in proxy mode with one enrolled user."""
    cfg = make_config(tmp_path / "proxy", MTLS_MODE="proxy", TRUSTED_PROXIES="127.0.0.1")
    (tmp_path / "proxy").mkdir(exist_ok=True)
    generate_ca(cfg)
    app = create_app(cfg, testing=True)
    client = app.test_client()
    client.post("/admin/login", data={"password": "test-admin-password-1234"})
    return app, cfg, register(client, cfg.db_path)


def ctx(app, headers=None, environ=None):
    return app.test_request_context("/", headers=headers or {}, environ_overrides=environ or {})


def proxy_headers(user, **override):
    headers = {
        "X-Proxy-Auth": PROXY_SECRET,
        "X-SSL-Client-Verify": "SUCCESS",
        "X-SSL-Client-Cert": quote(user.cert_pem),
        "X-SSL-Client-Serial": format(parse_pem(user.cert_pem).serial_number, "X"),
    }
    headers.update(override)
    return {k: v for k, v in headers.items() if v is not None}


def test_proxy_mode_accepts_a_complete_assertion(proxy):
    app, cfg, user = proxy
    with ctx(app, proxy_headers(user), {"REMOTE_ADDR": "127.0.0.1"}):
        assert authenticated_client_cert(cfg, load_ca(cfg)[1]).serial_number


@pytest.mark.parametrize("override, remote, message", [
    ({"X-Proxy-Auth": "wrong"}, "127.0.0.1", "доверенного прокси"),
    ({"X-Proxy-Auth": None}, "127.0.0.1", "доверенного прокси"),
    ({}, "203.0.113.9", "доверенного прокси"),
    ({"X-SSL-Client-Verify": "FAILED:certificate has expired"}, "127.0.0.1", "не предоставлен"),
    ({"X-SSL-Client-Verify": "NONE"}, "127.0.0.1", "не предоставлен"),
    ({"X-SSL-Client-Cert": None}, "127.0.0.1", "не передал"),
    ({"X-SSL-Client-Cert": quote("garbage")}, "127.0.0.1", "повреждён"),
    ({"X-SSL-Client-Serial": "1234"}, "127.0.0.1", "серийный номер"),
])
def test_proxy_mode_refuses_incomplete_or_forged_assertions(proxy, override, remote, message):
    app, cfg, user = proxy
    with ctx(app, proxy_headers(user, **override), {"REMOTE_ADDR": remote}):
        with pytest.raises(CertError, match=message):
            authenticated_client_cert(cfg, load_ca(cfg)[1])


def test_unix_socket_peer_still_needs_the_shared_secret(proxy):
    app, cfg, user = proxy
    with ctx(app, proxy_headers(user), {"REMOTE_ADDR": ""}):
        assert authenticated_client_cert(cfg, load_ca(cfg)[1])
    with ctx(app, proxy_headers(user, **{"X-Proxy-Auth": "wrong"}), {"REMOTE_ADDR": ""}):
        with pytest.raises(CertError):
            authenticated_client_cert(cfg, load_ca(cfg)[1])


def test_off_mode_refuses_everything(tmp_path):
    cfg = make_config(tmp_path, MTLS_MODE="off")
    generate_ca(cfg)
    app = create_app(cfg, testing=True)
    with ctx(app):
        with pytest.raises(CertError, match="отключён"):
            authenticated_client_cert(cfg, load_ca(cfg)[1])


def test_direct_mode_reads_only_the_tls_socket_never_headers(tmp_path):
    cfg = make_config(tmp_path, MTLS_MODE="direct")
    generate_ca(cfg)
    app = create_app(cfg, testing=True)
    key, ca_cert = load_ca(cfg)
    cert, _ = leaf(key, ca_cert.subject, algorithm=hashes.SHA256())
    with ctx(app, {"X-SSL-Client-Cert": quote(pem(cert)), "X-SSL-Client-Verify": "SUCCESS"}):
        with pytest.raises(CertError, match="не предоставлен"):
            authenticated_client_cert(cfg, ca_cert)
    with ctx(app, environ={"SSL_CLIENT_CERT": pem(cert)}):
        assert authenticated_client_cert(cfg, ca_cert).serial_number == cert.serial_number
