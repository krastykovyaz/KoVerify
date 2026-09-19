"""Challenge-response certificate login, the route result.html actually calls."""
import base64

from conftest import nonce_for, register


def test_route_exists_and_returns_json(client, session_code):
    """Previously this route was absent, so the browser got HTML 404."""
    response = client.post(f"/api/session/{session_code}/verify/cert", json={})
    assert response.status_code != 404
    assert response.is_json


def test_valid_signature_authenticates(client, user, session_code):
    nonce = nonce_for(client)
    response = client.post(f"/api/session/{session_code}/verify/cert", json={
        "user_id": user.id, "cert_pem": user.cert_pem,
        "nonce": nonce, "signature_b64": user.sign(nonce),
    })
    body = response.get_json()
    assert body["ok"] is True, body
    assert body["name"] == user.name


def test_certificate_without_private_key_is_rejected(client, user, session_code):
    """Someone holding only the public certificate cannot sign the nonce."""
    nonce = nonce_for(client)
    forged = base64.b64encode(b"not a real signature").decode()
    body = client.post(f"/api/session/{session_code}/verify/cert", json={
        "user_id": user.id, "cert_pem": user.cert_pem,
        "nonce": nonce, "signature_b64": forged,
    }).get_json()
    assert body["ok"] is False


def test_nonce_cannot_be_replayed(client, user, app, cfg):
    first = client.post("/api/session/create").get_json()["code"]
    nonce = nonce_for(client)
    signature = user.sign(nonce)

    ok = client.post(f"/api/session/{first}/verify/cert", json={
        "user_id": user.id, "cert_pem": user.cert_pem,
        "nonce": nonce, "signature_b64": signature,
    }).get_json()
    assert ok["ok"] is True

    second = client.post("/api/session/create").get_json()["code"]
    replay = client.post(f"/api/session/{second}/verify/cert", json={
        "user_id": user.id, "cert_pem": user.cert_pem,
        "nonce": nonce, "signature_b64": signature,
    }).get_json()
    assert replay["ok"] is False
    assert "nonce" in replay["reason"].lower()


def test_unknown_nonce_is_rejected(client, user, session_code):
    body = client.post(f"/api/session/{session_code}/verify/cert", json={
        "user_id": user.id, "cert_pem": user.cert_pem,
        "nonce": "0" * 64, "signature_b64": user.sign("0" * 64),
    }).get_json()
    assert body["ok"] is False


def test_revoked_certificate_is_rejected(admin, cfg, client, session_code, user):
    admin.post("/admin/api/revoke", json={"user_id": user.id})
    nonce = nonce_for(client)
    body = client.post(f"/api/session/{session_code}/verify/cert", json={
        "user_id": user.id, "cert_pem": user.cert_pem,
        "nonce": nonce, "signature_b64": user.sign(nonce),
    }).get_json()
    assert body["ok"] is False
    assert "отозван" in body["reason"] or "не найден" in body["reason"]


def test_cannot_claim_another_users_identity(admin, cfg, client, session_code, user):
    other = register(admin, cfg.db_path, user_id="bob-002", name="Bob Example")
    nonce = nonce_for(client)
    # Alice's certificate and signature, but claiming to be Bob.
    body = client.post(f"/api/session/{session_code}/verify/cert", json={
        "user_id": other.id, "cert_pem": user.cert_pem,
        "nonce": nonce, "signature_b64": user.sign(nonce),
    }).get_json()
    assert body["ok"] is False


def test_malformed_certificate_is_rejected(client, session_code, user):
    nonce = nonce_for(client)
    body = client.post(f"/api/session/{session_code}/verify/cert", json={
        "user_id": user.id, "cert_pem": "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----",
        "nonce": nonce, "signature_b64": user.sign(nonce),
    }).get_json()
    assert body["ok"] is False
