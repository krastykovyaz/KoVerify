"""Pairing sessions: slot assignment, expiry and code strength."""
import sqlite3
from datetime import datetime, timedelta, timezone

import pyotp

from conftest import register


def totp_for(cfg, user_id):
    conn = sqlite3.connect(cfg.db_path)
    secret = conn.execute(
        "SELECT totp_secret FROM users WHERE id=?", (user_id,)
    ).fetchone()[0]
    conn.close()
    return pyotp.TOTP(secret).now()


def test_session_code_has_meaningful_entropy(client):
    """24 bits was enumerable. Codes are also free of lookalike characters."""
    payload = client.post("/api/session/create").get_json()
    code = payload["code"]
    assert len(code) >= 8
    assert not set(code) & set("IO01")

    codes = {client.post("/api/session/create").get_json()["code"] for _ in range(50)}
    assert len(codes) == 50, "codes collided"


def test_two_people_fill_both_slots(admin, cfg, client, session_code):
    alice = register(admin, cfg.db_path, user_id="alice-001", name="Alice")
    bob = register(admin, cfg.db_path, user_id="bob-002", name="Bob")

    first = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": alice.id, "code": totp_for(cfg, alice.id)}).get_json()
    assert first["ok"] and first["slot"] == "a"

    second = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": bob.id, "code": totp_for(cfg, bob.id)}).get_json()
    assert second["ok"] and second["slot"] == "b"

    status = client.get(f"/api/session/{session_code}/status").get_json()
    assert status["status"] == "both_verified"


def test_one_person_cannot_occupy_both_slots(admin, cfg, client, session_code):
    alice = register(admin, cfg.db_path, user_id="alice-001", name="Alice")
    ok = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": alice.id, "code": totp_for(cfg, alice.id)}).get_json()
    assert ok["ok"]

    again = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": alice.id, "code": totp_for(cfg, alice.id)}).get_json()
    assert again["ok"] is False

    status = client.get(f"/api/session/{session_code}/status").get_json()
    assert status["side_b"]["verified"] is False
    assert status["status"] == "pending"


def test_expired_session_refuses_verification(admin, cfg, client, session_code):
    alice = register(admin, cfg.db_path, user_id="alice-001", name="Alice")
    conn = sqlite3.connect(cfg.db_path)
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    conn.execute("UPDATE sessions SET expires_at=? WHERE code=?", (past, session_code))
    conn.commit()
    conn.close()

    body = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": alice.id, "code": totp_for(cfg, alice.id)}).get_json()
    assert body["ok"] is False
    assert "истекла" in body["reason"]
    assert client.get(f"/api/session/{session_code}/status").get_json()["status"] == "expired"


def test_wrong_totp_code_is_refused(admin, cfg, client, session_code):
    alice = register(admin, cfg.db_path, user_id="alice-001", name="Alice")
    body = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": alice.id, "code": "000000"}).get_json()
    assert body["ok"] is False


def test_revoked_user_cannot_verify(admin, cfg, client, session_code):
    alice = register(admin, cfg.db_path, user_id="alice-001", name="Alice")
    admin.post("/admin/api/revoke", json={"user_id": alice.id})
    body = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": alice.id, "code": totp_for(cfg, alice.id)}).get_json()
    assert body["ok"] is False


def test_unknown_user_and_wrong_code_are_indistinguishable(admin, cfg, client,
                                                           session_code):
    """Otherwise the endpoint enumerates which user IDs exist."""
    alice = register(admin, cfg.db_path, user_id="alice-001", name="Alice")
    unknown = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": "no-such-person", "code": "123456"}).get_json()
    wrong = client.post(f"/api/session/{session_code}/verify/totp", json={
        "user_id": alice.id, "code": "123456"}).get_json()
    assert unknown["reason"] == wrong["reason"]


def test_missing_session_returns_json_404(client):
    response = client.post("/api/session/NOSUCHCO/verify/totp", json={})
    assert response.status_code == 404
    assert response.is_json


def test_malformed_body_does_not_crash(client, session_code):
    response = client.post(f"/api/session/{session_code}/verify/totp",
                           data="not json", content_type="text/plain")
    assert response.status_code < 500
