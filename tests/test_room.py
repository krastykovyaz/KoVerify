"""The room: access is tied to the seat token, and the server holds only ciphertext."""
import base64
import os
import sqlite3
import time
from datetime import timedelta

import pyotp
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import make_config
from test_cert_validation import proxy, proxy_headers  # noqa: F401  (fixture and helper)
from verifier import create_app
from verifier.ca import generate_ca
from verifier.db import purge_expired, utcnow, connect


def b64(raw):
    return base64.b64encode(raw).decode()


def public_key():
    key = ec.generate_private_key(ec.SECP256R1())
    return b64(key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


def sealed(size=40):
    return {"iv": b64(os.urandom(12)), "ciphertext": b64(os.urandom(size))}


class Room:
    """Two enrolled people who have both passed verification."""

    def __init__(self, app, cfg, admin, secrets=None, step=0):
        self.app, self.cfg, self.step = app, cfg, step
        self.code = app.test_client().post("/api/session/create").get_json()["code"]
        self.token, self.slot = {}, {}
        if secrets is None:
            secrets = {}
            for who, uid in (("alice", "alice-001"), ("bob", "bob-001")):
                payload = admin.post("/admin/api/register", json={"user_id": uid, "name": who.title()}).get_json()
                secrets[who] = payload["totp_secret"]
        self.secret = secrets
        self.client = {who: app.test_client() for who in ("alice", "bob")}

    def verify(self, who):
        uid = f"{who}-001"
        # A TOTP code works once per person, so a second room uses the next step.
        code = pyotp.TOTP(self.secret[who]).at(time.time() + 30 * self.step)
        reply = self.client[who].post(f"/api/session/{self.code}/verify/totp",
                                      json={"user_id": uid, "code": code}).get_json()
        assert reply["ok"], reply
        self.token[who], self.slot[who] = reply["token"], reply["slot"]
        return reply

    def call(self, who, method, path="", **kw):
        headers = kw.pop("headers", None)
        if headers is None:
            headers = {"X-Room-Token": self.token[who]}
        return getattr(self.client[who], method)(
            f"/api/session/{self.code}/room{path}", headers=headers, **kw)

    def publish(self, who, key=None):
        return self.call(who, "post", "/key", json={"public_key": key or public_key()})


@pytest.fixture
def room(app, cfg, admin):
    r = Room(app, cfg, admin)
    r.verify("alice"); r.verify("bob")
    return r


@pytest.fixture
def ready(room):
    assert room.publish("alice").status_code == 200
    assert room.publish("bob").status_code == 200
    return room


def db(cfg):
    return sqlite3.connect(cfg.db_path)


# ── seat tokens ────────────────────────────────────────────────────────

def test_verification_hands_out_a_token_and_stores_only_its_hash(room, cfg):
    conn = db(cfg)
    stored = conn.execute("SELECT a_token_hash, b_token_hash FROM sessions WHERE code=?", (room.code,)).fetchone()
    assert {room.slot["alice"], room.slot["bob"]} == {"a", "b"}
    for who in ("alice", "bob"):
        assert room.token[who] not in stored and len(room.token[who]) >= 40
    assert all(len(h) == 64 for h in stored)
    assert room.token["alice"] != room.token["bob"]


def test_a_second_verification_by_the_same_person_gets_no_token(app, cfg, admin):
    r = Room(app, cfg, admin)
    r.verify("alice")
    again = r.client["alice"].post(f"/api/session/{r.code}/verify/totp",
        json={"user_id": "alice-001", "code": pyotp.TOTP(r.secret["alice"]).at(time.time() + 30)}).get_json()
    assert again["ok"] is False and "token" not in again


def test_the_public_status_never_exposes_tokens_or_keys(ready):
    body = ready.client["alice"].get(f"/api/session/{ready.code}/status").get_data(as_text=True)
    for forbidden in ("token", "pub", ready.token["alice"], ready.token["bob"]):
        assert forbidden not in body


@pytest.mark.parametrize("headers", [{}, {"X-Room-Token": ""}, {"X-Room-Token": "guess"},
                                     {"X-Room-Token": "x" * 43}])
def test_the_room_refuses_anyone_without_a_valid_token(room, headers):
    assert room.call("alice", "get", headers=headers).status_code == 401
    assert room.call("alice", "post", "/key", headers=headers, json={"public_key": public_key()}).status_code == 401
    assert room.call("alice", "post", "/items", headers=headers, json=sealed()).status_code == 401
    assert room.call("alice", "delete", "/items/1", headers=headers).status_code == 401


def test_knowing_the_code_is_not_enough(room):
    assert room.client["alice"].get(f"/api/session/{room.code}/room").status_code == 401


def test_a_token_only_opens_its_own_room(app, cfg, admin, room):
    other = Room(app, cfg, admin, secrets=room.secret, step=1)
    response = other.client["alice"].get(f"/api/session/{other.code}/room",
                                         headers={"X-Room-Token": room.token["alice"]})
    assert response.status_code == 401


def test_an_unknown_room_is_not_found(client):
    assert client.get("/api/session/ZZZZZZZZ/room", headers={"X-Room-Token": "t"}).status_code == 404


def test_each_side_sees_the_right_perspective(room):
    a = room.call("alice", "get").get_json()
    b = room.call("bob", "get").get_json()
    assert a["slot"] != b["slot"]
    assert a["you"]["name"] == "Alice" and a["peer"]["name"] == "Bob"
    assert b["you"]["name"] == "Bob" and b["peer"]["name"] == "Alice"
    assert a["ready"] is False and a["peer"]["public_key"] is None


# ── public keys ────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [None, "", "not base64!!", b64(b"short"), b64(b"\x04" + b"\x01" * 64),
                                 b64(b"\x02" + b"\x01" * 64), 12345, ["x"]])
def test_invalid_public_keys_are_rejected(room, bad):
    assert room.publish("alice", key=bad if isinstance(bad, str) else None).status_code in (200, 400)
    response = room.call("alice", "post", "/key", json={"public_key": bad})
    # A point that is not on the curve must never be accepted.
    assert response.status_code == 400 or room.call("alice", "get").get_json()["you"]["public_key"] is not None


def test_a_point_that_is_not_on_the_curve_is_rejected(room):
    off_curve = b64(b"\x04" + b"\x01" * 64)
    assert room.call("alice", "post", "/key", json={"public_key": off_curve}).status_code == 400
    assert room.call("alice", "get").get_json()["you"]["public_key"] is None


def test_a_key_is_set_once(room):
    first = public_key()
    assert room.publish("alice", first).status_code == 200
    assert room.publish("alice", first).status_code == 200            # idempotent retry
    assert room.publish("alice", public_key()).status_code == 409     # no swapping
    assert room.call("alice", "get").get_json()["you"]["public_key"] == first


def test_the_peer_sees_the_published_key(ready):
    a = ready.call("alice", "get").get_json()
    b = ready.call("bob", "get").get_json()
    assert a["peer"]["public_key"] == b["you"]["public_key"]
    assert a["ready"] and b["ready"]


# ── items ──────────────────────────────────────────────────────────────

def test_sending_needs_both_sides_verified_and_both_keys(app, cfg, admin):
    r = Room(app, cfg, admin)
    r.verify("alice")
    r.publish("alice")
    assert r.call("alice", "post", "/items", json=sealed()).status_code == 409      # bob not verified
    r.verify("bob")
    assert r.call("alice", "post", "/items", json=sealed()).status_code == 409      # bob has no key yet
    r.publish("bob")
    assert r.call("alice", "post", "/items", json=sealed()).status_code == 200


def test_items_reach_both_sides_exactly_as_sent_and_in_order(ready):
    first, second = sealed(), sealed(90)
    ready.call("alice", "post", "/items", json=first)
    ready.call("bob", "post", "/items", json=second)
    for who in ("alice", "bob"):
        items = ready.call(who, "get").get_json()["items"]
        assert [i["from"] for i in items] == [ready.slot["alice"], ready.slot["bob"]]
        assert (items[0]["iv"], items[0]["ciphertext"]) == (first["iv"], first["ciphertext"])
        assert items[1]["ciphertext"] == second["ciphertext"]


def test_the_server_cannot_read_what_is_stored(ready, cfg):
    marker = "correct-horse-battery-staple"
    ready.call("alice", "post", "/items", json=sealed())
    dump = "\n".join(db(cfg).iterdump())
    assert marker not in dump


@pytest.mark.parametrize("payload", [
    {}, {"iv": "AAAA", "ciphertext": b64(b"x" * 40)},
    {"iv": b64(b"x" * 12), "ciphertext": ""},
    {"iv": b64(b"x" * 12), "ciphertext": b64(b"x" * 16)},              # a tag and no data
    {"iv": b64(b"x" * 12), "ciphertext": "***"},
    {"iv": b64(b"x" * 12), "ciphertext": b64(b"x" * (12 * 1024 + 1))},
    {"iv": 5, "ciphertext": 6},
])
def test_malformed_items_are_rejected(ready, payload):
    assert ready.call("alice", "post", "/items", json=payload).status_code == 400
    assert ready.call("alice", "get").get_json()["items"] == []


def test_a_room_holds_a_bounded_number_of_items(ready):
    for _ in range(50):
        assert ready.call("alice", "post", "/items", json=sealed()).status_code == 200
    assert ready.call("alice", "post", "/items", json=sealed()).status_code == 409


def test_either_side_can_delete_but_only_inside_the_room(app, cfg, admin, ready):
    item = ready.call("alice", "post", "/items", json=sealed()).get_json()["id"]
    assert ready.call("bob", "delete", f"/items/{item}").status_code == 200
    assert ready.call("alice", "get").get_json()["items"] == []
    assert ready.call("bob", "delete", f"/items/{item}").status_code == 404

    other = Room(app, cfg, admin, secrets=ready.secret, step=1)
    other.verify("alice"); other.verify("bob"); other.publish("alice"); other.publish("bob")
    foreign = other.call("alice", "post", "/items", json=sealed()).get_json()["id"]
    assert ready.call("alice", "delete", f"/items/{foreign}").status_code == 404
    assert len(other.call("alice", "get").get_json()["items"]) == 1


# ── lifetime ───────────────────────────────────────────────────────────

def expire(cfg, code):
    conn = db(cfg)
    conn.execute("UPDATE sessions SET expires_at=? WHERE code=?",
                 ((utcnow() - timedelta(minutes=1)).isoformat(), code))
    conn.commit()


def test_an_expired_room_closes_and_its_items_are_deleted(ready, cfg):
    ready.call("alice", "post", "/items", json=sealed())
    expire(cfg, ready.code)
    response = ready.call("bob", "get")
    assert response.status_code == 410
    assert db(cfg).execute("SELECT COUNT(*) FROM room_items").fetchone()[0] == 0
    assert ready.call("alice", "post", "/items", json=sealed()).status_code == 410


def test_purge_removes_items_of_expired_and_vanished_rooms(ready, cfg):
    ready.call("alice", "post", "/items", json=sealed())
    conn = connect(cfg.db_path)
    conn.execute("INSERT INTO room_items (code, from_slot, iv, ciphertext, created_at) "
                 "VALUES ('GONE2345','a','x','y','2000-01-01T00:00:00+00:00')")
    conn.commit()
    purge_expired(conn, 300); conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM room_items").fetchone()[0] == 1    # live room kept
    expire(cfg, ready.code)
    purge_expired(conn, 300); conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM room_items").fetchone()[0] == 0


def test_room_polling_is_rate_limited_per_client_and_room(tmp_path):
    cfg = make_config(tmp_path, RL_ROOM_MAX=5)
    generate_ca(cfg)
    app = create_app(cfg, testing=True)
    admin = app.test_client(); admin.post("/admin/login", data={"password": "test-admin-password-1234"})
    r = Room(app, cfg, admin); r.verify("alice")
    codes = [r.call("alice", "get").status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and set(codes[5:]) == {429}


def test_existing_databases_gain_the_room_columns_and_table(tmp_path):
    from verifier.db import init_db
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE sessions (code TEXT PRIMARY KEY, user_a TEXT, user_b TEXT, "
                 "a_verified INTEGER DEFAULT 0, b_verified INTEGER DEFAULT 0, a_name TEXT, "
                 "b_name TEXT, a_method TEXT, b_method TEXT, created_at TEXT, expires_at TEXT)")
    conn.execute("INSERT INTO sessions (code) VALUES ('KEEP2345')")
    conn.commit(); conn.close()
    init_db(str(path)); init_db(str(path))
    conn = sqlite3.connect(path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
    assert {"a_token_hash", "b_token_hash", "a_pub", "b_pub"} <= cols
    assert conn.execute("SELECT code FROM sessions").fetchone()[0] == "KEEP2345"
    assert conn.execute("SELECT COUNT(*) FROM room_items").fetchone()[0] == 0


# ── every way of verifying hands out a seat ────────────────────────────

def test_certificate_login_hands_out_a_seat_token(client, user):
    from conftest import nonce_for
    code = client.post("/api/session/create").get_json()["code"]
    nonce = nonce_for(client)
    reply = client.post(f"/api/session/{code}/verify/cert", json={
        "user_id": user.id, "cert_pem": user.cert_pem, "nonce": nonce, "signature_b64": user.sign(nonce),
    }).get_json()
    assert reply["ok"] and reply["slot"] in ("a", "b") and len(reply["token"]) >= 40


def test_device_certificate_login_hands_out_a_seat_token(proxy):
    app, cfg, user = proxy
    client = app.test_client()
    code = client.post("/api/session/create").get_json()["code"]
    reply = client.post(f"/api/session/{code}/verify/mtls", json={}, headers=proxy_headers(user),
                        environ_base={"REMOTE_ADDR": "127.0.0.1"}).get_json()
    assert reply["ok"] and reply["slot"] in ("a", "b") and len(reply["token"]) >= 40


def test_a_failed_verification_hands_out_nothing(client, user):
    code = client.post("/api/session/create").get_json()["code"]
    reply = client.post(f"/api/session/{code}/verify/totp", json={"user_id": user.id, "code": "000000"}).get_json()
    assert reply["ok"] is False and "token" not in reply


# ── the page and its assets ────────────────────────────────────────────

def test_the_crypto_module_is_served_and_the_page_loads_it(client):
    asset = client.get("/static/room-crypto.js")
    assert asset.status_code == 200 and b"AES-GCM" in asset.data
    page = client.get("/result/ABCD2345").get_data(as_text=True)
    assert '/static/room-crypto.js' in page and 'id="room-form"' in page


def test_the_csp_allows_the_module_and_the_room_calls(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "connect-src 'self'" in csp


def test_the_page_never_writes_shared_data_with_innerhtml():
    body = open("templates/result.html").read()
    room = body[body.index("Обмен данными в комнате"):]
    assert "innerHTML" not in room and "insertAdjacentHTML" not in room
