"""The room: two verified people passing each other secrets.

The server only ever stores ciphertext. Each browser makes an ECDH key pair,
publishes the public half here, and encrypts to the other side's public key, so
a database leak, a backup or a log line reveals nothing readable. The server
still decides who may publish a key and who may read the room, so access is
tied to the token handed out when a slot is claimed, not to knowing the code.

What the server can still do is substitute a public key. That is why the page
shows both sides a short code derived from the two keys, to be compared aloud.
"""
import base64
import binascii

from cryptography.hazmat.primitives.asymmetric import ec
from flask import Blueprint, current_app, jsonify, request

from ..db import get_db, parse_ts, utcnow
from ..security import client_ip, constant_time_equals, hash_token, rate_limit

bp = Blueprint("room", __name__, url_prefix="/api/session/<code>/room")

MAX_ITEMS_PER_ROOM = 50
MAX_CIPHERTEXT_BYTES = 12 * 1024        # a handful of short fields, never files
IV_BYTES = 12                           # AES-GCM
GCM_TAG_BYTES = 16
PUBLIC_KEY_BYTES = 65                   # uncompressed P-256 point


def _cfg():
    return current_app.config["VERIFIER"]


def _fail(reason, status):
    return jsonify({"ok": False, "reason": reason}), status


def _b64(value, *, exact=None, minimum=0, maximum=None):
    """Decode strictly, or None. Rejects anything that is not canonical base64."""
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if exact is not None and len(raw) != exact:
        return None
    if len(raw) < minimum or (maximum is not None and len(raw) > maximum):
        return None
    return raw


def _valid_public_key(value):
    raw = _b64(value, exact=PUBLIC_KEY_BYTES)
    if raw is None:
        return False
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        return False
    return True


def _authorize(code):
    """Return (conn, row, slot) or an error response tuple."""
    cfg = _cfg()
    allowed, retry = rate_limit("room", f"{client_ip()}|{code}", cfg.rl_room)
    if not allowed:
        response = jsonify({"ok": False, "reason": f"слишком много запросов, повторите через {retry} с"})
        response.status_code = 429
        response.headers["Retry-After"] = str(retry)
        return response

    conn = get_db()
    row = conn.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()
    if row is None:
        return _fail("комната не найдена", 404)

    expires = parse_ts(row["expires_at"])
    if expires is not None and utcnow() > expires:
        conn.execute("DELETE FROM room_items WHERE code=?", (code,))
        conn.commit()
        return _fail("комната закрыта, данные удалены", 410)

    supplied = hash_token(request.headers.get("X-Room-Token", ""))
    slot = None
    for candidate in ("a", "b"):
        stored = row[f"{candidate}_token_hash"]
        # Compare against every slot so timing does not reveal which one matched.
        if stored and constant_time_equals(supplied, stored):
            slot = candidate
    if slot is None:
        return _fail("нет доступа к комнате", 401)
    return conn, row, slot


def _side(row, slot):
    return {
        "name": row[f"{slot}_name"],
        "verified": bool(row[f"{slot}_verified"]),
        "public_key": row[f"{slot}_pub"] or None,
    }


@bp.route("", methods=["GET"])
def room_state(code):
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, row, slot = auth
    peer = "b" if slot == "a" else "a"
    items = conn.execute(
        "SELECT id, from_slot, iv, ciphertext, created_at FROM room_items "
        "WHERE code=? ORDER BY id", (code,)
    ).fetchall()
    you, other = _side(row, slot), _side(row, peer)
    return jsonify({
        "ok": True,
        "slot": slot,
        "expires_at": row["expires_at"],
        "you": you,
        "peer": other,
        "ready": bool(you["verified"] and other["verified"]
                      and you["public_key"] and other["public_key"]),
        "items": [
            {"id": i["id"], "from": i["from_slot"], "iv": i["iv"],
             "ciphertext": i["ciphertext"], "created_at": i["created_at"]}
            for i in items
        ],
    })


@bp.route("/key", methods=["POST"])
def publish_key(code):
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, row, slot = auth
    public_key = (request.get_json(silent=True) or {}).get("public_key")
    if not _valid_public_key(public_key):
        return _fail("некорректный открытый ключ", 400)

    # Set once. Replacing a key would make everything already sent unreadable and
    # would let a stolen token swap in a key of the thief's choosing.
    cursor = conn.execute(
        f"UPDATE sessions SET {slot}_pub=? WHERE code=? "
        f"AND ({slot}_pub IS NULL OR {slot}_pub='')",
        (public_key, code),
    )
    conn.commit()
    if cursor.rowcount == 1 or row[f"{slot}_pub"] == public_key:
        return jsonify({"ok": True})
    return _fail("ключ уже опубликован и не может быть заменён", 409)


@bp.route("/items", methods=["POST"])
def add_item(code):
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, row, slot = auth
    peer = "b" if slot == "a" else "a"

    if not (row["a_verified"] and row["b_verified"]):
        return _fail("собеседник ещё не прошёл верификацию", 409)
    if not (row["a_pub"] and row["b_pub"]):
        return _fail("собеседник ещё не готов принимать данные", 409)

    data = request.get_json(silent=True) or {}
    iv, ciphertext = data.get("iv"), data.get("ciphertext")
    if _b64(iv, exact=IV_BYTES) is None:
        return _fail("некорректный вектор инициализации", 400)
    if _b64(ciphertext, minimum=GCM_TAG_BYTES + 1, maximum=MAX_CIPHERTEXT_BYTES) is None:
        return _fail("данные пустые или слишком большие", 400)

    count = conn.execute("SELECT COUNT(*) FROM room_items WHERE code=?", (code,)).fetchone()[0]
    if count >= MAX_ITEMS_PER_ROOM:
        return _fail("достигнут предел записей в комнате", 409)

    cursor = conn.execute(
        "INSERT INTO room_items (code, from_slot, iv, ciphertext, created_at) VALUES (?,?,?,?,?)",
        (code, slot, iv, ciphertext, utcnow().isoformat()),
    )
    conn.commit()
    return jsonify({"ok": True, "id": cursor.lastrowid})


@bp.route("/items/<int:item_id>", methods=["DELETE"])
def delete_item(code, item_id):
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, _row, _slot = auth
    # Either side may remove anything in the room: read it, copy it, burn it.
    cursor = conn.execute("DELETE FROM room_items WHERE id=? AND code=?", (item_id, code))
    conn.commit()
    if cursor.rowcount == 0:
        return _fail("запись не найдена", 404)
    return jsonify({"ok": True})
