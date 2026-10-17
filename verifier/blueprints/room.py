"""The room: two verified people passing each other secrets.

The server only ever stores ciphertext. Each browser makes an ECDH key pair,
publishes the public half here, and encrypts to the other side's public key, so
a database leak, a backup or a log line reveals nothing readable. The server
still decides who may publish a key and who may read the room, so access is
tied to the token handed out when a slot is claimed, not to knowing the code.

What the server can still do is substitute a public key. Two things stop it.
First, keys are committed before they are revealed: each side publishes the
SHA-256 of its public key, and may reveal the key only once both commitments
exist and the key matches its own commitment. The page pins the other side's
commitment the first time it sees it, so a server that wants to show Alice a
fake key for Bob has to choose that fake key before it has seen Alice's real
one. Second, both screens show a ten-digit code derived from the two keys, to
be compared aloud. Without the commitment that code was worth little: a server
choosing both fake keys could find a matching pair by birthday search in
seconds. With it, the server gets one blind guess in ten billion.
"""
import base64
import binascii
import hashlib
import os
import re
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric import ec
from flask import Blueprint, Response, current_app, jsonify, request

from ..db import close_room, delete_proof, get_db, parse_ts, proof_path, utcnow
from ..security import client_ip, constant_time_equals, hash_token, rate_limit

bp = Blueprint("room", __name__, url_prefix="/api/session/<code>/room")

MAX_ITEMS_PER_ROOM = 50
MAX_CIPHERTEXT_BYTES = 12 * 1024        # a handful of short fields, never files
IV_BYTES = 12                           # AES-GCM
GCM_TAG_BYTES = 16
PUBLIC_KEY_BYTES = 65                   # uncompressed P-256 point
COMMIT_RE = re.compile(r"^[0-9a-f]{64}$")


def commitment_of(public_key_b64):
    """What a side must have published before revealing this key."""
    return hashlib.sha256(public_key_b64.encode()).hexdigest()

# A request nobody answers lapses, and a call that is never closed out does too,
# so the room never shows a stale prompt.
# A page polls every three seconds; four missed polls and the person is gone.
PRESENCE_WINDOW = timedelta(seconds=12)

VIDEO_REQUEST_TTL = timedelta(seconds=120)
VIDEO_RECORDED_TTL = timedelta(minutes=30)


def _cfg():
    return current_app.config["VERIFIER"]


@bp.before_request
def _allow_a_larger_body_for_proof_uploads():
    if request.endpoint == "room.upload_proof":
        request.max_content_length = _cfg().proof_max_bytes + 1024


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

    # Closed, by hand or by running out of time: say so to everyone, whatever
    # token they hold. A room that expired is finished off right here.
    expires = parse_ts(row["expires_at"])
    if row["closed_at"] or (expires is not None and utcnow() > expires):
        if not row["closed_at"]:
            close_room(conn, code, _cfg().proofs_dir)
            conn.commit()
        return _fail("комната закрыта, все данные удалены", 410)

    supplied = hash_token(request.headers.get("X-Room-Token", ""))
    slot = None
    for candidate in ("a", "b"):
        stored = row[f"{candidate}_token_hash"]
        # Compare against every slot so timing does not reveal which one matched.
        if stored and constant_time_equals(supplied, stored):
            slot = candidate
    if slot is None:
        return _fail("нет доступа к комнате", 401)
    # Any authorised call shows this person is here. The other side sees it as
    # presence; it is wiped with everything else when the room closes.
    conn.execute(f"UPDATE sessions SET {slot}_seen_at=? WHERE code=?",
                 (utcnow().isoformat(), code))
    conn.commit()
    return conn, row, slot


def _side(row, slot):
    seen = parse_ts(row[f"{slot}_seen_at"])
    return {
        "name": row[f"{slot}_name"],
        "verified": bool(row[f"{slot}_verified"]),
        "public_key": row[f"{slot}_pub"] or None,
        "commit": row[f"{slot}_commit"] or None,
        "online": bool(seen and utcnow() - seen <= PRESENCE_WINDOW),
    }


def _video_view(row):
    """The current video verification, or None when idle or lapsed."""
    state, by, at = row["video_state"], row["video_by"], parse_ts(row["video_at"])
    if not state or at is None:
        return None
    now = utcnow()
    if state == "requested" and now - at > VIDEO_REQUEST_TTL:
        return None
    if state == "recorded" and now - at > VIDEO_RECORDED_TTL:
        return None
    view = {"state": state, "by": by, "at": row["video_at"]}
    if state in ("recorded", "confirmed", "denied") and row["proof_iv"]:
        view["proof"] = {"iv": row["proof_iv"], "size": row["proof_size"], "at": row["proof_at"]}
    return view


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
        "video": _video_view(row),
        "items": [
            {"id": i["id"], "from": i["from_slot"], "iv": i["iv"],
             "ciphertext": i["ciphertext"], "created_at": i["created_at"]}
            for i in items
        ],
    })


@bp.route("/commit", methods=["POST"])
def publish_commitment(code):
    """Step one of the key exchange: promise a key without showing it."""
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, row, slot = auth
    commit = (request.get_json(silent=True) or {}).get("commit")
    if not isinstance(commit, str) or not COMMIT_RE.match(commit):
        return _fail("некорректное обязательство", 400)
    cursor = conn.execute(
        f"UPDATE sessions SET {slot}_commit=? WHERE code=? "
        f"AND ({slot}_commit IS NULL OR {slot}_commit='')",
        (commit, code),
    )
    conn.commit()
    if cursor.rowcount == 1 or row[f"{slot}_commit"] == commit:
        return jsonify({"ok": True})
    return _fail("обязательство уже опубликовано и не может быть заменено", 409)


@bp.route("/key", methods=["POST"])
def publish_key(code):
    """Step two: reveal the key, only after both sides have committed."""
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, row, slot = auth
    other = "b" if slot == "a" else "a"
    public_key = (request.get_json(silent=True) or {}).get("public_key")
    if not _valid_public_key(public_key):
        return _fail("некорректный открытый ключ", 400)
    if not row[f"{slot}_commit"]:
        return _fail("сначала опубликуйте обязательство", 409)
    if not row[f"{other}_commit"]:
        return _fail("собеседник ещё не опубликовал обязательство", 409)
    if commitment_of(public_key) != row[f"{slot}_commit"]:
        return _fail("ключ не соответствует опубликованному обязательству", 409)

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


# What may happen to a video verification, and who may do it. The requester is
# the verifier: they asked to see the other person and they decide the outcome.
# The other person answers by recording a short video in their browser; it is
# encrypted there and uploaded as the proof. Every transition is one UPDATE
# that carries its own precondition, so two racing requests cannot both win.
_FREE = (
    "(video_state IS NULL OR video_state IN ('declined','confirmed','denied') "
    "OR (video_state='requested' AND video_at < :request_cutoff) "
    "OR (video_state='recorded' AND video_at < :recorded_cutoff))"
)
_VIDEO_ACTIONS = {
    # action: (new state, precondition)
    "request": ("'requested'", _FREE),
    "cancel":  ("NULL", "video_state='requested' AND video_by=:me"),
    "decline": ("'declined'",
                "video_state='requested' AND video_by=:other AND video_at >= :request_cutoff"),
    "confirm": ("'confirmed'",
                "video_state='recorded' AND video_by=:me AND video_at >= :recorded_cutoff"),
    "deny":    ("'denied'",
                "video_state='recorded' AND video_by=:me AND video_at >= :recorded_cutoff"),
}


def _video_params(code, slot, other, now):
    return {
        "now": now.isoformat(), "code": code, "me": slot, "other": other,
        "request_cutoff": (now - VIDEO_REQUEST_TTL).isoformat(),
        "recorded_cutoff": (now - VIDEO_RECORDED_TTL).isoformat(),
    }


@bp.route("/video", methods=["POST"])
def video(code):
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, row, slot = auth
    other = "b" if slot == "a" else "a"
    action = (request.get_json(silent=True) or {}).get("action")
    if action not in _VIDEO_ACTIONS:
        return _fail("неизвестное действие", 400)

    if action == "request":
        ready = (row["a_verified"] and row["b_verified"] and row["a_pub"] and row["b_pub"])
        if not ready:
            return _fail("собеседник ещё не готов: видеопроверка станет доступна позже", 409)

    new_state, condition = _VIDEO_ACTIONS[action]
    now = utcnow()
    if action == "request":
        # A new request starts clean: the previous proof, if any, is gone.
        delete_proof(_cfg().proofs_dir, code)
        assignment = (f"video_state={new_state}, video_by=:me, video_at=:now, "
                      "proof_iv=NULL, proof_size=NULL, proof_at=NULL")
    elif new_state == "NULL":
        assignment = "video_state=NULL, video_by=NULL, video_at=:now"
    else:
        assignment = f"video_state={new_state}, video_at=:now"
    cursor = conn.execute(
        f"UPDATE sessions SET {assignment} WHERE code=:code AND {condition}",
        _video_params(code, slot, other, now),
    )
    conn.commit()
    if cursor.rowcount != 1:
        return _fail("это действие сейчас недоступно", 409)
    if new_state == "NULL":
        delete_proof(_cfg().proofs_dir, code)
    fresh = conn.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()
    return jsonify({"ok": True, "video": _video_view(fresh)})


@bp.route("/video/proof", methods=["POST"])
def upload_proof(code):
    """The person asked to prove themselves uploads their encrypted recording.

    The body is raw ciphertext (AES-GCM, sealed in the browser under the room
    key); the IV travels in a header. The server cannot play it and keeps one
    file per room, deleted with the room, with the request, or on re-recording.
    """
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, row, slot = auth
    other = "b" if slot == "a" else "a"
    cfg = _cfg()

    iv = request.headers.get("X-Proof-IV", "")
    if _b64(iv, exact=IV_BYTES) is None:
        return _fail("некорректный вектор инициализации", 400)
    # Refuse early when the size is declared; when it is not, the body is still
    # capped as it is read (max_content_length), so nothing unbounded is buffered.
    declared = request.content_length
    if declared is not None and declared > cfg.proof_max_bytes:
        return _fail(f"видео слишком большое (предел {cfg.proof_max_bytes // (1024 * 1024)} МБ)", 413)
    data = request.get_data(cache=False)
    if len(data) <= GCM_TAG_BYTES or len(data) > cfg.proof_max_bytes:
        return _fail("видео пустое или слишком большое", 400)

    now = utcnow()
    # Only the person who was asked, while the request stands or to replace
    # their own earlier recording before it was judged.
    cursor = conn.execute(
        "UPDATE sessions SET video_state='recorded', video_at=:now, proof_iv=:iv, "
        "proof_size=:size, proof_at=:now WHERE code=:code AND video_by=:other AND ("
        "(video_state='requested' AND video_at >= :request_cutoff) OR "
        "(video_state='recorded' AND video_at >= :recorded_cutoff))",
        {**_video_params(code, slot, other, now), "iv": iv, "size": len(data)},
    )
    if cursor.rowcount != 1:
        conn.rollback()
        return _fail("сейчас видео не ожидается", 409)
    path = proof_path(cfg.proofs_dir, code)
    tmp = path + ".part"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    conn.commit()
    fresh = conn.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()
    return jsonify({"ok": True, "video": _video_view(fresh)})


@bp.route("/video/proof", methods=["GET"])
def download_proof(code):
    """Either seat may fetch the ciphertext; only the room key opens it."""
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, row, slot = auth
    view = _video_view(row)
    if not view or "proof" not in view:
        return _fail("видео нет", 404)
    try:
        with open(proof_path(_cfg().proofs_dir, code), "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return _fail("видео нет", 404)
    response = Response(data, mimetype="application/octet-stream")
    response.headers["X-Proof-IV"] = row["proof_iv"]
    response.headers["X-Proof-From"] = "b" if row["video_by"] == "a" else "a"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@bp.route("/close", methods=["POST"])
def close(code):
    """Close the room now and delete everything in it, for both people.

    Items, public keys, seat tokens, names, methods, video state and the proof
    recording are wiped. Both browsers learn of it on their next poll and wipe
    their own copy of the private key.
    """
    auth = _authorize(code)
    if not isinstance(auth, tuple) or len(auth) != 3:
        return auth
    conn, _row, _slot = auth
    close_room(conn, code, _cfg().proofs_dir)
    conn.commit()
    return jsonify({"ok": True})
