"""Public API: pairing sessions and the three verification methods."""
import base64
import datetime as dt
import secrets

import pyotp
from flask import Blueprint, current_app, jsonify, request

from ..ca import load_ca_cert
from ..certs import CertError, authenticate_by_challenge, lookup_user
from ..db import get_db, parse_ts, purge_expired, utcnow
from ..mtls import authenticated_client_cert
from ..security import client_ip, rate_limit

bp = Blueprint("api", __name__)

# Unambiguous alphabet: no I, O, 0 or 1, because people read these aloud.
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 8


def _cfg():
    return current_app.config["VERIFIER"]


def _json_body():
    return request.get_json(silent=True) or {}


def _too_many(retry_after):
    response = jsonify({
        "ok": False,
        "reason": f"слишком много попыток, повторите через {retry_after} с",
    })
    response.status_code = 429
    response.headers["Retry-After"] = str(retry_after)
    return response


def new_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def _load_session(conn, code):
    return conn.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()


def _session_expired(row):
    expires = parse_ts(row["expires_at"])
    return expires is not None and utcnow() > expires


def record_verification(conn, code, user_id, name, method):
    """Claim a free slot for this user atomically.

    The UPDATE carries its own precondition, so two simultaneous requests
    cannot both take side A.
    """
    row = _load_session(conn, code)
    if row is None:
        return None
    if row["user_a"] == user_id or row["user_b"] == user_id:
        return None

    for slot in ("a", "b"):
        if slot == "a":
            sql = (
                "UPDATE sessions SET user_a=?, a_name=?, a_verified=1, a_method=? "
                "WHERE code=? AND (user_a IS NULL OR user_a='') AND "
                "(user_b IS NULL OR user_b<>?)"
            )
        else:
            sql = (
                "UPDATE sessions SET user_b=?, b_name=?, b_verified=1, b_method=? "
                "WHERE code=? AND (user_b IS NULL OR user_b='') AND "
                "(user_a IS NULL OR user_a<>?)"
            )
        cursor = conn.execute(sql, (user_id, name, method, code, user_id))
        if cursor.rowcount == 1:
            conn.commit()
            return slot
    conn.commit()
    return None


@bp.route("/api/session/create", methods=["POST"])
def create_session():
    cfg = _cfg()
    allowed, retry = rate_limit("session_create", client_ip(), (60, 300))
    if not allowed:
        return _too_many(retry)

    conn = get_db()
    purge_expired(conn, cfg.nonce_ttl_seconds)
    now = utcnow()
    expires = now + dt.timedelta(minutes=cfg.session_ttl_minutes)
    for _ in range(5):
        code = new_code()
        try:
            conn.execute(
                "INSERT INTO sessions (code, created_at, expires_at) VALUES (?,?,?)",
                (code, now.isoformat(), expires.isoformat()),
            )
            conn.commit()
            break
        except Exception:
            continue
    else:
        return jsonify({"ok": False, "reason": "не удалось создать сессию"}), 500
    return jsonify({
        "code": code,
        "expires_in_minutes": cfg.session_ttl_minutes,
        "code_length": CODE_LENGTH,
    })


@bp.route("/api/session/<code>/status")
def session_status(code):
    cfg = _cfg()
    allowed, retry = rate_limit("status", client_ip(), cfg.rl_status)
    if not allowed:
        return _too_many(retry)

    row = _load_session(get_db(), code)
    if not row:
        return jsonify({"error": "не найдено"}), 404
    if _session_expired(row):
        return jsonify({"status": "expired"})
    both = bool(row["a_verified"] and row["b_verified"])
    return jsonify({
        "status": "both_verified" if both else "pending",
        "side_a": {"name": row["a_name"], "verified": bool(row["a_verified"]),
                   "method": row["a_method"]},
        "side_b": {"name": row["b_name"], "verified": bool(row["b_verified"]),
                   "method": row["b_method"]},
    })


@bp.route("/api/nonce")
def get_nonce():
    cfg = _cfg()
    allowed, retry = rate_limit("nonce", client_ip(), (60, 300))
    if not allowed:
        return _too_many(retry)

    conn = get_db()
    purge_expired(conn, cfg.nonce_ttl_seconds)
    nonce = secrets.token_hex(32)
    conn.execute(
        "INSERT INTO nonces VALUES (?,?)", (nonce, utcnow().isoformat())
    )
    conn.commit()
    return jsonify({"nonce": nonce, "ttl_seconds": cfg.nonce_ttl_seconds})


@bp.route("/api/session/<code>/verify/totp", methods=["POST"])
def verify_totp(code):
    cfg = _cfg()
    data = _json_body()
    user_id = str(data.get("user_id", "")).strip()
    otp = str(data.get("code", "")).strip()

    allowed, retry = rate_limit("totp", f"{client_ip()}|{user_id}", cfg.rl_totp)
    if not allowed:
        return _too_many(retry)

    conn = get_db()
    row = _load_session(conn, code)
    if not row:
        return jsonify({"ok": False, "reason": "сессия не найдена"}), 404
    if _session_expired(row):
        return jsonify({"ok": False, "reason": "сессия истекла"})

    user = conn.execute(
        "SELECT * FROM users WHERE id=? AND revoked=0", (user_id,)
    ).fetchone()
    # One message for both cases, so the endpoint cannot be used to enumerate IDs.
    if not user or not user["totp_secret"] or not otp:
        return jsonify({"ok": False, "reason": "неверный ID или код"})
    if not pyotp.TOTP(user["totp_secret"]).verify(otp, valid_window=1):
        return jsonify({"ok": False, "reason": "неверный ID или код"})

    slot = record_verification(conn, code, user_id, user["name"], "TOTP")
    if slot is None:
        return jsonify({"ok": False, "reason": "уже верифицированы или мест нет"})
    return jsonify({"ok": True, "name": user["name"], "slot": slot})


@bp.route("/api/session/<code>/verify/cert", methods=["POST"])
def verify_cert(code):
    """Challenge-response: the caller signs a server nonce with their key."""
    cfg = _cfg()
    data = _json_body()
    user_id = str(data.get("user_id", "")).strip() or None
    cert_pem = data.get("cert_pem")
    nonce = data.get("nonce")
    signature_b64 = data.get("signature_b64")

    allowed, retry = rate_limit("cert", client_ip(), cfg.rl_mtls)
    if not allowed:
        return _too_many(retry)

    conn = get_db()
    row = _load_session(conn, code)
    if not row:
        return jsonify({"ok": False, "reason": "сессия не найдена"}), 404
    if _session_expired(row):
        return jsonify({"ok": False, "reason": "сессия истекла"})

    try:
        signature = base64.b64decode(signature_b64 or "", validate=True)
    except Exception:
        return jsonify({"ok": False, "reason": "подпись повреждена"})

    try:
        user = authenticate_by_challenge(
            cfg, load_ca_cert(cfg), cert_pem, nonce, signature, user_id
        )
    except CertError as exc:
        return jsonify({"ok": False, "reason": str(exc)})

    slot = record_verification(conn, code, user["id"], user["name"], "Сертификат")
    if slot is None:
        return jsonify({"ok": False, "reason": "уже верифицированы или мест нет"})
    return jsonify({"ok": True, "name": user["name"], "slot": slot})


@bp.route("/api/session/<code>/verify/mtls", methods=["POST"])
def verify_mtls(code):
    """Device certificate presented through a mutual-TLS handshake."""
    cfg = _cfg()
    allowed, retry = rate_limit("mtls", client_ip(), cfg.rl_mtls)
    if not allowed:
        return _too_many(retry)

    conn = get_db()
    row = _load_session(conn, code)
    if not row:
        return jsonify({"ok": False, "reason": "сессия не найдена"}), 404
    if _session_expired(row):
        return jsonify({"ok": False, "reason": "сессия истекла"})

    try:
        cert = authenticated_client_cert(cfg, load_ca_cert(cfg))
        user = lookup_user(cert)
    except CertError as exc:
        return jsonify({
            "ok": False,
            "reason": str(exc),
            "hint": "убедитесь что HTTPS включён и сертификат установлен на устройстве",
        })

    slot = record_verification(conn, code, user["id"], user["name"], "mTLS (авто)")
    if slot is None:
        return jsonify({"ok": False, "reason": "уже верифицированы в этой сессии"})
    return jsonify({"ok": True, "name": user["name"], "method": "mtls", "slot": slot})
