"""Administrative panel and its JSON API."""
import base64
import datetime as dt
import secrets

import pyotp
from cryptography.hazmat.primitives import serialization
from flask import (Blueprint, current_app, jsonify, redirect, render_template,
                   request, send_file, session, url_for)

from ..ca import (build_p12, ca_exists, generate_ca, generate_p12_password,
                  issue_user_cert, load_ca)
from ..db import get_db, utcnow
from ..qr import qr_b64
from ..security import (admin_required, clear_rate_limit, client_ip,
                        constant_time_equals, rate_limit)

bp = Blueprint("admin", __name__, url_prefix="/admin")

ALLOWED_ID_EXTRA = {"-", "_"}
MAX_ID_LENGTH = 64
MAX_NAME_LENGTH = 120


def _cfg():
    return current_app.config["VERIFIER"]


def _valid_user_id(value):
    if not value or len(value) > MAX_ID_LENGTH:
        return False
    return all(ch.isalnum() or ch in ALLOWED_ID_EXTRA for ch in value)


@bp.route("/login", methods=["GET", "POST"])
def admin_login():
    cfg = _cfg()
    error = None
    if request.method == "POST":
        allowed, retry = rate_limit("admin_login", client_ip(), cfg.rl_admin_login)
        if not allowed:
            error = f"Слишком много попыток. Повторите через {retry} с."
            return render_template("admin_login.html", error=error), 429

        supplied = request.form.get("password", "")
        if constant_time_equals(supplied, cfg.admin_secret):
            session.clear()
            session["is_admin"] = True
            session.permanent = False
            clear_rate_limit("admin_login", client_ip())
            return redirect(url_for("admin.admin_panel"))
        error = "Неверный пароль"
    return render_template("admin_login.html", error=error)


@bp.route("/logout", methods=["GET", "POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin.admin_login"))


@bp.route("")
@bp.route("/")
@admin_required
def admin_panel():
    users = get_db().execute(
        "SELECT id, name, totp_secret, serial, revoked, created_at "
        "FROM users ORDER BY created_at DESC"
    ).fetchall()
    return render_template("admin.html", users=users, ca_ok=ca_exists(_cfg()))


@bp.route("/api/init-ca", methods=["POST"])
@admin_required
def api_init_ca():
    cfg = _cfg()
    if ca_exists(cfg):
        return jsonify({"ok": False, "reason": "CA уже существует"})
    generate_ca(cfg)
    return jsonify({"ok": True})


@bp.route("/api/ca-cert")
@admin_required
def api_ca_cert():
    return send_file(_cfg().ca_cert_path, as_attachment=True, download_name="ca.crt")


@bp.route("/api/register", methods=["POST"])
@admin_required
def api_register():
    cfg = _cfg()
    data = request.get_json(silent=True) or {}
    user_id = str(data.get("user_id", "")).strip()
    name = str(data.get("name", "")).strip()

    if not user_id or not name:
        return jsonify({"ok": False, "reason": "user_id и name обязательны"})
    if not _valid_user_id(user_id):
        return jsonify({"ok": False, "reason": "ID: только буквы, цифры, - и _"})
    if len(name) > MAX_NAME_LENGTH:
        return jsonify({"ok": False, "reason": "слишком длинное имя"})
    if not ca_exists(cfg):
        return jsonify({"ok": False, "reason": "Сначала создайте CA"})

    conn = get_db()
    if conn.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
        return jsonify({"ok": False, "reason": f"{user_id} уже существует"})

    ca_key, ca_cert = load_ca(cfg)
    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
        name=name, issuer_name="Verifier")

    cert, user_key, serial_hex = issue_user_cert(cfg, ca_key, ca_cert, user_id, name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    p12_password = generate_p12_password()
    p12_b64 = base64.b64encode(
        build_p12(name, user_key, cert, ca_cert, p12_password)
    ).decode()

    dl_token = secrets.token_urlsafe(32)
    now = utcnow()
    expires = now + dt.timedelta(hours=cfg.download_ttl_hours)

    conn.execute(
        "INSERT INTO users (id, name, totp_secret, cert_pem, serial, p12_b64, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (user_id, name, totp_secret, cert_pem, serial_hex, p12_b64, now.isoformat()),
    )
    conn.execute(
        "INSERT INTO download_tokens (token, user_id, created_at, expires_at) "
        "VALUES (?,?,?,?)",
        (dl_token, user_id, now.isoformat(), expires.isoformat()),
    )
    conn.commit()

    base_url = request.host_url.rstrip("/")
    download_url = f"{base_url}/download/{dl_token}"
    return jsonify({
        "ok": True,
        "user_id": user_id,
        "name": name,
        "totp_secret": totp_secret,
        "qr_totp_b64": qr_b64(totp_uri),
        "download_url": download_url,
        "qr_download_b64": qr_b64(download_url),
        "p12_password": p12_password,
        "cert_pem": cert_pem,
        "serial": serial_hex,
        "valid_until": (now + dt.timedelta(days=cfg.cert_valid_days)).strftime("%d.%m.%Y"),
    })


@bp.route("/api/user/<user_id>")
@admin_required
def api_user_detail(user_id):
    user = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return jsonify({"ok": False, "reason": "не найден"}), 404
    totp_uri = pyotp.TOTP(user["totp_secret"]).provisioning_uri(
        name=user["name"], issuer_name="Verifier")
    return jsonify({
        "ok": True, "user_id": user["id"], "name": user["name"],
        "totp_secret": user["totp_secret"],
        "qr_totp_b64": qr_b64(totp_uri),
        "cert_pem": user["cert_pem"], "serial": user["serial"],
        "revoked": bool(user["revoked"]), "created_at": user["created_at"],
    })


def _set_revoked(flag):
    data = request.get_json(silent=True) or {}
    user_id = str(data.get("user_id", "")).strip()
    if not user_id:
        return jsonify({"ok": False, "reason": "user_id обязателен"}), 400
    conn = get_db()
    cursor = conn.execute("UPDATE users SET revoked=? WHERE id=?", (flag, user_id))
    if cursor.rowcount == 0:
        return jsonify({"ok": False, "reason": "пользователь не найден"}), 404
    if flag:
        # A revoked user must not keep a live download link.
        conn.execute("UPDATE download_tokens SET used=1 WHERE user_id=?", (user_id,))
    conn.commit()
    return jsonify({"ok": True})


@bp.route("/api/revoke", methods=["POST"])
@admin_required
def api_revoke():
    return _set_revoked(1)


@bp.route("/api/restore", methods=["POST"])
@admin_required
def api_restore():
    return _set_revoked(0)
