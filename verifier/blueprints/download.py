"""One-time credential delivery links."""
import base64
import io

import pyotp
from flask import Blueprint, current_app, render_template, send_file

from ..db import get_db, parse_ts, utcnow
from ..mobileconfig import build as build_mobileconfig
from ..qr import qr_b64
from ..security import client_ip, rate_limit

bp = Blueprint("download", __name__, url_prefix="/download")


def _cfg():
    return current_app.config["VERIFIER"]


def _fetch(token):
    return get_db().execute(
        "SELECT dt.token, dt.used, dt.expires_at, u.name, u.p12_b64, "
        "       u.totp_secret, u.id AS user_id, u.revoked "
        "FROM download_tokens dt JOIN users u ON dt.user_id = u.id "
        "WHERE dt.token = ?",
        (token,),
    ).fetchone()


def _expired(row):
    expires = parse_ts(row["expires_at"])
    return expires is not None and utcnow() > expires


def _consume(token):
    """Spend the link. Returns True only for the caller that won the race."""
    conn = get_db()
    cursor = conn.execute(
        "UPDATE download_tokens SET used=1 WHERE token=? AND used=0", (token,)
    )
    conn.commit()
    return cursor.rowcount == 1


def _error(message, status):
    return render_template("download_error.html", error=message), status


@bp.route("/<token>")
def download_page(token):
    allowed, retry = rate_limit("download", client_ip(), (60, 300))
    if not allowed:
        return _error(f"Слишком много запросов. Повторите через {retry} с.", 429)

    row = _fetch(token)
    if not row or row["revoked"]:
        return _error("Ссылка недействительна", 404)
    if row["used"]:
        return _error(
            "Ссылка уже использована. Попросите новую у администратора.", 410)
    if _expired(row):
        return _error(
            f"Ссылка истекла ({_cfg().download_ttl_hours} часа)", 410)

    totp_uri = pyotp.TOTP(row["totp_secret"]).provisioning_uri(
        name=row["name"], issuer_name="Verifier")
    return render_template(
        "download.html", token=token, name=row["name"], user_id=row["user_id"],
        qr_totp_b64=qr_b64(totp_uri), totp_secret=row["totp_secret"],
    )


def _deliver(token, builder, mimetype, suffix):
    """Shared delivery path for every credential artifact.

    Both artifacts carry the same private key, so both spend the same one-time
    link. Previously the profile route ignored the flag entirely, which let a
    consumed link keep handing out credentials indefinitely.
    """
    allowed, retry = rate_limit("download", client_ip(), (60, 300))
    if not allowed:
        return "Слишком много запросов", 429

    row = _fetch(token)
    if not row or row["revoked"]:
        return "Ссылка недействительна", 404
    if row["used"]:
        return "Ссылка недействительна или уже использована", 410
    if _expired(row):
        return "Ссылка истекла", 410
    if not _consume(token):
        return "Ссылка недействительна или уже использована", 410

    payload = builder(row)
    buffer = io.BytesIO(payload)
    buffer.seek(0)
    response = send_file(
        buffer, mimetype=mimetype, as_attachment=True,
        download_name=f"{row['user_id']}-verifier{suffix}",
    )
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@bp.route("/<token>/p12")
def download_p12(token):
    return _deliver(
        token,
        lambda row: base64.b64decode(row["p12_b64"]),
        "application/x-pkcs12",
        ".p12",
    )


@bp.route("/<token>/mobileconfig")
def download_mobileconfig(token):
    return _deliver(
        token,
        lambda row: build_mobileconfig(
            row["name"], row["user_id"], row["p12_b64"]).encode(),
        "application/x-apple-aspen-config",
        ".mobileconfig",
    )
