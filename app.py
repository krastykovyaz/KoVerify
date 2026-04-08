import os, secrets, base64, io, ssl
import datetime as dt
from datetime import datetime, timezone
from functools import wraps
import sqlite3

import pyotp
import qrcode
from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, session, abort, send_file)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

CA_KEY_PATH  = "ca/ca.key"
CA_CERT_PATH = "ca/ca.crt"
# Отдельный сертификат сервера для HTTPS (не CA!)
SRV_KEY_PATH  = "ca/server.key"
SRV_CERT_PATH = "ca/server.crt"
DB_PATH      = "db.sqlite"
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "admin123")

# ─────────────────────────────────────────────────────────────
#  БД
# ─────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = get_db()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            totp_secret  TEXT,
            cert_pem     TEXT,
            serial       TEXT,
            p12_b64      TEXT,
            revoked      INTEGER DEFAULT 0,
            created_at   TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            code        TEXT PRIMARY KEY,
            user_a      TEXT,
            user_b      TEXT,
            a_verified  INTEGER DEFAULT 0,
            b_verified  INTEGER DEFAULT 0,
            a_name      TEXT,
            b_name      TEXT,
            a_method    TEXT,
            b_method    TEXT,
            created_at  TEXT,
            expires_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS nonces (
            nonce      TEXT PRIMARY KEY,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS download_tokens (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            used       INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
    """)
    c.commit()

# ─────────────────────────────────────────────────────────────
#  CA и серверный сертификат
# ─────────────────────────────────────────────────────────────

def ca_exists():
    return os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH)

def generate_ca():
    os.makedirs("ca", exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,       "VerifierCA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Verifier"),
        ]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "VerifierCA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # Сразу генерируем серверный сертификат подписанный CA
    _generate_server_cert(key, cert)

def _generate_server_cert(ca_key, ca_cert):
    """Серверный сертификат для HTTPS (localhost + IP)."""
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(SRV_KEY_PATH, "wb") as f:
        f.write(srv_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName("secure.fin-tech.com"),
        x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ipaddress.IPv6Address("::1"),  # localhost IPv6
    ])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + dt.timedelta(days=825))
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    with open(SRV_CERT_PATH, "wb") as f:
        f.write(srv_cert.public_bytes(serialization.Encoding.PEM))

def load_ca():
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

def make_ssl_context():
    """SSL-контекст для Flask: HTTPS + запрос клиентских сертификатов."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SRV_CERT_PATH, SRV_KEY_PATH)
    ctx.load_verify_locations(CA_CERT_PATH)   # какие клиентские сертификаты принимаем
    ctx.verify_mode = ssl.CERT_OPTIONAL        # запрашиваем но не требуем
    return ctx

# ─────────────────────────────────────────────────────────────
#  Вспомогательные функции
# ─────────────────────────────────────────────────────────────

def _assign_slot(row, user_id):
    if row["user_a"] == user_id or row["user_b"] == user_id:
        return None
    if not row["user_a"]:
        return "a"
    if not row["user_b"] and row["user_a"] != user_id:
        return "b"
    return None

def _check_cert(cert_pem, nonce, sig_b64, expected_user_id):
    if not all([cert_pem, nonce, sig_b64]):
        return {"ok": False, "reason": "неполные данные"}
    c = get_db()
    if not c.execute("SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone():
        return {"ok": False, "reason": "nonce истёк или уже использован"}
    c.execute("DELETE FROM nonces WHERE nonce=?", (nonce,))
    c.commit()
    try:
        cert = load_pem_x509_certificate(cert_pem.encode())
        with open(CA_CERT_PATH, "rb") as f:
            ca = load_pem_x509_certificate(f.read())
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm)
        now = datetime.now(timezone.utc)
        if not (cert.not_valid_before_utc < now < cert.not_valid_after_utc):
            return {"ok": False, "reason": "сертификат просрочен"}
        serial = format(cert.serial_number, "x")
        user = c.execute(
            "SELECT id, name, revoked FROM users WHERE serial=?", (serial,)
        ).fetchone()
        if not user or user["revoked"]:
            return {"ok": False, "reason": "сертификат не найден или отозван"}
        if user["id"] != expected_user_id:
            return {"ok": False, "reason": "сертификат принадлежит другому пользователю"}
        cert.public_key().verify(base64.b64decode(sig_b64), nonce.encode(),
            padding.PKCS1v15(), hashes.SHA256())
        return {"ok": True, "name": user["name"]}
    except Exception as e:
        return {"ok": False, "reason": str(e)}

def _make_mobileconfig(name, user_id, p12_b64, password=""):
    pu = secrets.token_hex(16).upper()
    cu = secrets.token_hex(16).upper()
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadContent</key><array><dict>
    <key>PayloadType</key><string>com.apple.security.pkcs12</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>PayloadIdentifier</key><string>com.verifier.cert.{user_id}</string>
    <key>PayloadUUID</key><string>{cu}</string>
    <key>PayloadDisplayName</key><string>Verifier — {name}</string>
    <key>PayloadContent</key><data>{p12_b64}</data>
    <key>Password</key><string>{password}</string>
  </dict></array>
  <key>PayloadDisplayName</key><string>Verifier — {name}</string>
  <key>PayloadIdentifier</key><string>com.verifier.profile.{user_id}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{pu}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadOrganization</key><string>Verifier</string>
</dict></plist>"""

def _make_qr_b64(data: str) -> str:
    qr  = qrcode.make(data)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def _read_client_cert_from_environ():
    """
    Читает клиентский сертификат из Flask/werkzeug environ.
    werkzeug передаёт его как PEM-строку в SSL_CLIENT_CERT.
    """
    raw = (request.environ.get("SSL_CLIENT_CERT")
           or request.environ.get("HTTP_X_SSL_CLIENT_CERT"))
    if not raw:
        return None
    if isinstance(raw, str):
        raw = raw.encode()
    try:
        return load_pem_x509_certificate(raw)
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────
#  Защита админки
# ─────────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────────────────
#  СТРАНИЦЫ
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/session/<code>")
def verify_page(code):
    return render_template("verify.html", code=code)

@app.route("/result/<code>")
def result_page(code):
    return render_template("result.html", code=code)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == ADMIN_SECRET:
            session["is_admin"] = True
            return redirect(url_for("admin_panel"))
        error = "Неверный пароль"
    return render_template("admin_login.html", error=error)

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_panel():
    print("----- ADMIN PANEL REQUEST RECEIVED -----")  # ←
    c     = get_db()
    users = c.execute(
        "SELECT id, name, totp_secret, serial, revoked, created_at "
        "FROM users ORDER BY created_at DESC"
    ).fetchall()
    print("USERS COUNT:", len(users))  # ←
    return render_template("admin.html", users=users, ca_ok=ca_exists())

# ─────────────────────────────────────────────────────────────
#  ADMIN API
# ─────────────────────────────────────────────────────────────

@app.route("/admin/api/init-ca", methods=["POST"])
@admin_required
def api_init_ca():
    if ca_exists():
        return jsonify({"ok": False, "reason": "CA уже существует"})
    generate_ca()
    return jsonify({"ok": True})

@app.route("/admin/api/ca-cert")
@admin_required
def api_ca_cert():
    return send_file(CA_CERT_PATH, as_attachment=True, download_name="ca.crt")

@app.route("/admin/api/register", methods=["POST"])
@admin_required
def api_register():
    data    = request.get_json()
    user_id = data.get("user_id", "").strip()
    name    = data.get("name", "").strip()

    if not user_id or not name:
        return jsonify({"ok": False, "reason": "user_id и name обязательны"})
    if not user_id.replace("-","").replace("_","").isalnum():
        return jsonify({"ok": False, "reason": "ID: только буквы, цифры, - и _"})

    c = get_db()
    if c.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
        return jsonify({"ok": False, "reason": f"{user_id} уже существует"})
    if not ca_exists():
        return jsonify({"ok": False, "reason": "Сначала создайте CA"})

    ca_key, ca_cert = load_ca()
    totp_secret = pyotp.random_base32()
    totp_uri    = pyotp.TOTP(totp_secret).provisioning_uri(
        name=name, issuer_name="Verifier")

    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serial   = x509.random_serial_number()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,       name),
            x509.NameAttribute(NameOID.SERIAL_NUMBER,     user_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Verifier"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + dt.timedelta(days=730))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(f"{user_id}@verifier")]),
            critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem   = cert.public_bytes(serialization.Encoding.PEM).decode()
    serial_hex = format(serial, "x")

    p12_password = secrets.token_hex(4)
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=name.encode(), key=user_key, cert=cert, cas=[ca_cert],
        encryption_algorithm=BestAvailableEncryption(p12_password.encode())
    )
    p12_b64 = base64.b64encode(p12_bytes).decode()

    dl_token = secrets.token_urlsafe(32)
    now      = datetime.now(timezone.utc)
    expires  = now + dt.timedelta(hours=24)

    c.execute("""
        INSERT INTO users (id, name, totp_secret, cert_pem, serial, p12_b64, created_at)
        VALUES (?,?,?,?,?,?,?)
    """, (user_id, name, totp_secret, cert_pem, serial_hex, p12_b64, now.isoformat()))
    c.execute("""
        INSERT INTO download_tokens (token, user_id, created_at, expires_at)
        VALUES (?,?,?,?)
    """, (dl_token, user_id, now.isoformat(), expires.isoformat()))
    c.commit()

    base_url     = request.host_url.rstrip("/")
    download_url = f"{base_url}/download/{dl_token}"
    return jsonify({
        "ok":              True,
        "user_id":         user_id,
        "name":            name,
        "totp_secret":     totp_secret,
        "qr_totp_b64":     _make_qr_b64(totp_uri),
        "download_url":    download_url,
        "qr_download_b64": _make_qr_b64(download_url),
        "p12_password":    p12_password,
        "cert_pem":        cert_pem,
        "serial":          serial_hex,
        "valid_until":     (now + dt.timedelta(days=730)).strftime("%d.%m.%Y"),
    })

@app.route("/admin/api/user/<user_id>")
@admin_required
def api_user_detail(user_id):
    c    = get_db()
    user = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return jsonify({"ok": False, "reason": "не найден"}), 404
    totp_uri = pyotp.TOTP(user["totp_secret"]).provisioning_uri(
        name=user["name"], issuer_name="Verifier")
    return jsonify({
        "ok": True, "user_id": user["id"], "name": user["name"],
        "totp_secret": user["totp_secret"],
        "qr_totp_b64": _make_qr_b64(totp_uri),
        "cert_pem": user["cert_pem"], "serial": user["serial"],
        "revoked": bool(user["revoked"]), "created_at": user["created_at"],
    })

@app.route("/admin/api/revoke", methods=["POST"])
@admin_required
def api_revoke():
    user_id = request.get_json().get("user_id")
    c = get_db()
    c.execute("UPDATE users SET revoked=1 WHERE id=?", (user_id,))
    c.commit()
    return jsonify({"ok": True})

@app.route("/admin/api/restore", methods=["POST"])
@admin_required
def api_restore():
    user_id = request.get_json().get("user_id")
    c = get_db()
    c.execute("UPDATE users SET revoked=0 WHERE id=?", (user_id,))
    c.commit()
    return jsonify({"ok": True})

# ─────────────────────────────────────────────────────────────
#  СКАЧИВАНИЕ КЛЮЧЕЙ
# ─────────────────────────────────────────────────────────────

def _get_dl(token):
    c = get_db()
    row = c.execute("""
        SELECT dt.*, u.name, u.p12_b64, u.totp_secret, u.id as user_id
        FROM download_tokens dt
        JOIN users u ON dt.user_id = u.id
        WHERE dt.token = ?
    """, (token,)).fetchone()
    return c, row

@app.route("/download/<token>")
def download_page(token):
    c, row = _get_dl(token)
    if not row:
        return render_template("download_error.html", error="Ссылка недействительна"), 404
    if row["used"]:
        return render_template("download_error.html",
            error="Ссылка уже использована. Попросите новую у администратора."), 410
    if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
        return render_template("download_error.html", error="Ссылка истекла (24 часа)"), 410
    totp_uri = pyotp.TOTP(row["totp_secret"]).provisioning_uri(
        name=row["name"], issuer_name="Verifier")
    return render_template("download.html",
        token=token, name=row["name"], user_id=row["user_id"],
        qr_totp_b64=_make_qr_b64(totp_uri),
        totp_secret=row["totp_secret"])

@app.route("/download/<token>/p12")
def download_p12(token):
    c, row = _get_dl(token)
    if not row or row["used"]:
        return "Ссылка недействительна или уже использована", 410
    if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
        return "Ссылка истекла", 410
    c.execute("UPDATE download_tokens SET used=1 WHERE token=?", (token,))
    c.commit()
    buf = io.BytesIO(base64.b64decode(row["p12_b64"]))
    buf.seek(0)
    return send_file(buf, mimetype="application/x-pkcs12",
                     as_attachment=True, download_name=f"{row['user_id']}-verifier.p12")

@app.route("/download/<token>/mobileconfig")
def download_mobileconfig(token):
    c, row = _get_dl(token)
    if not row:
        return "Ссылка недействительна", 404
    if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
        return "Ссылка истекла", 410
    mc  = _make_mobileconfig(row["name"], row["user_id"], row["p12_b64"])
    buf = io.BytesIO(mc.encode())
    buf.seek(0)
    return send_file(buf, mimetype="application/x-apple-aspen-config",
                     as_attachment=True, download_name=f"{row['user_id']}-verifier.mobileconfig")

# ─────────────────────────────────────────────────────────────
#  PUBLIC API — сессии
# ─────────────────────────────────────────────────────────────

@app.route("/api/session/create", methods=["POST"])
def create_session():
    code = secrets.token_hex(3).upper()
    now  = datetime.now(timezone.utc)
    c    = get_db()
    c.execute("INSERT INTO sessions (code, created_at, expires_at) VALUES (?,?,?)",
              (code, now.isoformat(), (now + dt.timedelta(minutes=30)).isoformat()))
    c.commit()
    return jsonify({"code": code, "expires_in_minutes": 30})

@app.route("/api/session/<code>/status")
def session_status(code):
    c   = get_db()
    row = c.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()
    if not row:
        return jsonify({"error": "не найдено"}), 404
    if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
        return jsonify({"status": "expired"})
    both = bool(row["a_verified"] and row["b_verified"])
    return jsonify({
        "status": "both_verified" if both else "pending",
        "side_a": {"name": row["a_name"], "verified": bool(row["a_verified"]), "method": row["a_method"]},
        "side_b": {"name": row["b_name"], "verified": bool(row["b_verified"]), "method": row["b_method"]},
    })

@app.route("/api/nonce")
def get_nonce():
    n = secrets.token_hex(32)
    c = get_db()
    c.execute("INSERT INTO nonces VALUES (?,?)", (n, datetime.now(timezone.utc).isoformat()))
    c.execute("DELETE FROM nonces WHERE created_at < datetime('now','-5 minutes')")
    c.commit()
    return jsonify({"nonce": n})

@app.route("/api/session/<code>/verify/totp", methods=["POST"])
def verify_totp(code):
    data    = request.get_json()
    user_id = data.get("user_id", "").strip()
    otp     = data.get("code", "").strip()
    c   = get_db()
    row = c.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()
    if not row:
        return jsonify({"ok": False, "reason": "сессия не найдена"}), 404
    if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
        return jsonify({"ok": False, "reason": "сессия истекла"})
    user = c.execute("SELECT * FROM users WHERE id=? AND revoked=0", (user_id,)).fetchone()
    if not user or not user["totp_secret"]:
        return jsonify({"ok": False, "reason": "пользователь не найден"})
    if not pyotp.TOTP(user["totp_secret"]).verify(otp, valid_window=1):
        return jsonify({"ok": False, "reason": "неверный код"})
    slot = _assign_slot(row, user_id)
    if slot is None:
        return jsonify({"ok": False, "reason": "уже верифицированы"})
    col = "a" if slot == "a" else "b"
    c.execute(f"UPDATE sessions SET user_{col}=?, {col}_name=?, {col}_verified=1, {col}_method='TOTP' WHERE code=?",
              (user_id, user["name"], code))
    c.commit()
    return jsonify({"ok": True, "name": user["name"], "slot": slot})

@app.route("/api/session/<code>/verify/mtls", methods=["POST"])
def verify_mtls(code):
    """
    Браузер автоматически предъявляет клиентский сертификат при mTLS.

    Режим 1 — продакшн (nginx): заголовки X-SSL-Client-*
    Режим 2 — локально (Flask HTTPS): environ SSL_CLIENT_CERT
    """
    user_id       = None
    client_serial = ""

    # Режим 1: nginx передаёт данные в заголовках
    if request.headers.get("X-SSL-Client-Verify") == "SUCCESS":
        client_dn     = request.headers.get("X-SSL-Client-S-DN", "")
        client_serial = request.headers.get("X-SSL-Client-Serial", "").lower().lstrip("0")
        for part in client_dn.split(","):
            if part.strip().upper().startswith("SERIALNUMBER="):
                user_id = part.strip().split("=", 1)[1]
                break

    # Режим 2: Flask HTTPS — werkzeug передаёт объект сертификата
    if not user_id:
        cert_obj = _read_client_cert_from_environ()
        if cert_obj:
            client_serial = format(cert_obj.serial_number, "x").lower().lstrip("0")
            for attr in cert_obj.subject:
                if attr.oid == NameOID.SERIAL_NUMBER:
                    user_id = attr.value
                    break

    if not user_id:
        return jsonify({
            "ok":     False,
            "reason": "сертификат не предоставлен",
            "hint":   "убедитесь что HTTPS включён и сертификат установлен на устройстве"
        })

    c   = get_db()
    row = c.execute("SELECT * FROM sessions WHERE code=?", (code,)).fetchone()
    if not row:
        return jsonify({"ok": False, "reason": "сессия не найдена"}), 404
    if datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
        return jsonify({"ok": False, "reason": "сессия истекла"})
    user = c.execute("SELECT * FROM users WHERE id=? AND revoked=0", (user_id,)).fetchone()
    if not user:
        return jsonify({"ok": False, "reason": "пользователь не найден или отозван"})
    db_serial = (user["serial"] or "").lower().lstrip("0")
    if client_serial and db_serial and client_serial != db_serial:
        return jsonify({"ok": False, "reason": "серийный номер не совпадает"})
    slot = _assign_slot(row, user_id)
    if slot is None:
        return jsonify({"ok": False, "reason": "уже верифицированы в этой сессии"})
    col = "a" if slot == "a" else "b"
    c.execute(f"UPDATE sessions SET user_{col}=?, {col}_name=?, {col}_verified=1, {col}_method='mTLS (авто)' WHERE code=?",
              (user_id, user["name"], code))
    c.commit()
    return jsonify({"ok": True, "name": user["name"], "method": "mtls"})

# ─────────────────────────────────────────────────────────────
#  ЗАПУСК
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("ca", exist_ok=True)
    init_db()
    if not ca_exists():
        print("Генерируем CA и серверный сертификат...")
        generate_ca()
        print("CA создан: ca/ca.key, ca/ca.crt")
        print("Серверный сертификат: ca/server.key, ca/server.crt")

    print(f"""
  ┌─────────────────────────────────────────────────┐
  │  Верификатор запущен (HTTPS + mTLS)             │
  │                                                 │
  │  Сайт:    https://localhost:5000                │
  │  Админка: https://localhost:5000/admin          │
  │  Пароль:  {ADMIN_SECRET:<37} │
  │                                                 │
  │  ВАЖНО: добавьте ca/ca.crt в доверенные         │
  │  сертификаты браузера (инструкция ниже)         │
  └─────────────────────────────────────────────────┘
""")
    ssl_ctx = make_ssl_context()
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=ssl_ctx)
    # app.run(debug=True, host="0.0.0.0", port=5000)