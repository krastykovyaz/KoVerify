"""Client certificate validation.

Presenting a certificate proves nothing on its own: certificates are public.
A caller is only authenticated when one of these holds.

  * They signed a server-issued nonce with the matching private key, which
    proves possession directly.
  * A trusted reverse proxy completed a mutual-TLS handshake for this request
    and told us so, and the certificate it forwarded validates against our CA.

Anything arriving in a header from an untrusted source is discarded.
"""
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.x509.oid import NameOID

from .db import get_db, parse_ts, utcnow


class CertError(Exception):
    """Certificate rejected. The message is safe to show to the caller."""


def parse_pem(cert_pem):
    if not cert_pem:
        raise CertError("сертификат не предоставлен")
    raw = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
    try:
        return x509.load_pem_x509_certificate(raw)
    except Exception:
        raise CertError("сертификат повреждён или не в формате PEM")


def _verify_signature(public_key, signature, payload, hash_alg):
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, payload, padding.PKCS1v15(), hash_alg)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, payload, ec.ECDSA(hash_alg))
    else:
        raise CertError("неподдерживаемый тип ключа")


def verify_chain(cert, ca_cert):
    """Check the certificate was issued by our CA and is currently valid."""
    if cert.issuer != ca_cert.subject:
        raise CertError("сертификат выдан неизвестным центром")
    try:
        _verify_signature(
            ca_cert.public_key(),
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise CertError("подпись сертификата недействительна")
    except CertError:
        raise
    except Exception:
        raise CertError("не удалось проверить подпись сертификата")

    now = utcnow()
    if now < cert.not_valid_before_utc:
        raise CertError("сертификат ещё не действителен")
    if now > cert.not_valid_after_utc:
        raise CertError("сертификат просрочен")

    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if constraints.value.ca:
            raise CertError("сертификат CA не может использоваться для входа")
    except x509.ExtensionNotFound:
        pass
    return True


def subject_user_id(cert):
    for attr in cert.subject:
        if attr.oid == NameOID.SERIAL_NUMBER:
            return attr.value
    return None


def normalise_serial(value):
    return (value or "").strip().lower().lstrip("0")


def lookup_user(cert, expected_user_id=None):
    """Resolve the certificate to a live, non-revoked user record."""
    conn = get_db()
    serial = normalise_serial(format(cert.serial_number, "x"))
    rows = conn.execute(
        "SELECT id, name, serial, revoked FROM users WHERE serial IS NOT NULL"
    ).fetchall()
    user = next((r for r in rows if normalise_serial(r["serial"]) == serial), None)
    if user is None:
        raise CertError("сертификат не найден")
    if user["revoked"]:
        raise CertError("сертификат отозван")

    cert_user_id = subject_user_id(cert)
    if cert_user_id and cert_user_id != user["id"]:
        raise CertError("сертификат не соответствует учётной записи")
    if expected_user_id and user["id"] != expected_user_id:
        raise CertError("сертификат принадлежит другому пользователю")
    return user


def consume_nonce(nonce, ttl_seconds):
    """Atomically spend a nonce. A nonce is valid exactly once."""
    if not nonce:
        raise CertError("nonce не предоставлен")
    conn = get_db()
    row = conn.execute(
        "SELECT created_at FROM nonces WHERE nonce=?", (nonce,)
    ).fetchone()
    # DELETE reports how many rows it removed, so a racing second request that
    # reaches this line with the same nonce deletes nothing and is rejected.
    cursor = conn.execute("DELETE FROM nonces WHERE nonce=?", (nonce,))
    conn.commit()
    if cursor.rowcount != 1 or row is None:
        raise CertError("nonce истёк или уже использован")
    created = parse_ts(row["created_at"])
    if created is None or (utcnow() - created).total_seconds() > ttl_seconds:
        raise CertError("nonce истёк")
    return True


def verify_proof_of_possession(cert, nonce, signature):
    """Confirm the caller holds the private key for this certificate."""
    if not signature:
        raise CertError("подпись не предоставлена")
    try:
        _verify_signature(cert.public_key(), signature, nonce.encode(), hashes.SHA256())
    except InvalidSignature:
        raise CertError("подпись nonce недействительна")
    except CertError:
        raise
    except Exception:
        raise CertError("не удалось проверить подпись nonce")
    return True


def authenticate_by_challenge(cfg, ca_cert, cert_pem, nonce, signature,
                              expected_user_id=None):
    """Full challenge-response authentication. Requires the private key."""
    cert = parse_pem(cert_pem)
    consume_nonce(nonce, cfg.nonce_ttl_seconds)
    verify_chain(cert, ca_cert)
    verify_proof_of_possession(cert, nonce, signature)
    return lookup_user(cert, expected_user_id)
