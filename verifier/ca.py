"""Certificate authority: creation, issuance and PKCS#12 packaging."""
import datetime as dt
import ipaddress
import os
import secrets
import string
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID

from .db import utcnow

KEY_FILE_MODE = 0o600


def ca_exists(cfg):
    return os.path.exists(cfg.ca_key_path) and os.path.exists(cfg.ca_cert_path)


def _write_private_key(path, key, passphrase):
    """Write a private key with owner-only permissions, encrypted when possible."""
    if passphrase:
        encryption = BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )
    # Create with restrictive permissions from the start, never world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, KEY_FILE_MODE)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, KEY_FILE_MODE)


def generate_ca(cfg):
    os.makedirs(cfg.ca_dir, exist_ok=True)
    os.chmod(cfg.ca_dir, 0o700)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    _write_private_key(cfg.ca_key_path, key, cfg.ca_passphrase)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "VerifierCA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Verifier"),
    ])
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    with open(cfg.ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cfg.ca_cert_path, 0o644)
    return key, cert


def generate_server_cert(cfg, ca_key, ca_cert, hostnames=("localhost",), key_path=None,
                         cert_path=None):
    """Issue a TLS server certificate. Only used for local development."""
    key_path = key_path or os.path.join(cfg.ca_dir, "server.key")
    cert_path = cert_path or os.path.join(cfg.ca_dir, "server.crt")
    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write_private_key(key_path, srv_key, None)

    entries = [x509.DNSName(h) for h in hostnames]
    entries.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))
    entries.append(x509.IPAddress(ipaddress.IPv6Address("::1")))
    san = x509.SubjectAlternativeName(entries)

    now = utcnow()
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(srv_cert.public_bytes(serialization.Encoding.PEM))
    return srv_key, srv_cert


def load_ca(cfg):
    with open(cfg.ca_key_path, "rb") as f:
        password = cfg.ca_passphrase.encode() if cfg.ca_passphrase else None
        ca_key = serialization.load_pem_private_key(f.read(), password=password)
    with open(cfg.ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def load_ca_cert(cfg):
    with open(cfg.ca_cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def issue_user_cert(cfg, ca_key, ca_cert, user_id, name):
    """Issue a client certificate for a user. Returns (cert, private key, serial hex)."""
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serial = x509.random_serial_number()
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, user_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Verifier"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=cfg.cert_valid_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(f"{user_id}@verifier")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, user_key, format(serial, "x")


def generate_p12_password():
    """Readable password: no ambiguous characters, typed by hand on a phone."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(10))


def build_p12(name, user_key, cert, ca_cert, password):
    """Package into PKCS#12.

    Old iOS and macOS releases reject PBES2/AES-256, so we prefer the legacy
    RC2/3DES container that openssl emits and fall back to the modern one.
    """
    key_pem = user_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with tempfile.TemporaryDirectory() as tmp:
        key_file = os.path.join(tmp, "u.key")
        crt_file = os.path.join(tmp, "u.crt")
        ca_file = os.path.join(tmp, "ca.crt")
        out_file = os.path.join(tmp, "out.p12")
        for path, blob in (
            (key_file, key_pem),
            (crt_file, cert.public_bytes(serialization.Encoding.PEM)),
            (ca_file, ca_cert.public_bytes(serialization.Encoding.PEM)),
        ):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, KEY_FILE_MODE)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)

        base_cmd = [
            "openssl", "pkcs12", "-export",
            "-inkey", key_file, "-in", crt_file, "-CAfile", ca_file,
            "-out", out_file, "-passout", "env:P12PASS", "-name", name,
        ]
        env = dict(os.environ, P12PASS=password)
        for cmd in (base_cmd + ["-legacy"], base_cmd):
            try:
                result = subprocess.run(cmd, capture_output=True, env=env, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                break
            if result.returncode == 0:
                with open(out_file, "rb") as f:
                    return f.read()

    # openssl unavailable or failed: use the library implementation.
    return pkcs12.serialize_key_and_certificates(
        name=name.encode(), key=user_key, cert=cert, cas=[ca_cert],
        encryption_algorithm=BestAvailableEncryption(password.encode()),
    )
