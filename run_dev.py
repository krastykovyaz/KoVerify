#!/usr/bin/env python3
"""Local development server.

Serves HTTPS with a locally issued certificate and, unlike production, reads
client certificates straight off the TLS socket (MTLS_MODE=direct).
"""
import os
import ssl
import sys

from verifier import create_app
from verifier.ca import ca_exists, generate_ca, generate_server_cert, load_ca
from verifier.config import Config


def main():
    os.environ.setdefault("FLASK_SECRET", "dev-only-secret-" + "x" * 32)
    os.environ.setdefault("ADMIN_SECRET", "dev-admin-password")
    os.environ.setdefault("MTLS_MODE", "direct")
    cfg = Config(testing=True)

    if not ca_exists(cfg):
        print("Генерируем CA...")
        generate_ca(cfg)

    key_path = os.path.join(cfg.ca_dir, "server.key")
    cert_path = os.path.join(cfg.ca_dir, "server.crt")
    if not (os.path.exists(key_path) and os.path.exists(cert_path)):
        ca_key, ca_cert = load_ca(cfg)
        generate_server_cert(cfg, ca_key, ca_cert, hostnames=("localhost",),
                             key_path=key_path, cert_path=cert_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(cfg.ca_cert_path)
    ctx.verify_mode = ssl.CERT_OPTIONAL

    app = create_app(cfg)
    print("  https://localhost:5000   admin password:", cfg.admin_secret)
    print("  ВНИМАНИЕ: режим разработки, не для продакшена.", file=sys.stderr)
    app.run(debug=False, host="127.0.0.1", port=5000, ssl_context=ctx)


if __name__ == "__main__":
    main()
