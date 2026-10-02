#!/usr/bin/env bash
#
# Encrypt the CA private key at rest.
#
# The key has been plaintext since 2026-04-02 and has been copied into every
# backup. Encrypting it means a leaked copy is useless without the passphrase.
# The application already supports this: it reads CA_PASSPHRASE from the
# environment. Run as root:  sudo bash deploy/encrypt-ca-key.sh
#
# The script keeps the plaintext key aside until the service has restarted and
# answered a health check, then shreds it. If anything fails it puts everything
# back exactly as it was.
set -euo pipefail

ENV_FILE=/etc/verifier.env
CA_DIR=/var/www/verifier/ca
PY=/var/www/verifier/venv/bin/python
SOCKET=/run/verifier/verifier.sock

die() { printf 'xxx %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root"
grep -q '^CA_PASSPHRASE=.\+' "$ENV_FILE" && die "CA_PASSPHRASE is already set; the key looks encrypted"
head -1 "$CA_DIR/ca.key" | grep -q "ENCRYPTED" && die "ca.key is already encrypted"

pass="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export NEW_CA_PASSPHRASE="$pass" CA_DIR

echo "==> writing and verifying the encrypted key (the plaintext one is untouched)"
"$PY" - <<'PYEOF'
import os
from cryptography.hazmat.primitives import serialization as s
d, p = os.environ["CA_DIR"], os.environ["NEW_CA_PASSPHRASE"].encode()
plain = s.load_pem_private_key(open(f"{d}/ca.key", "rb").read(), password=None)
blob = plain.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.BestAvailableEncryption(p))
fd = os.open(f"{d}/ca.key.new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(blob)
back = s.load_pem_private_key(open(f"{d}/ca.key.new", "rb").read(), password=p)
pub = lambda k: k.public_key().public_numbers()
assert pub(back) == pub(plain), "encrypted key does not match the original"
print("encrypted key loads and matches")
PYEOF

cp -a "$ENV_FILE" "$ENV_FILE.pre-encrypt"
restore() {
  echo "!!! restoring the previous state" >&2
  [ -f "$CA_DIR/ca.key.plaintext" ] && mv -f "$CA_DIR/ca.key.plaintext" "$CA_DIR/ca.key"
  rm -f "$CA_DIR/ca.key.new"
  mv -f "$ENV_FILE.pre-encrypt" "$ENV_FILE"
  systemctl restart verifier || true
}
trap 'restore' ERR

echo "==> switching over"
mv "$CA_DIR/ca.key" "$CA_DIR/ca.key.plaintext"
mv "$CA_DIR/ca.key.new" "$CA_DIR/ca.key"
chown www-data:www-data "$CA_DIR/ca.key"; chmod 600 "$CA_DIR/ca.key"
sed -i "s|^CA_PASSPHRASE=.*|CA_PASSPHRASE=$pass|" "$ENV_FILE"
grep -q '^CA_PASSPHRASE=' "$ENV_FILE" || echo "CA_PASSPHRASE=$pass" >> "$ENV_FILE"
chmod 600 "$ENV_FILE"
systemctl restart verifier

echo "==> waiting for the service to come up with the encrypted key"
ok=0
for _ in $(seq 1 30); do
  curl -fsS --max-time 2 --unix-socket "$SOCKET" http://localhost/healthz >/dev/null 2>&1 && { ok=1; break; }
  sleep 1
done
[ "$ok" = 1 ] || false      # triggers the ERR trap and rolls back

trap - ERR
shred -u "$CA_DIR/ca.key.plaintext"
rm -f "$ENV_FILE.pre-encrypt"
echo
echo "Done. The CA key is encrypted and the plaintext copy is shredded."
echo
echo "SAVE THIS PASSPHRASE SOMEWHERE OFF THIS MACHINE (a password manager):"
echo "    $pass"
echo
echo "Without it, backups of the CA cannot be used. Then run deploy/purge-key-copies.sh"
echo "to remove the older plaintext copies."
