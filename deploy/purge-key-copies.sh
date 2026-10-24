#!/usr/bin/env bash
#
# Remove the stray plaintext copies of the CA key and users' private keys.
#
# Found by the 2026-10-02 audit:
#   * the CA key inside every deploy backup under /var/backups/verifier
#   * a byte-identical CA key, mode 644, in the /root/verify checkout
#   * a leftover development TLS key in the production CA directory
#   * users' PKCS#12 bundles inside old database backups
#
# Refuses to run until the key is encrypted and an encrypted backup exists, so
# the CA never ends up existing in only one place. Without --yes it only lists.
set -euo pipefail

ENV_FILE=/etc/verifier.env
CA_DIR=/var/www/verifier/ca
BACKUPS=/var/backups/verifier
DATA_BACKUPS=/var/backups/verifier-data
REPO_CA=/root/verify/ca

die() { printf 'xxx %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root"
APPLY=0; [ "${1:-}" = "--yes" ] && APPLY=1

grep -q '^CA_PASSPHRASE=.\+' "$ENV_FILE" \
  || die "the CA key is not encrypted yet; run deploy/encrypt-ca-key.sh first"
ls "$DATA_BACKUPS"/verifier-*.tar.enc >/dev/null 2>&1 \
  || die "no encrypted backup exists; run deploy/backup.sh first and copy it off the host"

targets=()
for d in "$BACKUPS"/*/code/ca; do [ -d "$d" ] && targets+=("$d"); done
[ -d "$REPO_CA" ] && targets+=("$REPO_CA")
[ -f "$CA_DIR/server.key" ] && targets+=("$CA_DIR/server.key")

echo "would remove:"; printf '  %s\n' "${targets[@]:-(nothing)}"
echo "would blank the private-key column in:"
ls "$BACKUPS"/*/db.sqlite 2>/dev/null | sed 's/^/  /' || true
[ "$APPLY" = 1 ] || { echo; echo "dry run. Re-run with --yes to apply."; exit 0; }

for t in "${targets[@]}"; do
  if [ -d "$t" ]; then
    find "$t" -type f -name '*.key' -exec shred -u {} \;
    rm -rf "$t"
  else
    shred -u "$t"
  fi
done
for db in "$BACKUPS"/*/db.sqlite; do
  [ -f "$db" ] && sqlite3 "$db" "UPDATE users SET p12_b64=NULL;"
done
echo "done."
