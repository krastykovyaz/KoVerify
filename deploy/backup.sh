#!/usr/bin/env bash
#
# Encrypted backup of the two things that cannot be recreated: the database and
# the certificate authority. Without the CA every issued certificate is
# worthless and every person has to be enrolled again.
#
# Needs BACKUP_PASSPHRASE in /etc/verifier.env. Store that passphrase somewhere
# that is NOT this machine, or the backups die with it.
#
# Optional: BACKUP_REMOTE=user@host:/path copies each archive off the host.
#
# Restore:
#   openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_PASSPHRASE \
#       -in verifier-<stamp>.tar.enc | tar -x
set -euo pipefail
umask 077

ENV_FILE=/etc/verifier.env
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
: "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE is not set in $ENV_FILE}"

DEST="${BACKUP_DIR:-/var/backups/verifier-data}"
KEEP="${BACKUP_KEEP:-14}"
DB_PATH="${DB_PATH:-/var/www/verifier/db.sqlite}"
CA_DIR="${CA_DIR:-/var/www/verifier/ca}"

mkdir -p "$DEST"
chmod 700 "$DEST"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
sqlite3 "$DB_PATH" ".backup '$work/db.sqlite'"
# The private-key bundles are wiped from the live database after delivery, but
# scrub the copy too so a restore can never resurrect one.
sqlite3 "$work/db.sqlite" "UPDATE users SET p12_b64=NULL;"
cp -a "$CA_DIR" "$work/ca"
rm -f "$work/ca/server.key" "$work"/ca/*.bak-* 2>/dev/null || true

out="$DEST/verifier-$stamp.tar.enc"
tar -C "$work" -cf - db.sqlite ca \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_PASSPHRASE -out "$out"
chmod 600 "$out"

# Prove the archive decrypts before trusting it, and prune only after that.
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_PASSPHRASE -in "$out" \
  | tar -t >/dev/null || { rm -f "$out"; echo "backup failed verification" >&2; exit 1; }

ls -1t "$DEST"/verifier-*.tar.enc 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f

if [ -n "${BACKUP_REMOTE:-}" ]; then
  rsync -a --chmod=F600 "$out" "$BACKUP_REMOTE/" && echo "copied off-host to $BACKUP_REMOTE"
else
  echo "note: BACKUP_REMOTE is not set, so this backup exists only on this host" >&2
fi
echo "backup written: $out"
