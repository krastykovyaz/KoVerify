#!/usr/bin/env bash
#
# Deploy the verifier to this host. Run as root:
#     sudo bash deploy/deploy.sh
#
# Takes a backup first and rolls back automatically if the new version fails
# its health check, so a bad deploy restores the previous one.
#
# Flags:
#   --dry-run      show what would happen, change nothing
#   --rollback     restore the most recent backup and exit
#   --with-db      with --rollback: also restore the database snapshot. Off by
#                  default, because restoring it discards every enrolment and
#                  revocation made since the backup and silently un-revokes
#                  anyone revoked in the meantime. Schema changes are additive,
#                  so older code runs fine against the current database.
#   --force-nginx  install the nginx site file even if its listen directives
#                  differ from the live ones (see the drift guard below)

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/var/www/verifier
BACKUP_ROOT=/var/backups/verifier
KEEP_BACKUPS="${KEEP_BACKUPS:-10}"
ENV_FILE=/etc/verifier.env
SERVICE=verifier
SOCKET=/run/verifier/verifier.sock
RUN_USER=www-data
RUN_GROUP=www-data
NGINX_SITE=/etc/nginx/sites-available/verifier
NGINX_SNIPPETS=/etc/nginx/snippets

DRY_RUN=0
DO_ROLLBACK=0
WITH_DB=0
FORCE_NGINX=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --rollback) DO_ROLLBACK=1 ;;
    --with-db) WITH_DB=1 ;;
    --force-nginx) FORCE_NGINX=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxxx\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = 1 ]; then echo "    would run: $*"; else "$@"; fi; }

[ "$(id -u)" = 0 ] || die "must run as root"

latest_backup() { ls -1d "$BACKUP_ROOT"/*/ 2>/dev/null | sort | tail -1; }

restore_nginx_from() {
  local backup="$1"
  [ -d "$backup/nginx" ] || return 0
  [ -f "$backup/nginx/verifier" ] && cp -a "$backup/nginx/verifier" "$NGINX_SITE"
  for f in verifier-proxy.conf verifier-proxy-auth.conf; do
    [ -f "$backup/nginx/$f" ] && cp -a "$backup/nginx/$f" "$NGINX_SNIPPETS/$f"
  done
  return 0
}

rollback() {
  local backup; backup="$(latest_backup)"
  [ -n "$backup" ] || die "no backup to roll back to"
  warn "rolling back to $backup"
  systemctl stop "$SERVICE" || true
  rsync -a --delete \
        --exclude venv/ --exclude db.sqlite --exclude 'db.sqlite-*' --exclude ca/ \
        "$backup/code/" "$APP_DIR/"
  if [ "$WITH_DB" = 1 ] && [ -f "$backup/db.sqlite" ]; then
    warn "restoring the database snapshot: changes made since then are lost"
    cp -a "$backup/db.sqlite" "$APP_DIR/db.sqlite"
  else
    warn "leaving the current database in place (use --with-db to restore the snapshot)"
  fi
  [ -f "$backup/verifier.service" ] && cp -a "$backup/verifier.service" \
        /etc/systemd/system/verifier.service
  restore_nginx_from "$backup"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || warn "nginx config did not validate after rollback; check it by hand"
  systemctl daemon-reload
  systemctl start "$SERVICE"
  warn "rollback complete"
}

if [ "$DO_ROLLBACK" = 1 ]; then rollback; exit 0; fi

# ── Preflight ────────────────────────────────────────────────────────
log "preflight"

[ -f "$ENV_FILE" ] || die "$ENV_FILE is missing. Copy .env.example to it and fill it in."
perms="$(stat -c '%a' "$ENV_FILE")"
[ "$perms" = "600" ] || die "$ENV_FILE has mode $perms, expected 600"

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
[ -n "${FLASK_SECRET:-}" ]  || die "FLASK_SECRET is not set in $ENV_FILE"
[ -n "${ADMIN_SECRET:-}" ]  || die "ADMIN_SECRET is not set in $ENV_FILE"
[ "${#FLASK_SECRET}" -ge 32 ] || die "FLASK_SECRET is shorter than 32 characters"
[ "${#ADMIN_SECRET}" -ge 12 ] || die "ADMIN_SECRET is shorter than 12 characters"

if [ "${MTLS_MODE:-off}" = "proxy" ]; then
  [ -n "${PROXY_SHARED_SECRET:-}" ] \
    || die "MTLS_MODE=proxy requires PROXY_SHARED_SECRET in $ENV_FILE"
  [ "${#PROXY_SHARED_SECRET}" -ge 16 ] \
    || die "PROXY_SHARED_SECRET is shorter than 16 characters"
fi
[ -n "${CA_PASSPHRASE:-}" ] || warn "CA_PASSPHRASE is empty: the CA key is stored unencrypted (see deploy/encrypt-ca-key.sh)"
[ -n "${BACKUP_PASSPHRASE:-}" ] || warn "BACKUP_PASSPHRASE is empty: the encrypted backup timer will not be enabled"

log "running the test suite"
if [ -x "$SRC/venv/bin/python" ]; then
  ( cd "$SRC" && ./venv/bin/python -m pytest tests/ -q ) \
    || die "tests failed, refusing to deploy"
else
  warn "no venv in $SRC, skipping tests"
fi

log "checking the configuration and the certificate authority"
# Config and CA only: starting the whole app here would open the production
# database as root and leave root-owned WAL files the service could not use.
( cd "$SRC" && ./venv/bin/python -c "
import sys
sys.path.insert(0, '.')
from verifier.config import Config, ConfigError
from verifier.ca import ca_exists, verify_ca
try:
    cfg = Config()
    if ca_exists(cfg):
        verify_ca(cfg)
except ConfigError as exc:
    print(exc); raise SystemExit(1)
print('configuration and CA accepted')
" ) || die "configuration or CA rejected, refusing to deploy"

# ── Backup ───────────────────────────────────────────────────────────
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$BACKUP_ROOT/$STAMP"
log "backing up to $BACKUP"
run mkdir -p "$BACKUP/code" "$BACKUP/nginx"
if [ -d "$APP_DIR" ]; then
  # The CA is deliberately not copied here: a deploy never touches it, and a
  # plaintext key in every backup directory is exactly what the audit flagged.
  # deploy/backup.sh keeps encrypted copies of the CA and database.
  run rsync -a --exclude venv/ --exclude ca/ "$APP_DIR/" "$BACKUP/code/"
  if [ -f "$APP_DIR/db.sqlite" ]; then
    # .backup is consistent against a live writer; cp is not.
    run sqlite3 "$APP_DIR/db.sqlite" ".backup '$BACKUP/db.sqlite'" \
      || run cp -a "$APP_DIR/db.sqlite" "$BACKUP/db.sqlite"
  fi
fi
[ -f /etc/systemd/system/verifier.service ] && \
  run cp -a /etc/systemd/system/verifier.service "$BACKUP/verifier.service"
[ -f "$NGINX_SITE" ] && run cp -a "$NGINX_SITE" "$BACKUP/nginx/verifier"
for f in verifier-proxy.conf verifier-proxy-auth.conf; do
  [ -f "$NGINX_SNIPPETS/$f" ] && run cp -a "$NGINX_SNIPPETS/$f" "$BACKUP/nginx/$f"
done
run chmod -R go-rwx "$BACKUP"
if [ "$DRY_RUN" = 0 ]; then
  ls -1d "$BACKUP_ROOT"/*/ 2>/dev/null | sort | head -n -"$KEEP_BACKUPS" | xargs -r rm -rf
fi

# ── Sync code ────────────────────────────────────────────────────────
log "syncing application code"
run mkdir -p "$APP_DIR"
run rsync -a --delete \
    --exclude venv/ \
    --exclude db.sqlite --exclude 'db.sqlite-*' \
    --exclude ca/ \
    --exclude .git/ --exclude __pycache__/ --exclude .pytest_cache/ \
    --exclude tests/ --exclude '.env*' \
    "$SRC/" "$APP_DIR/"

log "installing dependencies"
if [ ! -x "$APP_DIR/venv/bin/python" ]; then
  run python3 -m venv "$APP_DIR/venv"
fi
run "$APP_DIR/venv/bin/pip" install -q --upgrade pip
run "$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

# ── Permissions ──────────────────────────────────────────────────────
log "tightening permissions"
run chown -R "$RUN_USER:$RUN_GROUP" "$APP_DIR"
run chmod 750 "$APP_DIR"
run chmod 755 "$APP_DIR/deploy"/*.sh
if [ -d "$APP_DIR/ca" ]; then
  run chmod 700 "$APP_DIR/ca"
  run find "$APP_DIR/ca" -name '*.key' -exec chmod 600 {} \;
  run find "$APP_DIR/ca" -name '*.crt' -exec chmod 644 {} \;
fi
[ -f "$APP_DIR/db.sqlite" ] && run chmod 640 "$APP_DIR/db.sqlite"
# nginx needs to read the CA certificate for ssl_client_certificate.
[ -f "$APP_DIR/ca/ca.crt" ] && run chmod 644 "$APP_DIR/ca/ca.crt"

# ── System configuration ─────────────────────────────────────────────
log "installing unit and nginx configuration"
run install -m 644 "$SRC/deploy/verifier.service" /etc/systemd/system/verifier.service
for unit in verifier-check.service verifier-check.timer verifier-backup.service verifier-backup.timer; do
  run install -m 644 "$SRC/deploy/$unit" "/etc/systemd/system/$unit"
done
run mkdir -p "$NGINX_SNIPPETS"
run install -m 644 "$SRC/deploy/nginx-proxy-headers.conf" \
    "$NGINX_SNIPPETS/verifier-proxy.conf"

# Render the shared secret into a snippet of its own so it never sits in a
# world-readable config file.
if [ "$DRY_RUN" = 0 ]; then
  umask 027
  printf 'proxy_set_header X-Proxy-Auth "%s";\n' "${PROXY_SHARED_SECRET:-}" \
    > "$NGINX_SNIPPETS/verifier-proxy-auth.conf"
  chmod 640 "$NGINX_SNIPPETS/verifier-proxy-auth.conf"
  umask 022
else
  echo "    would write $NGINX_SNIPPETS/verifier-proxy-auth.conf"
fi

# Drift guard. This host's public port 443 is owned by an nginx stream router
# that forwards to the listen address in the site file. Overwriting the site
# file with one that listens somewhere else would validate (`nginx -t` only
# checks syntax) and then fail at reload, leaving the next restart to take down
# every site on the machine.
install_site=1
if [ -f "$NGINX_SITE" ] && [ "$FORCE_NGINX" = 0 ]; then
  live_listen="$(grep -E '^\s*listen\s' "$NGINX_SITE" | sed 's/^\s*//' | sort)"
  repo_listen="$(grep -E '^\s*listen\s' "$SRC/deploy/nginx-verifier.conf" | sed 's/^\s*//' | sort)"
  if [ "$live_listen" != "$repo_listen" ]; then
    warn "the live nginx site file listens differently from the repository's; NOT overwriting it"
    diff <(echo "$live_listen") <(echo "$repo_listen") || true
    warn "reconcile deploy/nginx-verifier.conf, or re-run with --force-nginx if you are sure"
    install_site=0
  fi
fi
if [ "$install_site" = 1 ]; then
  run install -m 644 "$SRC/deploy/nginx-verifier.conf" "$NGINX_SITE"
  run ln -sfn "$NGINX_SITE" /etc/nginx/sites-enabled/verifier
fi

log "validating nginx configuration"
if [ "$DRY_RUN" = 0 ]; then
  if ! nginx -t; then
    warn "nginx configuration is invalid; restoring the files this deploy replaced"
    restore_nginx_from "$BACKUP"
    nginx -t || warn "nginx still does not validate after restoring; fix it before any reload"
    die "nginx configuration is invalid, nothing was restarted"
  fi
fi

# ── Restart and verify ───────────────────────────────────────────────
log "restarting $SERVICE"
run systemctl daemon-reload
run systemctl enable "$SERVICE"
run systemctl restart "$SERVICE"

if [ "$DRY_RUN" = 0 ]; then
  log "waiting for health check"
  healthy=0
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 2 --unix-socket "$SOCKET" \
         http://localhost/healthz >/dev/null 2>&1; then healthy=1; break; fi
    sleep 1
  done
  if [ "$healthy" != 1 ]; then
    warn "health check failed"
    journalctl -u "$SERVICE" -n 40 --no-pager || true
    rollback
    die "deploy failed and was rolled back"
  fi
  log "health check passed"
  run systemctl reload nginx
fi

# ── Scheduled jobs ───────────────────────────────────────────────────
run systemctl daemon-reload
run systemctl enable --now verifier-check.timer
if [ -n "${BACKUP_PASSPHRASE:-}" ]; then
  run systemctl enable --now verifier-backup.timer
fi

# ── What visitors actually see ───────────────────────────────────────
if [ "$DRY_RUN" = 0 ]; then
  log "checking the public TLS certificate (validated, not -k)"
  if ! bash "$APP_DIR/deploy/check-health.sh"; then
    warn "the checks above need attention; the deploy itself succeeded"
  fi
fi

log "deployed successfully (backup: $BACKUP)"
log "roll back at any time with: sudo bash deploy/deploy.sh --rollback"
