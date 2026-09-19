#!/usr/bin/env bash
#
# Deploy the verifier to this host. Run as root:
#     sudo bash deploy/deploy.sh
#
# Takes a full backup first and rolls back automatically if the new version
# fails its health check, so a bad deploy restores the previous one.
#
# Flags:
#   --dry-run   show what would happen, change nothing
#   --rollback  restore the most recent backup and exit

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/var/www/verifier
BACKUP_ROOT=/var/backups/verifier
ENV_FILE=/etc/verifier.env
SERVICE=verifier
SOCKET=/run/verifier/verifier.sock
RUN_USER=www-data
RUN_GROUP=www-data

DRY_RUN=0
DO_ROLLBACK=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --rollback) DO_ROLLBACK=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxxx\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = 1 ]; then echo "    would run: $*"; else "$@"; fi; }

[ "$(id -u)" = 0 ] || die "must run as root"

latest_backup() { ls -1d "$BACKUP_ROOT"/*/ 2>/dev/null | sort | tail -1; }

rollback() {
  local backup; backup="$(latest_backup)"
  [ -n "$backup" ] || die "no backup to roll back to"
  warn "rolling back to $backup"
  systemctl stop "$SERVICE" || true
  rsync -a --delete \
        --exclude venv/ --exclude db.sqlite --exclude 'db.sqlite-*' --exclude ca/ \
        "$backup/code/" "$APP_DIR/"
  [ -f "$backup/db.sqlite" ] && cp -a "$backup/db.sqlite" "$APP_DIR/db.sqlite"
  [ -f "$backup/verifier.service" ] && cp -a "$backup/verifier.service" \
        /etc/systemd/system/verifier.service
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

log "running the test suite"
if [ -x "$SRC/venv/bin/python" ]; then
  ( cd "$SRC" && ./venv/bin/python -m pytest tests/ -q ) \
    || die "tests failed, refusing to deploy"
else
  warn "no venv in $SRC, skipping tests"
fi

log "checking the configuration loads"
( cd "$SRC" && ./venv/bin/python -c "
import os, sys
sys.path.insert(0, '.')
from verifier.config import Config, ConfigError
try:
    Config()
except ConfigError as exc:
    print(exc); raise SystemExit(1)
print('configuration accepted')
" ) || die "configuration rejected, refusing to deploy"

# ── Backup ───────────────────────────────────────────────────────────
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$BACKUP_ROOT/$STAMP"
log "backing up to $BACKUP"
run mkdir -p "$BACKUP/code"
if [ -d "$APP_DIR" ]; then
  run rsync -a --exclude venv/ "$APP_DIR/" "$BACKUP/code/"
  if [ -f "$APP_DIR/db.sqlite" ]; then
    # .backup is consistent against a live writer; cp is not.
    run sqlite3 "$APP_DIR/db.sqlite" ".backup '$BACKUP/db.sqlite'" \
      || run cp -a "$APP_DIR/db.sqlite" "$BACKUP/db.sqlite"
  fi
fi
[ -f /etc/systemd/system/verifier.service ] && \
  run cp -a /etc/systemd/system/verifier.service "$BACKUP/verifier.service"
run chmod -R go-rwx "$BACKUP"

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
run mkdir -p /etc/nginx/snippets
run install -m 644 "$SRC/deploy/nginx-proxy-headers.conf" \
    /etc/nginx/snippets/verifier-proxy.conf

# Render the shared secret into a snippet of its own so it never sits in a
# world-readable config file.
if [ "$DRY_RUN" = 0 ]; then
  umask 027
  printf 'proxy_set_header X-Proxy-Auth "%s";\n' "${PROXY_SHARED_SECRET:-}" \
    > /etc/nginx/snippets/verifier-proxy-auth.conf
  chmod 640 /etc/nginx/snippets/verifier-proxy-auth.conf
  umask 022
else
  echo "    would write /etc/nginx/snippets/verifier-proxy-auth.conf"
fi
run install -m 644 "$SRC/deploy/nginx-verifier.conf" \
    /etc/nginx/sites-available/verifier
run ln -sfn /etc/nginx/sites-available/verifier /etc/nginx/sites-enabled/verifier

log "validating nginx configuration"
if [ "$DRY_RUN" = 0 ]; then
  nginx -t || die "nginx configuration is invalid, nothing was restarted"
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

log "deployed successfully (backup: $BACKUP)"
log "roll back at any time with: sudo bash deploy/deploy.sh --rollback"
