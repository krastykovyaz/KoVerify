#!/usr/bin/env bash
#
# Daily check for the failures that have actually happened here. Exits non-zero
# and logs to the journal when anything is wrong, so the timer's unit shows up
# in `systemctl --failed`.
#
# Every TLS check validates the certificate. Earlier health checks used
# `curl -k`, which is how a server certificate stayed expired for three months.
set -uo pipefail

ENV_FILE=/etc/verifier.env
# shellcheck disable=SC1090
[ -r "$ENV_FILE" ] && { set -a; source "$ENV_FILE"; set +a; }

HOST="${PUBLIC_HOST:-secure.fin-tech.com}"
CONNECT="${TLS_CONNECT:-127.0.0.1:443}"
WARN_DAYS="${EXPIRY_WARN_DAYS:-21}"
CA_DIR="${CA_DIR:-/var/www/verifier/ca}"
DB_PATH="${DB_PATH:-/var/www/verifier/db.sqlite}"
SOCKET=/run/verifier/verifier.sock

fail=0
problem() { echo "PROBLEM: $*"; logger -t verifier-check -p user.err -- "$*" 2>/dev/null || true; fail=1; }
days_until() { echo $(( ( $(date -d "$1" +%s) - $(date +%s) ) / 86400 )); }

systemctl is-active --quiet verifier || problem "verifier service is not active"

curl -fsS --max-time 5 --unix-socket "$SOCKET" http://localhost/healthz >/dev/null 2>&1 \
  || problem "the application did not answer its health check"

nginx -t >/dev/null 2>&1 \
  || problem "nginx -t fails: the next reload will break every site on this host"

handshake="$(echo | openssl s_client -connect "$CONNECT" -servername "$HOST" \
             -verify_hostname "$HOST" -verify_return_error 2>&1)"
echo "$handshake" | grep -q "Verify return code: 0" \
  || problem "TLS certificate for $HOST is not valid: $(echo "$handshake" | grep -m1 'Verify return code' || echo 'handshake failed')"

end="$(echo | openssl s_client -connect "$CONNECT" -servername "$HOST" 2>/dev/null \
       | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
if [ -n "$end" ]; then
  left="$(days_until "$end")"
  [ "$left" -ge "$WARN_DAYS" ] || problem "TLS certificate for $HOST expires in $left days"
fi

if [ -f "$CA_DIR/ca.crt" ]; then
  openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/ca.crt" >/dev/null 2>&1 \
    || problem "the CA certificate does not validate itself; no issued certificate will verify"
  ca_end="$(openssl x509 -in "$CA_DIR/ca.crt" -noout -enddate | cut -d= -f2)"
  [ "$(days_until "$ca_end")" -ge 180 ] || problem "the CA certificate expires in $(days_until "$ca_end") days"
fi

if [ -f "$DB_PATH" ]; then
  soon=0
  # User ids are restricted to [A-Za-z0-9_-] at registration, so they are safe to interpolate.
  while IFS= read -r uid; do
    sqlite3 -readonly "$DB_PATH" "SELECT cert_pem FROM users WHERE id='$uid';" \
      | openssl x509 -noout -checkend $((30 * 86400)) >/dev/null 2>&1 || soon=$((soon + 1))
  done < <(sqlite3 -readonly "$DB_PATH" "SELECT id FROM users WHERE revoked=0 AND cert_pem IS NOT NULL;" 2>/dev/null)
  [ "$soon" -eq 0 ] || problem "$soon user certificate(s) expire within 30 days; reissue them from the admin panel"
fi

[ "$fail" -eq 0 ] && echo "ok: service, app, nginx config, TLS certificate, CA and user certificates"
exit "$fail"
