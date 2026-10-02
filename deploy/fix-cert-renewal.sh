#!/usr/bin/env bash
#
# Repair Let's Encrypt renewal for secure.fin-tech.com.
#
# Renewal used the "standalone" authenticator, which must bind port 80 itself.
# nginx owns port 80 permanently, so every renewal failed and the certificate
# expired on 2026-07-02. The "webroot" authenticator writes the challenge file
# into a directory nginx already serves, so nginx never has to stop.
#
# Run as root:  sudo bash deploy/fix-cert-renewal.sh
set -euo pipefail

NAME=secure.fin-tech.com
WEBROOT=/var/www/html

die() { printf 'xxx %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "must run as root"
command -v certbot >/dev/null || die "certbot is not installed"

echo "==> checking that Let's Encrypt can reach the challenge path"
mkdir -p "$WEBROOT/.well-known/acme-challenge"
probe="probe-$(openssl rand -hex 8)"
echo ok > "$WEBROOT/.well-known/acme-challenge/$probe"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
        --resolve "$NAME:80:127.0.0.1" "http://$NAME/.well-known/acme-challenge/$probe" || true)"
rm -f "$WEBROOT/.well-known/acme-challenge/$probe"
[ "$code" = 200 ] || die "nginx did not serve the challenge path (HTTP $code); check the port-80 server block"

echo "==> issuing with the webroot authenticator (this also rewrites the renewal config)"
certbot certonly --non-interactive --webroot -w "$WEBROOT" -d "$NAME" \
  --cert-name "$NAME" --key-type ecdsa --force-renewal

echo "==> making renewals reload nginx so the new certificate is actually served"
install -d /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'HOOK'
#!/bin/sh
nginx -t && systemctl reload nginx
HOOK
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

nginx -t
systemctl reload nginx

echo "==> proving future renewals will work"
certbot renew --cert-name "$NAME" --dry-run

echo "==> what visitors now see (validated, no -k)"
echo | openssl s_client -connect 127.0.0.1:443 -servername "$NAME" -verify_hostname "$NAME" \
      -verify_return_error 2>&1 | grep -E "Verify return code"
echo | openssl s_client -connect 127.0.0.1:443 -servername "$NAME" 2>/dev/null \
      | openssl x509 -noout -enddate
