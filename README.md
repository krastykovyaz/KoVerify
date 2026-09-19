# Verifier

Two people meet, open the same session code, and each proves who they are.
Identity is proven with a time-based one-time password, or with a client
certificate issued by this service's own certificate authority.

## Running locally

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements-dev.txt
./venv/bin/python run_dev.py      # https://localhost:5000
```

The development server issues its own CA and TLS certificate on first run and
reads client certificates straight off the TLS socket.

## Tests

```bash
./venv/bin/python -m pytest tests/ -q
```

## Configuration

Every setting comes from the environment. Copy `.env.example` to
`/etc/verifier.env`, fill it in, and `chmod 600` it.

The application refuses to start when `FLASK_SECRET` or `ADMIN_SECRET` is
missing, too short, or a known placeholder, and when debug mode is enabled.
This is deliberate: a service that silently falls back to a default password
is worse than one that will not boot.

## How certificate login is trusted

A certificate is public. Possessing a copy proves nothing, so the service
accepts a certificate as identity in exactly two situations.

1. **Challenge-response**, at `/api/session/<code>/verify/cert`. The caller
   signs a single-use server nonce with the matching private key. This needs
   no proxy cooperation and is the path the browser uses.
2. **Mutual TLS**, at `/api/session/<code>/verify/mtls`. A reverse proxy
   completed the handshake and reports the result. This is only believed when
   `MTLS_MODE=proxy`, the request arrives from an address in
   `TRUSTED_PROXIES`, the proxy presents `PROXY_SHARED_SECRET`, the proxy
   reports `SUCCESS`, and the forwarded certificate validates against our CA.

This is the "Войти с сертификатом устройства" button on the session page,
and it does nothing until nginx is actually asking browsers for a
certificate. Three settings move together, never one alone:

| Setting | Where | Off | On |
|---|---|---|---|
| `MTLS_MODE` | `/etc/verifier.env` | `off` | `proxy` |
| `PROXY_SHARED_SECRET` | `/etc/verifier.env` | — | required when `MTLS_MODE=proxy` |
| `ssl_client_certificate` / `ssl_verify_client optional` | `deploy/nginx-verifier.conf` | commented out | uncommented |

Enabling only the nginx lines means nginx never tells the app a handshake
succeeded, so the button still fails. Enabling only `MTLS_MODE` means nginx
never asks the browser for a certificate in the first place, so no browser
ever has one to send — this was the actual state of the deployed site,
which is why the button failed with "сертификат не найден на устройстве"
for every enrolled user regardless of whether they had installed one.

`ssl_verify_client optional` requests a certificate from every connecting
browser, but the browser only shows a picker when it holds one issued by
`ca.crt`; an ordinary visitor with no certificate from us is not prompted.

The nginx snippet in `deploy/nginx-proxy-headers.conf` overwrites every
`X-SSL-Client-*` header on every proxied location. That snippet is a security
control, not boilerplate. A location that proxies without including it lets a
client supply its own `X-SSL-Client-Cert` and impersonate any enrolled user,
because nginx discards inherited `proxy_set_header` directives as soon as a
location defines one of its own.

## Deploying

```bash
sudo bash deploy/deploy.sh --dry-run    # show what would change
sudo bash deploy/deploy.sh              # deploy
sudo bash deploy/deploy.sh --rollback   # restore the previous version
```

The script refuses to deploy unless the test suite passes and the
configuration validates. It backs up the code, the database and the unit file
first, then restarts and health-checks the service, rolling back on its own if
the health check fails.

The service runs as `www-data` under a systemd sandbox. The CA directory is
`0700` and private keys are `0600`. Secrets live in `/etc/verifier.env`, never
in the unit file, because `systemctl cat` is readable by any local user.

## Operational notes

- **Rotating `FLASK_SECRET`** logs every administrator out. Nothing else breaks.
- **Rotating `ADMIN_SECRET`** changes the panel password.
- **Never regenerate the CA** on a populated installation. Every certificate
  already issued chains to the current CA and would stop validating.
- Credential links are single use. The PKCS#12 bundle and the Apple
  configuration profile both spend the same link, because both carry the same
  private key.
- The profile deliberately omits the bundle passphrase, so iOS prompts for it
  at install time. Give that passphrase to the person directly.
