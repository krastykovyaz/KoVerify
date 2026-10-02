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
sudo bash deploy/deploy.sh --rollback   # restore the previous code
```

The script refuses to deploy unless the test suite passes and the
configuration and certificate authority validate. It backs up the code, the
database, the unit file and the nginx files first, then restarts and
health-checks the service, rolling back on its own if the health check fails.
Only the ten most recent backups are kept.

- **Rollback restores code, not data.** Restoring the database snapshot would
  discard every enrolment and revocation made since, and silently un-revoke
  anyone revoked in the meantime, so it needs `--rollback --with-db`. Schema
  changes are additive; older code runs against the current database.
- **nginx drift guard.** On this host public port 443 belongs to an nginx
  `stream` SNI router that forwards to the verifier site on `127.0.0.1:7443`
  with PROXY protocol. `deploy.sh` will not overwrite the live site file when
  its `listen` directives differ from the repository's, because `nginx -t`
  only checks syntax and the mismatch would surface at the next reload.
  `--force-nginx` overrides this. If `nginx -t` fails after the files are
  replaced, the previous ones are put back.
- **The CA is not in deploy backups.** A plaintext private key in every backup
  directory was a finding. `deploy/backup.sh` keeps encrypted copies.

The service runs as `www-data` under a systemd sandbox. Its own code and
interpreter are mounted read-only for it, so a compromised worker cannot
rewrite them. The CA directory is `0700` and private keys are `0600`. Secrets
live in `/etc/verifier.env`, never in the unit file, because `systemctl cat`
is readable by any local user.

Dependencies are pinned to the versions running in production.

## Monitoring and backups

`deploy.sh` installs two systemd timers.

| Timer | Runs | Purpose |
|---|---|---|
| `verifier-check.timer` | daily 07:30 | `deploy/check-health.sh`: service, app, `nginx -t`, the public TLS certificate **validated** (not `-k`), CA and user-certificate expiry. A failure shows in `systemctl --failed` and the journal. |
| `verifier-backup.timer` | daily 03:20 | `deploy/backup.sh`: encrypted database and CA, 14 kept, optionally copied off the host. Needs `BACKUP_PASSPHRASE`. |

Keep the backup passphrase, and `CA_PASSPHRASE`, somewhere other than this
machine. A backup that dies with the host it protects is not a backup.
Restore instructions are at the top of `deploy/backup.sh`.

## One-time host remediation (2026-10-02 audit)

Run in this order, as root:

1. `bash deploy/deploy.sh` to ship the fixes.
2. `bash deploy/fix-cert-renewal.sh`. Renewal used the `standalone`
   authenticator, which cannot bind port 80 while nginx owns it, so the
   certificate expired on 2026-07-02. This switches to `webroot`, reissues,
   reloads nginx and proves a renewal dry run passes.
3. Add `BACKUP_PASSPHRASE=` (and optionally `BACKUP_REMOTE=`) to
   `/etc/verifier.env`, run `bash deploy/backup.sh`, and copy the archive off
   the host.
4. `bash deploy/encrypt-ca-key.sh` encrypts the CA key at rest and prints the
   passphrase once. It restores everything itself if the service does not come
   back healthy.
5. `bash deploy/purge-key-copies.sh` lists, then with `--yes` removes, the
   older plaintext CA keys and users' key bundles from old backups and the
   checkout. It refuses to run until steps 3 and 4 are done.

## Operational notes

- **Rotating `FLASK_SECRET`** logs every administrator out. Nothing else breaks.
- **Rotating `ADMIN_SECRET`** changes the panel password. Admin logins also
  expire server-side after `ADMIN_SESSION_MINUTES` (default 60).
- **Never regenerate the CA** on a populated installation. Every certificate
  already issued chains to the current CA and would stop validating. The app
  refuses to start on a CA whose certificate is not validly self-signed or does
  not match its key.
- **Client addresses.** gunicorn listens on a unix socket, so the app has no
  peer address. nginx overwrites `X-Real-IP` with the true client address and
  the app believes it only when `X-Proxy-Auth` proves the request came through
  nginx. `X-Forwarded-For` is never read.
- Credential links are single use. The PKCS#12 bundle and the Apple
  configuration profile both spend the same link, because both carry the same
  private key. **The server deletes the key bundle once the link is spent or
  expires.** If a delivery fails, use the 🔄 button in the panel to reissue: it
  makes a new key pair for the same person, keeps their TOTP secret, and the
  old certificate stops working immediately.
- The profile deliberately omits the bundle passphrase, so iOS prompts for it
  at install time. Give that passphrase to the person directly.
- A TOTP code works once. A second use of the same code is refused until the
  next 30-second step.
- Display names may not contain `<`, `>` or control characters.
