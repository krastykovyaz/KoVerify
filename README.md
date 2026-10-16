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

## Sharing in the room

After both people pass verification the room page offers **Обмен данными**: a
login, password, code, key and note can be sent to the other person in one go,
and each of them can read, copy or delete what is there.

- **Who is in the room.** Verifying hands the browser a random seat token; the
  server keeps only its hash. Every room call needs it, so knowing the
  eight-character code reveals nothing. The token and the private key live in
  that browser's local storage and are wiped when the room closes.
- **End-to-end encrypted.** Each browser makes an ECDH P-256 key pair and
  publishes only the public half. Messages are AES-256-GCM under a key derived
  from the shared secret (HKDF, salted with the room code), with the room code
  and sender bound in as authenticated data, so a ciphertext cannot be moved to
  another room or made to look like it came from the other person. The server
  stores ciphertext only: a database leak, a backup or a log reveals nothing.
  The code is in `templates/static/room-crypto.js`.
- **Safety code.** The server could in principle swap a public key, so both
  screens show ten digits derived from both keys. Read them to each other
  aloud; if they differ, send nothing.
- **Closing deletes everything.** Either person can press "Закрыть комнату и
  удалить всё", and a room also closes by itself when `SESSION_TTL_MINUTES`
  (30 by default) runs out; the page counts down. Either way the same routine
  runs: every shared item, both public keys, both seat-token hashes, the names,
  verification methods and any video request are wiped, and only a bare
  tombstone (code and timestamps) remains for a day so a late visitor is told
  "closed". Both browsers learn of it on their next poll, clear the room from
  the screen and delete their private key from local storage. An expired room
  is finished off the moment anyone touches it, and `verifier-purge.timer` does
  it every five minutes even if nobody does. Copy what you need first: nothing
  can be recovered.
- **Limits.** Short text only (12 KB per item), 50 items per room, a key can be
  published once, and polling is rate limited per client and room.
- **Tests.** `tests/test_room.py` covers access and limits.
  `tests/test_room_e2e.py` runs two simulated browsers through the real client
  crypto against a live server, including tampering, cross-room replay and a
  swapped key. `tests/test_room_ui.py` drives the real pages (sharing, video,
  closing, notifications, login) in a DOM with stubbed notifications, sound and
  tab visibility. Both need Node.js 24 or later and are skipped without it; the
  page tests also need `cd tests/js && npm install` once for jsdom.

## Activity notifications

The room tells each person what the other one does, so nobody has to keep
looking at the screen. Only the other person's actions notify you, never your
own.

| Event | Who is told |
|---|---|
| the other person verified, or the secure channel became ready | the one waiting |
| the other person entered the room | the one already there (toast only) |
| data was sent to you, or a record you were looking at was deleted | the receiver |
| a video request, its acceptance or refusal, and the verdict | the other person |
| five minutes and one minute before the room deletes itself | both |
| the room was closed or ran out of time | whoever did not close it |

- **On the page.** Every event is a toast, and a background tab shows an unread
  count in its title. The header shows whether the other person is in the room
  right now (they count as gone after four missed polls, 12 seconds).
- **Optional alerts.** "🔔 Уведомления" adds a beep, vibration and, if the
  browser allows, a system notification while the tab is in the background. It
  is off until chosen and remembered per browser.
- **Nothing sensitive in an alert.** System notifications say what kind of thing
  happened, never what was shared, and they never name the other person because
  they appear on lock screens. The toast, on the open page, does use the name.
- **Catching up.** Returning to a tab polls at once. After a reload the page
  says what arrived while you were away, once; the ids already seen are kept so
  reloading again does not repeat it.
- **The limit.** A page can only notice things while it is open. A tab that is
  closed, or that the phone has suspended in the background, polls nothing and
  alerts nothing until it is opened again. Reaching a closed tab needs Web Push:
  push keys, a service worker, and the browsers' push services, which also
  need an installed app on iPhone. That is a separate piece of work.

## Video verification

Either person in a room can ask the other to prove who they are on video.

1. **Ask.** "Запросить видеопроверку" sends a request. The other person sees an
   incoming banner (and the tab title flashes) and can accept or decline. A
   request nobody answers lapses after two minutes.
2. **Meet.** Once accepted, both get a button that opens a video call. The call
   screen repeats the safety code: reading it aloud on camera is what ties the
   video to the encrypted channel, so a swapped key cannot survive it.
3. **Decide.** Whoever asked is the verifier. They press "подтверждаю" or "не
   подтверждаю", and both screens show the result. A denial tells both people
   not to share secrets. Either side can ask again, and the roles can swap.

The server only tracks the request, who asked, and the result, and each step is
a single guarded update, so two people cannot start conflicting requests. It
does not carry video. The call happens at `VIDEO_URL_TEMPLATE` (public Jitsi by
default) in a room named by 128 bits that the two browsers derive from their
shared secret; the server never sees it and nobody else can guess it. The
provider can still see that a call happens and the video itself, so point the
template at a self-hosted Jitsi if that matters. A built-in call was not built:
it needs a TURN relay this host does not have.

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

`deploy.sh` installs three systemd timers.

| Timer | Runs | Purpose |
|---|---|---|
| `verifier-check.timer` | daily 07:30 | `deploy/check-health.sh`: service, app, `nginx -t`, the public TLS certificate **validated** (not `-k`), CA and user-certificate expiry. A failure shows in `systemctl --failed` and the journal. |
| `verifier-backup.timer` | daily 03:20 | `deploy/backup.sh`: encrypted database and CA, 14 kept, optionally copied off the host. Needs `BACKUP_PASSPHRASE`. |
| `verifier-purge.timer` | every 5 min | `python -m verifier.purge`: wipes rooms that have ended, so cleanup never waits for traffic. |

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
