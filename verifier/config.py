"""Configuration, loaded from the environment with fail-fast validation."""
import os
import secrets

# Values that must never be accepted as real secrets in production.
_WEAK_SECRETS = {
    "admin123", "randstr", "changeme", "secret", "password",
    "admin", "test", "dev", "ecole42",
}

# mTLS trust modes.
MTLS_OFF = "off"        # endpoint disabled
MTLS_PROXY = "proxy"    # trust a reverse proxy that terminated mTLS
MTLS_DIRECT = "direct"  # read the peer certificate off our own TLS socket


class ConfigError(RuntimeError):
    pass


def _env_bool(env, name, default=False):
    raw = env.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _env_list(env, name, default=()):
    raw = env.get(name, "") or ""
    items = [x.strip() for x in str(raw).split(",") if x.strip()]
    return items or list(default)


class Config:
    def __init__(self, env=None, testing=False):
        env = os.environ if env is None else env
        self.testing = testing
        self.debug = _env_bool(env, "VERIFIER_DEBUG", False)

        base = env.get("VERIFIER_HOME", os.getcwd())
        self.base_dir = base
        self.ca_dir = env.get("CA_DIR", os.path.join(base, "ca"))
        self.ca_key_path = os.path.join(self.ca_dir, "ca.key")
        self.ca_cert_path = os.path.join(self.ca_dir, "ca.crt")
        self.db_path = env.get("DB_PATH", os.path.join(base, "db.sqlite"))

        # Passphrase protecting the CA private key at rest. Optional so that an
        # existing unencrypted CA keeps working, but strongly recommended.
        self.ca_passphrase = env.get("CA_PASSPHRASE") or None

        self.secret_key = env.get("FLASK_SECRET")
        self.admin_secret = env.get("ADMIN_SECRET")

        self.mtls_mode = (env.get("MTLS_MODE") or MTLS_OFF).strip().lower()
        if self.mtls_mode not in (MTLS_OFF, MTLS_PROXY, MTLS_DIRECT):
            raise ConfigError(f"MTLS_MODE must be off|proxy|direct, got {self.mtls_mode!r}")
        # Only these source addresses may assert proxy mTLS headers. Empty
        # REMOTE_ADDR (a unix socket) skips this check; the socket's own
        # permissions and the shared secret below are the control there.
        self.trusted_proxies = _env_list(env, "TRUSTED_PROXIES", ["127.0.0.1", "::1"])
        # Proves a request actually traversed our nginx rather than reaching
        # the app socket some other way. Without it, any local process that can
        # open the upstream socket could assert a successful mTLS handshake.
        self.proxy_shared_secret = env.get("PROXY_SHARED_SECRET") or None

        self.session_ttl_minutes = int(env.get("SESSION_TTL_MINUTES", "30"))
        self.download_ttl_hours = int(env.get("DOWNLOAD_TTL_HOURS", "24"))
        self.nonce_ttl_seconds = int(env.get("NONCE_TTL_SECONDS", "300"))
        self.cert_valid_days = int(env.get("CERT_VALID_DAYS", "730"))

        # Rate limits: (max attempts, window seconds).
        self.rl_admin_login = (int(env.get("RL_ADMIN_LOGIN_MAX", "5")), 900)
        self.rl_totp = (int(env.get("RL_TOTP_MAX", "10")), 300)
        self.rl_mtls = (int(env.get("RL_MTLS_MAX", "20")), 300)
        self.rl_status = (int(env.get("RL_STATUS_MAX", "300")), 60)

        self._validate()

    def _validate(self):
        if self.testing:
            self.secret_key = self.secret_key or secrets.token_hex(32)
            self.admin_secret = self.admin_secret or "test-admin-secret-value"
            return

        problems = []
        if not self.secret_key:
            problems.append(
                "FLASK_SECRET is not set. Generate one with: python -c "
                "'import secrets;print(secrets.token_hex(32))'"
            )
        else:
            if self.secret_key.strip().lower() in _WEAK_SECRETS:
                problems.append("FLASK_SECRET is a known-weak placeholder value.")
            elif len(self.secret_key) < 32:
                problems.append("FLASK_SECRET must be at least 32 characters.")

        if not self.admin_secret:
            problems.append("ADMIN_SECRET is not set.")
        elif self.admin_secret.strip().lower() in _WEAK_SECRETS:
            problems.append("ADMIN_SECRET is a known-weak placeholder value.")
        elif len(self.admin_secret) < 12:
            problems.append("ADMIN_SECRET must be at least 12 characters.")

        if self.mtls_mode == MTLS_PROXY and not self.proxy_shared_secret:
            problems.append(
                "MTLS_MODE=proxy requires PROXY_SHARED_SECRET so the app can "
                "tell nginx traffic apart from anything else that reaches its "
                "socket. Generate one with: python3 -c "
                "'import secrets; print(secrets.token_urlsafe(32))'"
            )
        elif self.proxy_shared_secret and len(self.proxy_shared_secret) < 16:
            problems.append("PROXY_SHARED_SECRET must be at least 16 characters.")

        if self.debug:
            problems.append(
                "VERIFIER_DEBUG is enabled. The Werkzeug debugger allows remote "
                "code execution and must never run in production."
            )

        if problems:
            raise ConfigError(
                "Refusing to start with an insecure configuration:\n  - "
                + "\n  - ".join(problems)
            )
