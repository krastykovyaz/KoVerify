"""The nginx config actually parses on the target nginx version.

This caught a real bug: the config used the standalone "http2 on;" directive,
which nginx only accepts from 1.25.1 onward. The actual deployment target
runs 1.24.0 and would have failed `nginx -t` at deploy time, which
deploy.sh treats as fatal and refuses to restart the service over.
"""
import shutil
import subprocess

import pytest

NGINX_CONF = "deploy/nginx-verifier.conf"
PROXY_SNIPPET = "deploy/nginx-proxy-headers.conf"

pytestmark = pytest.mark.skipif(
    shutil.which("nginx") is None or shutil.which("openssl") is None,
    reason="nginx or openssl not available on this host",
)


@pytest.fixture
def nginx_sandbox(tmp_path):
    """A throwaway nginx config tree: never touches the real one."""
    sites = tmp_path / "sites-enabled"; sites.mkdir()
    snippets = tmp_path / "snippets"; snippets.mkdir()
    letsencrypt = tmp_path / "letsencrypt"; letsencrypt.mkdir()
    ca = tmp_path / "ca"; ca.mkdir()
    www = tmp_path / "www"; www.mkdir()
    (www / "manifest.json").write_text("{}")

    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(letsencrypt / "privkey.pem"),
         "-out", str(letsencrypt / "fullchain.pem"),
         "-days", "1", "-nodes", "-subj", "/CN=test"],
        capture_output=True, check=True,
    )
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.crt"),
         "-days", "1", "-nodes", "-subj", "/CN=testCA"],
        capture_output=True, check=True,
    )

    conf = open(NGINX_CONF).read()
    conf = (
        conf.replace(
            "/etc/letsencrypt/live/secure.fin-tech.com/fullchain.pem",
            str(letsencrypt / "fullchain.pem"),
        )
        .replace(
            "/etc/letsencrypt/live/secure.fin-tech.com/privkey.pem",
            str(letsencrypt / "privkey.pem"),
        )
        .replace("/var/www/verifier/ca/ca.crt", str(ca / "ca.crt"))
        .replace(
            "unix:/run/verifier/verifier.sock", f"unix:{tmp_path}/dummy.sock"
        )
        .replace("/var/log/nginx/", f"{tmp_path}/")
        .replace("/var/www/verifier/templates/static/", f"{www}/")
        .replace(
            "/var/www/verifier/templates/manifest.json",
            str(www / "manifest.json"),
        )
    )
    (sites / "verifier.conf").write_text(conf)
    shutil.copy(PROXY_SNIPPET, snippets / "verifier-proxy.conf")
    (snippets / "verifier-proxy-auth.conf").write_text(
        'proxy_set_header X-Proxy-Auth "test-secret";\n'
    )

    main_conf = tmp_path / "nginx.conf"
    main_conf.write_text(f"events {{}}\nhttp {{\n  include {sites}/*.conf;\n}}\n")
    return main_conf


def test_config_parses_on_the_installed_nginx(nginx_sandbox):
    result = subprocess.run(
        ["nginx", "-t", "-c", str(nginx_sandbox)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_mtls_is_actually_wired_on(nginx_sandbox):
    """Regression for the exact reported failure.

    MTLS_MODE=proxy in the app is worthless if nginx never asks the browser
    for a certificate. Both must be on together.
    """
    conf = open(NGINX_CONF).read()
    assert "# ssl_verify_client optional" not in conf, \
        "ssl_verify_client is commented out: the browser is never asked " \
        "for a certificate and the device-login button will always fail"
    assert "\n    ssl_verify_client optional;" in conf
    assert "\n    ssl_client_certificate " in conf


def test_env_example_matches_the_nginx_default():
    """Catches the two settings drifting apart again."""
    conf = open(NGINX_CONF).read()
    env = open(".env.example").read()
    nginx_mtls_on = "\n    ssl_verify_client optional;" in conf
    env_mtls_on = "\nMTLS_MODE=proxy" in env
    assert nginx_mtls_on == env_mtls_on, (
        "nginx and .env.example disagree about whether mTLS is on by default"
    )
