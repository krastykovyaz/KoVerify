"""Startup refuses an unsafe configuration instead of running with one."""
import pytest

from verifier.config import Config, ConfigError

BASE = {"FLASK_SECRET": "s" * 64, "ADMIN_SECRET": "a-strong-admin-secret",
        "PROXY_SHARED_SECRET": "p" * 32}


def env(**overrides):
    return dict(BASE, **overrides)


def test_a_sound_configuration_is_accepted():
    assert Config(env=env()).admin_secret == "a-strong-admin-secret"


@pytest.mark.parametrize("weak", ["admin123", "randstr", "Ecole42", "changeme"])
def test_known_weak_secrets_are_refused(weak):
    with pytest.raises(ConfigError):
        Config(env=env(ADMIN_SECRET=weak))
    with pytest.raises(ConfigError):
        Config(env=env(FLASK_SECRET=weak))


def test_missing_secrets_are_refused():
    with pytest.raises(ConfigError):
        Config(env={"ADMIN_SECRET": "a-strong-admin-secret"})
    with pytest.raises(ConfigError):
        Config(env={"FLASK_SECRET": "s" * 64})


def test_short_secrets_are_refused():
    with pytest.raises(ConfigError):
        Config(env=env(FLASK_SECRET="short"))
    with pytest.raises(ConfigError):
        Config(env=env(ADMIN_SECRET="short"))


def test_debug_mode_is_refused_outside_tests():
    """The Werkzeug debugger is remote code execution."""
    with pytest.raises(ConfigError) as excinfo:
        Config(env=env(VERIFIER_DEBUG="1"))
    assert "debugger" in str(excinfo.value).lower()


def test_unknown_mtls_mode_is_refused():
    with pytest.raises(ConfigError):
        Config(env=env(MTLS_MODE="sometimes"))


def test_mtls_defaults_to_off():
    assert Config(env=env()).mtls_mode == "off"


def test_trusted_proxies_default_to_loopback():
    assert Config(env=env()).trusted_proxies == ["127.0.0.1", "::1"]


def test_testing_mode_supplies_its_own_secrets():
    assert Config(env={}, testing=True).secret_key


def test_proxy_mode_without_a_shared_secret_is_refused():
    """Proxy trust is only sound when nginx can prove it is nginx."""
    broken = dict(BASE, MTLS_MODE="proxy")
    broken.pop("PROXY_SHARED_SECRET")
    with pytest.raises(ConfigError) as excinfo:
        Config(env=broken)
    assert "PROXY_SHARED_SECRET" in str(excinfo.value)


def test_proxy_mode_with_a_shared_secret_is_accepted():
    assert Config(env=env(MTLS_MODE="proxy")).mtls_mode == "proxy"


def test_short_proxy_secret_is_refused():
    with pytest.raises(ConfigError):
        Config(env=env(PROXY_SHARED_SECRET="tooshort"))
