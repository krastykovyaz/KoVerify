"""Certificate authority handling."""
import os
import stat

from verifier.ca import (ca_exists, generate_ca, generate_server_cert, load_ca,
                         issue_user_cert)
from verifier.certs import CertError, verify_chain
from conftest import make_config
import pytest


def test_generate_ca_produces_a_usable_authority(tmp_path):
    cfg = make_config(tmp_path)
    assert not ca_exists(cfg)
    generate_ca(cfg)
    assert ca_exists(cfg)
    key, cert = load_ca(cfg)
    assert cert.subject == cert.issuer


def test_private_keys_are_not_world_readable(tmp_path):
    """The CA key was previously written with 0644."""
    cfg = make_config(tmp_path)
    generate_ca(cfg)
    mode = stat.S_IMODE(os.stat(cfg.ca_key_path).st_mode)
    assert mode == 0o600, f"CA key mode is {oct(mode)}"
    assert stat.S_IMODE(os.stat(cfg.ca_dir).st_mode) == 0o700


def test_server_certificate_generation_does_not_crash(tmp_path):
    """This raised NameError on an undefined 'ipaddress' module."""
    cfg = make_config(tmp_path)
    ca_key, ca_cert = generate_ca(cfg)
    key, cert = generate_server_cert(cfg, ca_key, ca_cert, hostnames=("localhost",))
    assert cert.subject is not None
    verify_chain(cert, ca_cert)


def test_encrypted_ca_key_round_trips(tmp_path):
    cfg = make_config(tmp_path, CA_PASSPHRASE="a-long-ca-passphrase")
    generate_ca(cfg)
    key, cert = load_ca(cfg)
    assert key is not None
    with open(cfg.ca_key_path, "rb") as f:
        assert b"ENCRYPTED" in f.read()


def test_issued_certificate_chains_to_the_ca(tmp_path):
    cfg = make_config(tmp_path)
    ca_key, ca_cert = generate_ca(cfg)
    cert, _key, serial = issue_user_cert(cfg, ca_key, ca_cert, "u-1", "User One")
    verify_chain(cert, ca_cert)
    assert serial


def test_ca_certificate_is_refused_as_a_login_credential(tmp_path):
    cfg = make_config(tmp_path)
    ca_key, ca_cert = generate_ca(cfg)
    with pytest.raises(CertError):
        verify_chain(ca_cert, ca_cert)
