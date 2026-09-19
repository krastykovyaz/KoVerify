"""Deciding when a mutual-TLS assertion may be believed.

The rule is simple: a header only counts when the immediate peer is a
configured trusted proxy. Otherwise any client on the internet could set the
same header and impersonate any enrolled user.
"""
from urllib.parse import unquote

from flask import request

from .certs import CertError, parse_pem, verify_chain
from .config import MTLS_DIRECT, MTLS_OFF, MTLS_PROXY
from .security import constant_time_equals


def _peer_is_trusted_proxy(cfg):
    peer = request.remote_addr or ""
    if not peer:
        # Unix-socket upstream: there is no peer address to check. Access is
        # constrained by the socket's permissions plus the shared secret.
        return True
    return peer in cfg.trusted_proxies


def _from_proxy(cfg):
    # The shared secret comes first. Reaching this socket is not the same as
    # having come through nginx, and only nginx knows the secret.
    if not constant_time_equals(
        request.headers.get("X-Proxy-Auth"), cfg.proxy_shared_secret
    ):
        raise CertError("mTLS-заголовки приняты только от доверенного прокси")
    if not _peer_is_trusted_proxy(cfg):
        raise CertError("mTLS-заголовки приняты только от доверенного прокси")
    if request.headers.get("X-SSL-Client-Verify") != "SUCCESS":
        raise CertError("сертификат не предоставлен")
    raw = request.headers.get("X-SSL-Client-Cert")
    if not raw:
        raise CertError("прокси не передал сертификат клиента")
    # nginx $ssl_client_escaped_cert is percent-encoded.
    return parse_pem(unquote(raw))


def _from_socket():
    """Read the peer certificate the TLS layer actually negotiated.

    This key is placed in the WSGI environ by the server from the live socket.
    A client cannot inject it: header names are mapped with an HTTP_ prefix,
    and names containing underscores are dropped outright.
    """
    raw = request.environ.get("SSL_CLIENT_CERT")
    if not raw:
        raise CertError("сертификат не предоставлен")
    return parse_pem(raw)


def authenticated_client_cert(cfg, ca_cert):
    """Return a validated client certificate, or raise CertError.

    The certificate is checked against our CA before it is returned, so the
    caller never sees an unvalidated certificate.
    """
    if cfg.mtls_mode == MTLS_OFF:
        raise CertError("вход по сертификату устройства отключён на сервере")
    if cfg.mtls_mode == MTLS_PROXY:
        cert = _from_proxy(cfg)
    elif cfg.mtls_mode == MTLS_DIRECT:
        cert = _from_socket()
    else:
        raise CertError("вход по сертификату устройства отключён на сервере")

    verify_chain(cert, ca_cert)

    # Cross-check the serial the proxy reported, when it supplied one.
    reported = request.headers.get("X-SSL-Client-Serial")
    if cfg.mtls_mode == MTLS_PROXY and reported:
        from .certs import normalise_serial
        if normalise_serial(reported) != normalise_serial(format(cert.serial_number, "x")):
            raise CertError("серийный номер не совпадает с сертификатом")
    return cert
