"""Administrative access control."""
import pytest

from conftest import ADMIN_PASSWORD, make_config
from verifier import create_app
from verifier.ca import generate_ca

PROTECTED = [
    ("get", "/admin"),
    ("get", "/admin/api/user/anyone"),
    ("get", "/admin/api/ca-cert"),
    ("post", "/admin/api/register"),
    ("post", "/admin/api/revoke"),
    ("post", "/admin/api/restore"),
    ("post", "/admin/api/init-ca"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_admin_routes_reject_anonymous_callers(client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code in (302, 303, 401)
    if response.status_code in (302, 303):
        assert "/admin/login" in response.headers["Location"]


def test_wrong_password_does_not_grant_access(client):
    client.post("/admin/login", data={"password": "not-the-password"})
    assert client.get("/admin").status_code in (302, 303)


def test_correct_password_grants_access(admin):
    assert admin.get("/admin").status_code == 200


def test_logout_clears_the_session(admin):
    admin.post("/admin/logout")
    assert admin.get("/admin").status_code in (302, 303)


def test_login_is_rate_limited(client):
    """Unlimited guessing against a password is the whole attack."""
    seen_429 = False
    for _ in range(12):
        response = client.post("/admin/login", data={"password": "wrong"})
        if response.status_code == 429:
            seen_429 = True
            break
    assert seen_429, "brute force was never throttled"


def test_throttling_does_not_leak_through_forged_forwarded_header(client):
    """X-Forwarded-For from an untrusted peer must not reset the bucket."""
    for i in range(12):
        response = client.post(
            "/admin/login", data={"password": "wrong"},
            headers={"X-Forwarded-For": f"198.51.100.{i}"},
            environ_base={"REMOTE_ADDR": "203.0.113.9"},
        )
        if response.status_code == 429:
            return
    pytest.fail("rotating a forged header bypassed the limit")


def test_successful_login_clears_the_throttle(client):
    for _ in range(3):
        client.post("/admin/login", data={"password": "wrong"})
    assert client.post(
        "/admin/login", data={"password": ADMIN_PASSWORD}
    ).status_code in (302, 303)
    assert client.get("/admin").status_code == 200


def test_register_validates_the_identifier(admin):
    for bad in ["../etc/passwd", "a b", "x" * 100, "", "drop;table"]:
        body = admin.post(
            "/admin/api/register", json={"user_id": bad, "name": "X"}
        ).get_json()
        assert body["ok"] is False, f"accepted {bad!r}"


def test_register_rejects_a_duplicate(admin, cfg):
    first = admin.post("/admin/api/register",
                       json={"user_id": "dup-1", "name": "One"}).get_json()
    assert first["ok"]
    second = admin.post("/admin/api/register",
                        json={"user_id": "dup-1", "name": "Two"}).get_json()
    assert second["ok"] is False


def test_revoke_reports_an_unknown_user(admin):
    response = admin.post("/admin/api/revoke", json={"user_id": "ghost"})
    assert response.status_code == 404


def test_init_ca_refuses_to_overwrite_an_existing_ca(admin):
    body = admin.post("/admin/api/init-ca").get_json()
    assert body["ok"] is False


def test_download_link_in_admin_panel_is_a_real_link(admin):
    """The one-time download URL was a plain <div>, not clickable; an
    operator reading it off a phone had to select and copy it by hand."""
    body = admin.get("/admin").get_data(as_text=True)
    assert '<a href="#" target="_blank"' in body
    assert 'id="modal-download-url"' in body


def test_security_headers_are_present(client):
    headers = client.get("/").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_session_cookie_is_hardened(tmp_path):
    cfg = make_config(tmp_path)
    generate_ca(cfg)
    app = create_app(cfg, testing=True)
    app.config["SESSION_COOKIE_SECURE"] = True
    client = app.test_client()
    response = client.post("/admin/login", data={"password": ADMIN_PASSWORD})
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite" in cookie
