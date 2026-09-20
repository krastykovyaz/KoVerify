"""Every server-rendered page must render for a real visitor."""
import pytest


@pytest.mark.parametrize("path", ["/", "/session/ABCD2345", "/result/ABCD2345"])
def test_public_pages_render(client, path):
    response = client.get(path)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Internal Server Error" not in body
    assert "jinja2" not in body.lower()


def test_session_code_reaches_the_page(client):
    code = client.post("/api/session/create").get_json()["code"]
    for path in (f"/session/{code}", f"/result/{code}"):
        assert code in client.get(path).get_data(as_text=True)


def test_join_code_input_accepts_a_full_length_code(client):
    """The input previously capped at 6 characters while real codes are 8,
    silently truncating every manually typed code to one that could never
    match a real session."""
    code = client.post("/api/session/create").get_json()["code"]
    assert len(code) == 8
    body = client.get("/").get_data(as_text=True)
    assert 'maxlength="8"' in body
    assert 'maxlength="6"' not in body


def test_result_page_polls_the_status_endpoint(client):
    """The page is useless if it is not wired to the status route."""
    body = client.get("/result/ABCD2345").get_data(as_text=True)
    assert "/api/session/" in body and "/status" in body


def test_pwa_manifest_is_served_and_valid(client):
    response = client.get("/manifest.json")
    assert response.status_code == 200
    payload = response.get_json(force=True)
    assert payload["name"]
    icon = payload["icons"][0]["src"]
    assert client.get(icon).status_code == 200, f"manifest points at missing {icon}"


def test_pages_advertise_the_manifest(client):
    for path in ("/", "/session/ABCD2345"):
        assert "/manifest.json" in client.get(path).get_data(as_text=True)


def test_login_page_renders(client):
    assert client.get("/admin/login").status_code == 200


def test_polling_tolerates_several_tabs(client):
    """Four tabs polling every two seconds must not be throttled."""
    code = client.post("/api/session/create").get_json()["code"]
    statuses = [client.get(f"/api/session/{code}/status").status_code
                for _ in range(4 * 30)]
    assert 429 not in statuses
