"""Handing a participant everything at once, without the server ever holding it."""
import re
import sqlite3

from conftest import ADMIN_PASSWORD, register

PASSWORD_PATTERN = re.compile(r"^[A-Za-z0-9]{4,64}$")


def test_register_offers_a_link_that_carries_the_password(user):
    payload = user.payload
    assert payload["download_url_full"] == f"{payload['download_url']}#p={payload['p12_password']}"
    assert payload["qr_download_full_b64"] and payload["qr_download_b64"]
    assert payload["qr_download_full_b64"] != payload["qr_download_b64"]
    # The plain link must stay free of the password, for handing it over orally.
    assert payload["p12_password"] not in payload["download_url"]


def test_the_password_alphabet_fits_what_the_page_will_accept(user):
    assert PASSWORD_PATTERN.match(user.payload["p12_password"])
    page = open("templates/download.html").read()
    assert "/^[A-Za-z0-9]{4,64}$/" in page


def test_the_server_never_stores_the_certificate_password(user, cfg):
    password = user.payload["p12_password"]
    conn = sqlite3.connect(cfg.db_path)
    dump = "\n".join(conn.iterdump())
    conn.close()
    assert password not in dump


def test_the_download_page_never_receives_the_password(client, user):
    """A fragment is not sent, so the server-rendered page cannot contain it."""
    body = client.get(f"/download/{user.token}").get_data(as_text=True)
    assert user.payload["p12_password"] not in body


def test_the_download_page_shows_the_participants_login_and_ticket(client, user):
    body = client.get(f"/download/{user.token}").get_data(as_text=True)
    assert f'id="mine-id">{user.id}<' in body
    assert "Ваши данные для входа" in body
    assert user.payload["totp_secret"] in body
    assert 'id="mine-pw-row"' in body and "showPasswordFromLink" in body


def test_the_password_is_only_ever_written_with_textcontent(client, user):
    body = client.get(f"/download/{user.token}").get_data(as_text=True)
    script = body[body.index("showPasswordFromLink"):]
    assert "innerHTML" not in script.split("})()")[0]


def test_reissue_hands_out_the_same_all_in_one_link(admin, user):
    fresh = admin.post("/admin/api/reissue", json={"user_id": user.id}).get_json()
    assert fresh["download_url_full"].endswith(f"#p={fresh['p12_password']}")
    assert fresh["download_url_full"].startswith(fresh["download_url"])


def test_the_admin_panel_has_the_login_toggle_and_copy_all(admin):
    body = admin.get("/admin/").get_data(as_text=True)
    for needle in ('id="modal-user-id"', 'id="modal-all-at-once"', "function copyAll(",
                   "function renderDownload(", 'id="modal-copy-all"'):
        assert needle in body, needle


def test_no_page_relies_on_the_global_event_object():
    """Safari has never implemented it; it silently broke every copy button."""
    for path in ("templates/admin.html", "templates/download.html",
                 "templates/verify.html", "templates/index.html"):
        assert "event.target" not in open(path).read(), path
