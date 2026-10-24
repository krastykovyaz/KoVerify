"""One-time credential links."""
from conftest import register


def test_download_page_renders(client, user):
    response = client.get(f"/download/{user.token}")
    assert response.status_code == 200
    assert user.name in response.get_data(as_text=True)


def test_invalid_token_renders_error_page_not_a_crash(client):
    """The error template was missing, turning every bad link into a 500."""
    response = client.get("/download/definitely-not-a-real-token")
    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert "Internal Server Error" not in body
    assert "недействительна" in body


def test_p12_link_is_single_use(client, user):
    first = client.get(f"/download/{user.token}/p12")
    assert first.status_code == 200
    assert len(first.get_data()) > 0
    second = client.get(f"/download/{user.token}/p12")
    assert second.status_code == 410


def test_p12_is_served_as_an_attachment(client, user):
    """Android/macOS/Windows instructions all say to open a downloaded file."""
    response = client.get(f"/download/{user.token}/p12")
    assert "attachment" in response.headers.get("Content-Disposition", "")


def test_mobileconfig_is_served_inline_not_as_attachment(client, user):
    """iOS Safari only offers the install-profile prompt for an inline
    response; as an attachment it silently lands in Files with no prompt,
    which looks like the download button does nothing."""
    response = client.get(f"/download/{user.token}/mobileconfig")
    disposition = response.headers.get("Content-Disposition", "")
    assert "attachment" not in disposition


def test_mobileconfig_link_is_single_use(client, user):
    """This route previously ignored the used flag entirely."""
    first = client.get(f"/download/{user.token}/mobileconfig")
    assert first.status_code == 200
    second = client.get(f"/download/{user.token}/mobileconfig")
    assert second.status_code == 410


def test_mobileconfig_cannot_resurrect_a_spent_p12_link(client, user):
    """The reported bypass: spend the p12 link, then keep pulling the profile."""
    assert client.get(f"/download/{user.token}/p12").status_code == 200
    leaked = client.get(f"/download/{user.token}/mobileconfig")
    assert leaked.status_code == 410
    assert b"pkcs12" not in leaked.get_data().lower()


def test_p12_cannot_follow_a_spent_mobileconfig_link(client, user):
    assert client.get(f"/download/{user.token}/mobileconfig").status_code == 200
    assert client.get(f"/download/{user.token}/p12").status_code == 410


def test_profile_does_not_embed_the_passphrase(client, user):
    """Shipping the password inside the profile defeats encrypting the bundle."""
    body = client.get(f"/download/{user.token}/mobileconfig").get_data(as_text=True)
    assert "<key>Password</key>" not in body
    assert user.payload["p12_password"] not in body


def test_page_reports_a_spent_link(client, user):
    client.get(f"/download/{user.token}/p12")
    response = client.get(f"/download/{user.token}")
    assert response.status_code == 410
    assert "использована" in response.get_data(as_text=True)


def test_expired_link_is_refused(client, user, cfg):
    import sqlite3
    from datetime import datetime, timedelta, timezone
    conn = sqlite3.connect(cfg.db_path)
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    conn.execute("UPDATE download_tokens SET expires_at=? WHERE token=?",
                 (past, user.token))
    conn.commit()
    conn.close()
    assert client.get(f"/download/{user.token}").status_code == 410
    assert client.get(f"/download/{user.token}/p12").status_code == 410
    assert client.get(f"/download/{user.token}/mobileconfig").status_code == 410


def test_revoking_a_user_kills_their_download_link(admin, cfg, client):
    victim = register(admin, cfg.db_path, user_id="carol-003", name="Carol Example")
    admin.post("/admin/api/revoke", json={"user_id": victim.id})
    assert client.get(f"/download/{victim.token}").status_code in (404, 410)
    assert client.get(f"/download/{victim.token}/p12").status_code in (404, 410)
