"""Apple configuration profile generation."""
import secrets
from xml.sax.saxutils import escape


def build(name, user_id, p12_b64):
    """Build a .mobileconfig carrying the user's PKCS#12 bundle.

    The passphrase is deliberately omitted. iOS then prompts the person to type
    it during installation, which keeps the secret out of a file that is served
    over the network and often synced to a mail client or cloud backup.
    """
    profile_uuid = secrets.token_hex(16).upper()
    payload_uuid = secrets.token_hex(16).upper()
    safe_name = escape(name)
    safe_id = escape(user_id)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadContent</key><array><dict>
    <key>PayloadType</key><string>com.apple.security.pkcs12</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>PayloadIdentifier</key><string>com.verifier.cert.{safe_id}</string>
    <key>PayloadUUID</key><string>{payload_uuid}</string>
    <key>PayloadDisplayName</key><string>Verifier — {safe_name}</string>
    <key>PayloadContent</key><data>{p12_b64}</data>
  </dict></array>
  <key>PayloadDisplayName</key><string>Verifier — {safe_name}</string>
  <key>PayloadIdentifier</key><string>com.verifier.profile.{safe_id}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{profile_uuid}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadOrganization</key><string>Verifier</string>
</dict></plist>"""
