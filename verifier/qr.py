"""QR code rendering."""
import base64
import io

import qrcode


def qr_b64(data):
    image = qrcode.make(data)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()
