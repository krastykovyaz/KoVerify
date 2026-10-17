"""Delete rooms that have ended.

Run by a timer so that a room which ran out of time is wiped even when nobody
ever touches the site again. Everything it does is also done on contact, so
this only closes the gap between "expired" and "next request".

    python -m verifier.purge
"""
from .config import Config
from .db import connect, purge_expired


def main():
    cfg = Config()
    conn = connect(cfg.db_path)
    try:
        purge_expired(conn, cfg.nonce_ttl_seconds, cfg.proofs_dir)
        conn.commit()
        rooms = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        items = conn.execute("SELECT COUNT(*) FROM room_items").fetchone()[0]
    finally:
        conn.close()
    print(f"purged: {rooms} room records and {items} shared items remain")


if __name__ == "__main__":
    main()
