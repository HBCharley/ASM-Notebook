from sqlalchemy import text

from .db import ENGINE


def init_db() -> None:
    # Migrations are the source of truth; this just verifies connectivity.
    with ENGINE.connect() as conn:
        conn.execute(text("SELECT 1"))
