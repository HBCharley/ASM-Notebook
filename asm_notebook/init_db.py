from sqlalchemy import text

from .db import ENGINE, Base, IS_SQLITE
from . import models  # noqa: F401


def _sqlite_scan_number_migration() -> None:
    if not IS_SQLITE:
        return

    with ENGINE.begin() as conn:
        table_info = conn.execute(text("PRAGMA table_info(scan_runs)")).fetchall()
        if not table_info:
            return

        has_company_scan_number = any(row[1] == "company_scan_number" for row in table_info)
        if not has_company_scan_number:
            conn.execute(text("ALTER TABLE scan_runs ADD COLUMN company_scan_number INTEGER"))

        conn.execute(
            text(
                """
                WITH ranked AS (
                    SELECT id, ROW_NUMBER() OVER (PARTITION BY company_id ORDER BY id) AS rn
                    FROM scan_runs
                )
                UPDATE scan_runs
                SET company_scan_number = (SELECT rn FROM ranked WHERE ranked.id = scan_runs.id)
                WHERE company_scan_number IS NULL
                """
            )
        )

        conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_company_scan_number "
                "ON scan_runs(company_id, company_scan_number)"
            )
        )


def init_db() -> None:
    Base.metadata.create_all(bind=ENGINE)
    _sqlite_scan_number_migration()
