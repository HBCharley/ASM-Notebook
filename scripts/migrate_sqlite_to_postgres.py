from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Iterable

from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, create_engine, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.engine.url import make_url


TABLE_ORDER = [
    "companies",
    "company_domains",
    "scan_runs",
    "scan_artifacts",
]

TRUNCATE_ORDER = [
    "scan_artifacts",
    "scan_runs",
    "company_domains",
    "companies",
]


def _require_sqlite_file(sqlite_url: str) -> Path:
    url = make_url(sqlite_url)
    if url.get_backend_name() != "sqlite":
        raise SystemExit("Source must be a sqlite:// URL.")
    db_path = url.database
    if not db_path:
        raise SystemExit("SQLite URL must include a file path (not :memory:).")
    path = Path(db_path)
    if not path.exists():
        raise SystemExit(f"SQLite file not found: {path}")
    return path


def _alembic_upgrade(postgres_url: str) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config_path = repo_root / "alembic.ini"
    if not config_path.exists():
        raise SystemExit(f"Alembic config not found: {config_path}")
    cfg = Config(str(config_path))
    os.environ["ASM_DATABASE_URL"] = postgres_url
    command.upgrade(cfg, "head")


def _load_table_data(metadata: MetaData, engine: Engine, table_name: str) -> list[dict]:
    table = metadata.tables[table_name]
    with engine.connect() as conn:
        rows = conn.execute(select(table)).mappings().all()
    return [dict(row) for row in rows]


def _batched(items: list[dict], size: int = 1000) -> Iterable[list[dict]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _truncate_destination(engine: Engine) -> None:
    tables = ", ".join(TRUNCATE_ORDER)
    with engine.begin() as conn:
        conn.execute(text(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE"))


def _copy_table(engine: Engine, metadata: MetaData, table_name: str, rows: list[dict]) -> None:
    if not rows:
        return
    table = metadata.tables[table_name]
    with engine.begin() as conn:
        for batch in _batched(rows):
            conn.execute(table.insert(), batch)


def _sync_sequences(engine: Engine) -> None:
    with engine.begin() as conn:
        for table in TABLE_ORDER:
            conn.execute(
                text(
                    """
                    SELECT setval(
                        pg_get_serial_sequence(:table, 'id'),
                        COALESCE((SELECT MAX(id) FROM {table}), 1),
                        true
                    )
                    """.format(table=table)
                ),
                {"table": table},
            )


def _row_counts(metadata: MetaData, engine: Engine) -> dict[str, int]:
    counts: dict[str, int] = {}
    with engine.connect() as conn:
        for table in TABLE_ORDER:
            tbl = metadata.tables[table]
            counts[table] = conn.execute(select(text("COUNT(*)")).select_from(tbl)).scalar_one()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate ASM Notebook from SQLite to PostgreSQL.")
    parser.add_argument("--sqlite", required=True, help="sqlite:///path/to/asm_notebook.sqlite3")
    parser.add_argument("--postgres", required=True, help="postgresql+psycopg://USER:PASS@HOST:5432/DB")
    parser.add_argument(
        "--yes-i-know-this-truncates",
        action="store_true",
        help="Required confirmation flag (truncates destination tables).",
    )
    args = parser.parse_args()

    if not args.yes_i_know_this_truncates:
        raise SystemExit("Refusing to run without --yes-i-know-this-truncates.")

    _require_sqlite_file(args.sqlite)

    try:
        sqlite_engine = create_engine(args.sqlite, future=True)
    except OperationalError as exc:
        raise SystemExit(f"Failed to connect to SQLite: {exc}") from exc

    try:
        postgres_engine = create_engine(args.postgres, future=True)
    except OperationalError as exc:
        raise SystemExit(f"Failed to connect to PostgreSQL: {exc}") from exc

    _alembic_upgrade(args.postgres)

    metadata_src = MetaData()
    metadata_src.reflect(bind=sqlite_engine, only=TABLE_ORDER)
    metadata_dst = MetaData()
    metadata_dst.reflect(bind=postgres_engine, only=TABLE_ORDER)

    _truncate_destination(postgres_engine)

    for table_name in TABLE_ORDER:
        rows = _load_table_data(metadata_src, sqlite_engine, table_name)
        _copy_table(postgres_engine, metadata_dst, table_name, rows)

    _sync_sequences(postgres_engine)

    src_counts = _row_counts(metadata_src, sqlite_engine)
    dst_counts = _row_counts(metadata_dst, postgres_engine)

    print("Row counts (sqlite -> postgres):")
    for table in TABLE_ORDER:
        print(f"  {table}: {src_counts[table]} -> {dst_counts[table]}")

    if src_counts != dst_counts:
        raise SystemExit("Row count mismatch between SQLite and PostgreSQL.")

    print("Migration complete.")


if __name__ == "__main__":
    main()
