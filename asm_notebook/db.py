from __future__ import annotations

import os
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase


def _default_sqlite_url() -> str:
    db_path = os.getenv("ASM_DB_PATH", "asm_notebook.sqlite3")
    return f"sqlite:///{db_path}"


def _normalize_database_url(raw: str) -> str:
    value = raw.strip()
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value[len("postgres://") :]
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value[len("postgresql://") :]
    return value


DB_PATH = os.getenv("ASM_DB_PATH", "asm_notebook.sqlite3")
DATABASE_URL = _normalize_database_url(os.getenv("ASM_DATABASE_URL", _default_sqlite_url()))
IS_SQLITE = DATABASE_URL.startswith("sqlite://")

_engine_kwargs: dict[str, Any] = {
    "future": True,
    "pool_pre_ping": True,
}
if IS_SQLITE:
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

ENGINE = create_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass
