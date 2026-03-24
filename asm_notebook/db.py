from __future__ import annotations

import os
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def _normalize_database_url(raw: str) -> str:
    value = raw.strip()
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value[len("postgres://") :]
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value[len("postgresql://") :]
    return value


_raw_url = os.getenv("ASM_DATABASE_URL", "").strip()
if not _raw_url:
    raise RuntimeError(
        "ASM_DATABASE_URL is required and must point to PostgreSQL. "
        "Example: postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME"
    )

DATABASE_URL = _normalize_database_url(_raw_url)
if not DATABASE_URL.startswith("postgresql+psycopg://"):
    raise RuntimeError(
        "ASM_DATABASE_URL must be a PostgreSQL URL using postgresql+psycopg://"
    )

_engine_kwargs: dict[str, Any] = {
    "future": True,
    "pool_pre_ping": True,
}

ENGINE = create_engine(DATABASE_URL, **_engine_kwargs)
SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass
