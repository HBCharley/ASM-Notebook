from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DB_PATH = os.environ.get("ASM_DB_PATH", "asm_notebook.sqlite3")
DATABASE_URL = os.environ.get("ASM_DATABASE_URL", f"sqlite:///{DB_PATH}")

# Normalise legacy postgres:// and postgresql:// URIs to the psycopg3 dialect
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

ENGINE = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    connect_args=connect_args,
)
SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass
