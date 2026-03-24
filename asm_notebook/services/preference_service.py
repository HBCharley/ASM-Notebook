from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import UserPreference


def _key(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise HTTPException(
            status_code=400, detail={"error": "invalid_key", "message": "Key is required"}
        )
    if len(value) > 128:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_key", "message": "Key is too long"},
        )
    return value


def get_preference(session: Session, *, user_id: uuid.UUID, key: str) -> dict[str, Any] | None:
    key = _key(key)
    row = (
        session.execute(
            select(UserPreference).where(
                UserPreference.user_id == user_id, UserPreference.key == key
            )
        )
        .scalars()
        .first()
    )
    if not row:
        return None
    try:
        return json.loads(row.value_json or "{}")
    except Exception:
        return None


def set_preference(
    session: Session, *, user_id: uuid.UUID, key: str, value: dict[str, Any]
) -> dict[str, Any]:
    key = _key(key)
    try:
        payload = json.dumps(value or {}, ensure_ascii=False)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_value", "message": "Value must be JSON-serializable"},
        )

    row = (
        session.execute(
            select(UserPreference).where(
                UserPreference.user_id == user_id, UserPreference.key == key
            )
        )
        .scalars()
        .first()
    )
    if row:
        row.value_json = payload
    else:
        row = UserPreference(user_id=user_id, key=key, value_json=payload)
        session.add(row)
    session.commit()
    return value or {}

