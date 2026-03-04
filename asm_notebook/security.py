from __future__ import annotations

import logging
import os
from dataclasses import dataclass
import uuid
from typing import Any

from fastapi import HTTPException, Request
from google.auth.transport import requests as grequests
from google.oauth2 import id_token
from sqlalchemy import select

from .db import SessionLocal
from .models import AuthAllowlist, User
from .services import group_service

logger = logging.getLogger("asm_notebook.auth")


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    email: str
    is_admin: bool
    group_id: uuid.UUID | None


def _parse_csv_env(name: str, default: str = "") -> set[str]:
    raw = os.getenv(name, default)
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def public_company_slugs() -> list[str]:
    return sorted(_parse_csv_env("PUBLIC_COMPANY_SLUGS", "company-a,company-b"))


def admin_emails() -> set[str]:
    return _parse_csv_env("ADMIN_EMAILS")


def user_emails() -> set[str]:
    return _parse_csv_env("USER_EMAILS")


def _role_for_email(email: str | None) -> str:
    if not email:
        return "public"
    email = email.lower()
    if email in admin_emails():
        return "admin"
    if email in user_emails():
        return "user"
    try:
        with SessionLocal() as session:
            entry = (
                session.execute(
                    select(AuthAllowlist).where(AuthAllowlist.email == email)
                )
                .scalars()
                .first()
            )
            if entry:
                return entry.role
    except Exception:
        logger.warning("Auth allowlist lookup failed", exc_info=True)
    return "public"


def _require_client_id() -> str:
    client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    if not client_id:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Auth not configured"},
        )
    return client_id


def _verify_token(token: str) -> dict[str, Any]:
    client_id = _require_client_id()
    try:
        payload = id_token.verify_oauth2_token(token, grequests.Request(), client_id)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Invalid or expired token"},
        )
    if not payload:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Invalid token"},
        )
    if not payload.get("email_verified"):
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Email not verified"},
        )
    aud = payload.get("aud")
    if aud != client_id:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Invalid audience"},
        )
    return payload


def get_current_user(request: Request) -> CurrentUser | None:
    auth_header = request.headers.get("Authorization") or ""
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None

    payload = _verify_token(token)
    email = str(payload.get("email") or "").lower() or None
    if not email:
        return None
    role = _role_for_email(email)
    if role == "public":
        return None
    with SessionLocal() as session:
        user = (
            session.execute(select(User).where(User.email == email))
            .scalars()
            .first()
        )
        if not user:
            group_id = None
            if role == "user":
                group_id = group_service.resolve_group_id(group_service.DEFAULT_GROUP)
            user = User(email=email, is_admin=(role == "admin"), group_id=group_id)
            session.add(user)
            session.commit()
            session.refresh(user)
        else:
            if role == "admin" and not user.is_admin:
                user.is_admin = True
                user.group_id = None
                session.commit()
            if role == "user" and user.is_admin:
                user.is_admin = False
                if not user.group_id:
                    user.group_id = group_service.resolve_group_id(
                        group_service.DEFAULT_GROUP
                    )
                session.commit()
            if not user.is_admin and not user.group_id:
                user.group_id = group_service.resolve_group_id(
                    group_service.DEFAULT_GROUP
                )
                session.commit()
        return CurrentUser(
            id=user.id,
            email=user.email,
            is_admin=user.is_admin,
            group_id=user.group_id,
        )


def forbidden_response(role: str, message: str, company: str | None = None) -> HTTPException:
    detail = {"error": "forbidden", "message": message, "role": role}
    if company:
        detail["company"] = company
    return HTTPException(status_code=403, detail=detail)
