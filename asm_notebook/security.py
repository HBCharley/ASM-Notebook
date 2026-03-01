from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request
from google.auth.transport import requests as grequests
from google.oauth2 import id_token


@dataclass(frozen=True)
class Principal:
    role: str
    email: str | None
    sub: str | None
    authenticated: bool = False


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
    payload = id_token.verify_oauth2_token(token, grequests.Request(), client_id)
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


def get_principal(request: Request) -> Principal:
    auth_header = request.headers.get("Authorization") or ""
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return Principal(role="public", email=None, sub=None, authenticated=False)

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return Principal(role="public", email=None, sub=None, authenticated=False)

    payload = _verify_token(token)
    email = str(payload.get("email") or "").lower() or None
    sub = payload.get("sub") or None
    role = _role_for_email(email)
    return Principal(role=role, email=email, sub=sub, authenticated=True)


def forbidden_response(role: str, message: str, company: str | None = None) -> HTTPException:
    detail = {"error": "forbidden", "message": message, "role": role}
    if company:
        detail["company"] = company
    return HTTPException(status_code=403, detail=detail)
