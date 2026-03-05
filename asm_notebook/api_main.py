from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .init_db import init_db
import json

from sqlalchemy import delete, func, select

from .services import company_service, scan_service, cve_service
from .db import SessionLocal
from .models import (
    AuthAllowlist,
    Company,
    CompanyGroup,
    Group,
    ScanArtifact,
    ScanRun,
    User,
)
from .security import CurrentUser, forbidden_response, get_current_user
from .access_control import get_effective_group, query_companies_with_access
from .services import group_service

logger = logging.getLogger("asm_notebook.auth")

app = FastAPI(
    title="ASM Notebook API",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
)
router = APIRouter()


@app.exception_handler(HTTPException)
def _http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict) and exc.detail.get("error"):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


def _cors_origins() -> list[str]:
    raw = os.getenv("ASM_CORS_ORIGINS", "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    ]


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if raw == "":
        return default
    return raw in {"1", "true", "yes", "y", "on"}


def _demo_mode() -> bool:
    return _env_bool("DEMO_MODE", False)


def _tasks_enabled() -> bool:
    if os.getenv("ENABLE_TASKS") is not None:
        return _env_bool("ENABLE_TASKS", False)
    return _env_bool("ASM_TASKS_ENABLED", False)


def _validate_startup_config() -> None:
    demo = _demo_mode()
    client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    if not demo and not client_id:
        raise RuntimeError("GOOGLE_OAUTH_CLIENT_ID must be set unless DEMO_MODE=true")

    if _tasks_enabled() and not os.getenv("ASM_TASKS_SECRET", "").strip():
        raise RuntimeError("ASM_TASKS_SECRET must be set when ENABLE_TASKS=true")

    if not demo:
        raw = os.getenv("ASM_CORS_ORIGINS", "").strip()
        if not raw or "*" in {o.strip() for o in raw.split(",")}:
            raise RuntimeError(
                "ASM_CORS_ORIGINS must be explicitly set for production (no '*')"
            )


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CompanyCreate(BaseModel):
    slug: str
    name: str
    domains: list[str]
    group_ids: list[str] | None = None


class DomainReplace(BaseModel):
    domains: list[str]


class ScanRequest(BaseModel):
    deep_scan: bool = False


class CompanyUpdate(BaseModel):
    name: str


class AuthAllowlistEntry(BaseModel):
    email: str
    role: str


class GroupCreate(BaseModel):
    name: str


class CompanyGroupsUpdate(BaseModel):
    groups: list[str]


class UserGroupUpdate(BaseModel):
    email: str
    group: str


class CompanyGroupIdsUpdate(BaseModel):
    group_ids: list[str]


class UserGroupIdUpdate(BaseModel):
    group_id: str


class TaskRunScan(BaseModel):
    scan_id: int


@app.on_event("startup")
def _startup() -> None:
    _validate_startup_config()
    init_db()
    group_service.ensure_default_groups()


@router.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


def _scan_limits(role: str) -> dict[str, int]:
    def _int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, str(default)).strip())
        except Exception:
            return default

    if role == "admin":
        return {
            "cooldown_seconds": _int("ADMIN_SCAN_COOLDOWN_SECONDS", 300),
            "scans_per_hour": _int("ADMIN_SCANS_PER_HOUR", 20),
        }
    if role == "user":
        return {
            "cooldown_seconds": _int("USER_SCAN_COOLDOWN_SECONDS", 1800),
            "scans_per_hour": _int("USER_SCANS_PER_HOUR", 2),
        }
    return {"cooldown_seconds": 0, "scans_per_hour": 0}


def _require_task_secret(request: Request) -> None:
    secret = os.getenv("ASM_TASKS_SECRET", "").strip()
    if not secret:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "forbidden",
                "message": "ASM_TASKS_SECRET is required for task execution",
            },
        )
    header = request.headers.get("X-Tasks-Secret", "")
    if header != secret:
        raise HTTPException(
            status_code=403,
            detail={"error": "forbidden", "message": "Invalid task secret"},
        )


def _require_authenticated(current_user: CurrentUser | None) -> CurrentUser:
    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Authentication required"},
        )
    return current_user


def _require_admin(current_user: CurrentUser | None) -> CurrentUser:
    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Authentication required"},
        )
    if not current_user.is_admin:
        raise forbidden_response("user", "Admin access required")
    return current_user


def _principal_for_log(current_user: CurrentUser | None) -> str:
    if current_user is None:
        return "public:-"
    role = "admin" if current_user.is_admin else "user"
    return f"{role}:{current_user.email or '-'}"


def _allowed_company_slugs(
    session: SessionLocal, current_user: CurrentUser | None
) -> list[str]:
    rows = session.execute(
        query_companies_with_access(session, current_user).with_only_columns(
            Company.slug, maintain_column_froms=True
        )
    ).scalars().all()
    return sorted({*rows})


def _enforce_company_access(
    session: SessionLocal,
    current_user: CurrentUser | None,
    slug: str,
    write: bool = False,
    scan: bool = False,
) -> Company:
    company = (
        session.execute(select(Company).where(Company.slug == slug)).scalars().first()
    )
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    if current_user is not None and current_user.is_admin:
        return company
    role = "public" if current_user is None else "user"
    if write or scan:
        if current_user is None:
            raise HTTPException(
                status_code=401,
                detail={"error": "unauthorized", "message": "Authentication required"},
            )
    effective_group_id = get_effective_group(current_user)
    in_group = (
        session.execute(
            select(func.count())
            .select_from(CompanyGroup)
            .where(
                CompanyGroup.company_id == company.id,
                CompanyGroup.group_id == effective_group_id,
            )
        )
        .scalar_one()
        or 0
    ) > 0
    if not in_group:
        raise forbidden_response(role, "Company access denied", company.slug)
    return company


@router.get("/debug/cve")
def cve_debug(
    keywords: str | None = None,
    current_user: CurrentUser | None = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(current_user)
    samples = [k.strip() for k in (keywords or "").split(",") if k.strip()]
    return cve_service.get_cve_status(samples or None)


@router.get("/debug/cve/evidence")
def cve_evidence(
    company_slug: str,
    scan_id: int | None = None,
    domain: str | None = None,
    current_user: CurrentUser | None = Depends(get_current_user),
) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _enforce_company_access(s, current_user, company_slug, write=False)
        if scan_id is None:
            scan = (
                s.execute(
                    select(ScanRun)
                    .where(ScanRun.company_id == company.id)
                    .order_by(ScanRun.company_scan_number.desc())
                )
                .scalars()
                .first()
            )
        else:
            scan = s.get(ScanRun, scan_id)
            if scan and scan.company_id != company.id:
                scan = None
        if not scan:
            return {"error": "scan_not_found"}
        art = s.execute(
            select(ScanArtifact).where(
                ScanArtifact.scan_id == scan.id,
                ScanArtifact.artifact_type == "dns_intel",
            )
        ).scalar_one_or_none()
        if not art:
            return {"error": "dns_intel_not_found"}
        payload = json.loads(art.json_text)
        domains = payload.get("domains") or []
        if domain:
            d = domain.lower().strip(".")
            domains = [row for row in domains if str(row.get("domain", "")).lower() == d]
        return scan_service.build_cve_debug(domains)


@router.get("/me")
def me(current_user: CurrentUser | None = Depends(get_current_user)) -> dict[str, Any]:
    with SessionLocal() as s:
        allowed = _allowed_company_slugs(s, current_user)
        public_slugs = (
            s.execute(
                select(Company.slug)
                .join(CompanyGroup, CompanyGroup.company_id == Company.id)
                .join(Group, Group.id == CompanyGroup.group_id)
                .where(Group.name == group_service.UNAUTH_GROUP)
            )
            .scalars()
            .all()
        )
        role = "public"
        if current_user is not None:
            role = "admin" if current_user.is_admin else "user"
        max_companies = 3 if role == "user" else 0
        if role == "admin":
            max_companies = 0
        owned_count = 0
        if role == "user" and current_user is not None:
            owned_count = (
                s.execute(
                    select(func.count(Company.id)).where(
                        Company.created_by_user_id == current_user.id
                    )
                )
                .scalars()
                .first()
                or 0
            )
        return {
            "role": role,
            "email": current_user.email if current_user else None,
            "group_id": get_effective_group(current_user),
            "allowed_company_slugs": allowed,
            "public_company_slugs": public_slugs,
            "max_companies": max_companies,
            "owned_company_count": owned_count,
            "scan_limits": _scan_limits(role),
        }


@router.get("/admin/auth-allowlist")
def list_auth_allowlist(
    current_user: CurrentUser | None = Depends(get_current_user),
) -> list[dict[str, Any]]:
    _require_admin(current_user)
    with SessionLocal() as s:
        entries = (
            s.execute(select(AuthAllowlist).order_by(AuthAllowlist.email.asc()))
            .scalars()
            .all()
        )
        return [{"email": row.email, "role": row.role} for row in entries]


@router.post("/admin/auth-allowlist", status_code=201)
def add_auth_allowlist(
    payload: AuthAllowlistEntry, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, Any]:
    _require_admin(current_user)
    email = payload.email.strip().lower()
    role = payload.role.strip().lower()
    if role not in {"admin", "user"}:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_role", "message": "Role must be admin or user"},
        )
    if not email:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_email", "message": "Email is required"},
        )
    with SessionLocal() as s:
        existing = (
            s.execute(select(AuthAllowlist).where(AuthAllowlist.email == email))
            .scalars()
            .first()
        )
        if existing:
            existing.role = role
            s.add(existing)
        else:
            s.add(AuthAllowlist(email=email, role=role))
        s.commit()
    with SessionLocal() as s:
        user = s.execute(select(User).where(User.email == email)).scalars().first()
        if not user:
            group_id = None
            if role == "user":
                group_id = group_service.resolve_group_id(group_service.DEFAULT_GROUP)
            user = User(email=email, is_admin=(role == "admin"), group_id=group_id)
            s.add(user)
        else:
            user.is_admin = role == "admin"
            if not user.is_admin and not user.group_id:
                user.group_id = group_service.resolve_group_id(group_service.DEFAULT_GROUP)
            if user.is_admin:
                user.group_id = None
        s.commit()
    return {"email": email, "role": role}


@router.delete("/admin/auth-allowlist/{email}")
def delete_auth_allowlist(
    email: str, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, Any]:
    _require_admin(current_user)
    email = email.strip().lower()
    with SessionLocal() as s:
        existing = (
            s.execute(select(AuthAllowlist).where(AuthAllowlist.email == email))
            .scalars()
            .first()
        )
        if not existing:
            raise HTTPException(
                status_code=404,
                detail={"error": "not_found", "message": "Email not found"},
            )
        s.delete(existing)
        s.commit()
    return {"email": email, "deleted": True}


@router.get("/admin/groups")
def list_groups(current_user: CurrentUser | None = Depends(get_current_user)) -> list[str]:
    _require_admin(current_user)
    return group_service.list_groups()


@router.post("/admin/groups", status_code=201)
def create_group(
    payload: GroupCreate, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, str]:
    _require_admin(current_user)
    return group_service.create_group(payload.name)


@router.delete("/admin/groups/{name}")
def delete_group(name: str, current_user: CurrentUser | None = Depends(get_current_user)) -> dict[str, str]:
    _require_admin(current_user)
    normalized = name.strip()
    if normalized in {group_service.UNAUTH_GROUP, group_service.DEFAULT_GROUP}:
        raise HTTPException(
            status_code=400,
            detail={"error": "protected_group", "message": "Default groups cannot be removed"},
        )
    return group_service.delete_group(normalized)


@router.put("/admin/companies/{slug}/groups")
def update_company_groups(
    slug: str,
    payload: CompanyGroupsUpdate,
    current_user: CurrentUser | None = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(current_user)
    with SessionLocal() as s:
        company = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        groups = group_service.set_company_groups(company, payload.groups, session=s)
        s.commit()
        s.refresh(company)
        return {"slug": company.slug, "groups": groups}


@router.post("/admin/companies/{company_id}/groups")
def assign_company_groups(
    company_id: str,
    payload: CompanyGroupIdsUpdate,
    current_user: CurrentUser | None = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(current_user)
    with SessionLocal() as s:
        groups = group_service.set_company_groups_by_ids(
            company_id, payload.group_ids, session=s
        )
        s.commit()
        return {"company_id": company_id, "groups": groups}


@router.delete("/admin/companies/{company_id}/groups/{group_id}")
def remove_company_group(
    company_id: str,
    group_id: str,
    current_user: CurrentUser | None = Depends(get_current_user),
) -> dict[str, Any]:
    _require_admin(current_user)
    with SessionLocal() as s:
        company_uuid = uuid.UUID(str(company_id))
        group_uuid = uuid.UUID(str(group_id))
        entry = (
            s.execute(
                select(CompanyGroup).where(
                    CompanyGroup.company_id == company_uuid,
                    CompanyGroup.group_id == group_uuid,
                )
            )
            .scalars()
            .first()
        )
        if not entry:
            raise HTTPException(status_code=404, detail="Assignment not found")
        s.delete(entry)
        s.commit()
        return {"company_id": company_id, "group_id": group_id, "deleted": True}


@router.patch("/admin/users/{user_id}/group")
def update_user_group_id(
    user_id: str,
    payload: UserGroupIdUpdate,
    current_user: CurrentUser | None = Depends(get_current_user),
) -> dict[str, str]:
    _require_admin(current_user)
    with SessionLocal() as s:
        user = s.get(User, uuid.UUID(str(user_id)))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        group = s.get(Group, uuid.UUID(str(payload.group_id)))
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        user.is_admin = False
        user.group_id = group.id
        s.commit()
        return {"user_id": str(user.id), "group_id": str(group.id)}


@router.get("/admin/user-groups")
def list_user_groups(current_user: CurrentUser | None = Depends(get_current_user)) -> list[dict[str, str]]:
    _require_admin(current_user)
    return group_service.list_user_groups()


@router.put("/admin/user-groups")
def update_user_group(
    payload: UserGroupUpdate, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, str]:
    _require_admin(current_user)
    if payload.group.strip() in {group_service.UNAUTH_GROUP, ""}:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_group", "message": "Group is required"},
        )
    with SessionLocal() as s:
        user = s.execute(select(User).where(User.email == payload.email.lower().strip())).scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return group_service.set_user_group(str(user.id), payload.group)


@router.post("/companies", status_code=201)
def create_company(
    payload: CompanyCreate, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, Any]:
    user = _require_authenticated(current_user)
    role = "admin" if user.is_admin else "user"
    owner_email = user.email if role == "user" else None
    visibility = "private"
    group_ids: list[str] | None = None
    if role == "admin":
        if payload.group_ids:
            group_ids = payload.group_ids
        else:
            group_ids = [str(group_service.resolve_group_id(group_service.DEFAULT_GROUP))]
    else:
        if not user.group_id:
            raise forbidden_response("user", "User group is required")
        group_ids = [str(user.group_id)]
    if role == "user":
        with SessionLocal() as s:
            owned_count = (
                s.execute(
                    select(func.count(Company.id)).where(
                        Company.created_by_user_id == user.id
                    )
                )
                .scalars()
                .first()
                or 0
            )
            if owned_count >= 3:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "limit_reached",
                        "message": "User can create up to 3 companies.",
                    },
                )
    logger.info("create_company role=%s email=%s", role, user.email)
    return company_service.create_company(
        payload.slug,
        payload.name,
        payload.domains,
        owner_email=owner_email,
        visibility=visibility,
        group_ids=group_ids,
        created_by_user_id=user.id,
    )


@router.get("/companies")
def list_companies(current_user: CurrentUser | None = Depends(get_current_user)) -> list[dict[str, Any]]:
    with SessionLocal() as s:
        companies = (
            s.execute(
                query_companies_with_access(s, current_user).order_by(Company.slug)
            )
            .scalars()
            .all()
        )
        return [
            {
                "id": company.id,
                "slug": company.slug,
                "name": company.name,
                "domains": [d.domain for d in company.domains],
                "owner_email": company.owner_email,
                "visibility": company.visibility,
                "created_by_user_id": company.created_by_user_id,
                "groups": [g.name for g in company.groups],
            }
            for company in companies
        ]


@router.get("/companies/{slug}")
def get_company(slug: str, current_user: CurrentUser | None = Depends(get_current_user)) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _enforce_company_access(s, current_user, slug, write=False)
        return {
            "id": company.id,
            "slug": company.slug,
            "name": company.name,
            "domains": [d.domain for d in company.domains],
            "owner_email": company.owner_email,
            "visibility": company.visibility,
            "created_by_user_id": company.created_by_user_id,
            "groups": [g.name for g in company.groups],
        }


@router.patch("/companies/{slug}")
def update_company(
    slug: str, payload: CompanyUpdate, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, write=True)
    role = "admin" if current_user and current_user.is_admin else "user"
    logger.info("update_company role=%s email=%s slug=%s", role, current_user.email if current_user else None, slug)
    return company_service.update_company(slug, payload.name)


@router.put("/companies/{slug}/domains")
def replace_domains(
    slug: str, payload: DomainReplace, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, write=True)
    role = "admin" if current_user and current_user.is_admin else "user"
    logger.info("replace_domains role=%s email=%s slug=%s", role, current_user.email if current_user else None, slug)
    return company_service.replace_domains(slug, payload.domains)


@router.delete("/companies/{slug}", status_code=204)
def delete_company(slug: str, current_user: CurrentUser | None = Depends(get_current_user)) -> None:
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, write=True)
    role = "admin" if current_user and current_user.is_admin else "user"
    logger.info("delete_company role=%s email=%s slug=%s", role, current_user.email if current_user else None, slug)
    company_service.delete_company(slug)


@router.post("/companies/{slug}/scans", status_code=201)
def trigger_scan(
    slug: str,
    background_tasks: BackgroundTasks,
    payload: ScanRequest | None = None,
    current_user: CurrentUser | None = Depends(get_current_user),
) -> dict[str, Any]:
    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Authentication required"},
        )
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, scan=True)
    deep_scan = bool(payload.deep_scan) if payload else False
    role = "admin" if current_user.is_admin else "user"
    logger.info("trigger_scan role=%s email=%s slug=%s", role, current_user.email, slug)
    return scan_service.trigger_scan(
        slug, background_tasks, deep_scan=deep_scan, current_user=current_user
    )


@router.post("/tasks/run_scan", status_code=200)
def run_scan_task(payload: TaskRunScan, request: Request) -> dict[str, Any]:
    _require_task_secret(request)
    scan_service.run_scan_task(payload.scan_id)
    return {"ok": True, "scan_id": payload.scan_id}


@router.get("/tasks/health")
def tasks_health() -> dict[str, Any]:
    return scan_service.tasks_status()


@router.get("/companies/{slug}/scans")
def list_scans(slug: str, current_user: CurrentUser | None = Depends(get_current_user)) -> list[dict[str, Any]]:
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, write=False)
    return scan_service.list_scans(slug)


@router.get("/companies/{slug}/scans/latest")
def get_latest_scan(slug: str, current_user: CurrentUser | None = Depends(get_current_user)) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, write=False)
    return scan_service.get_latest_scan(slug)


@router.get("/companies/{slug}/scans/{scan_id}")
def get_company_scan(
    slug: str, scan_id: int, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, write=False)
    return scan_service.get_company_scan(slug, scan_id)


@router.get("/companies/{slug}/scans/by-number/{company_scan_number}")
def get_company_scan_by_number(
    slug: str,
    company_scan_number: int,
    current_user: CurrentUser | None = Depends(get_current_user),
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, write=False)
    return scan_service.get_company_scan_by_number(slug, company_scan_number)


@router.get("/companies/{slug}/scans/{scan_id}/artifacts")
def get_company_scan_artifacts(
    slug: str, scan_id: int, current_user: CurrentUser | None = Depends(get_current_user)
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, write=False)
    return scan_service.get_company_scan_artifacts(slug, scan_id)


@router.delete("/companies/{slug}/scans/{scan_id}", status_code=204)
def delete_company_scan(
    slug: str, scan_id: int, current_user: CurrentUser | None = Depends(get_current_user)
) -> None:
    if current_user is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Authentication required"},
        )
    with SessionLocal() as s:
        _enforce_company_access(s, current_user, slug, scan=True)
    role = "admin" if current_user.is_admin else "user"
    logger.info("delete_scan role=%s email=%s slug=%s scan_id=%s", role, current_user.email, slug, scan_id)
    scan_service.delete_company_scan(slug, scan_id)


app.include_router(router, prefix="/api/v1")


def _resolve_dist_dir() -> Path | None:
    env_override = os.getenv("ASM_FRONTEND_DIST", "").strip()
    candidates: list[Path] = []
    if env_override:
        candidates.append(Path(env_override))
    repo_root = Path(__file__).resolve().parent.parent
    candidates.extend([repo_root / "dist", repo_root / "frontend" / "dist"])
    for candidate in candidates:
        if (candidate / "index.html").is_file():
            return candidate
    return None


_DIST_DIR = _resolve_dist_dir()


def _static_response(path: Path, cacheable: bool) -> FileResponse:
    response = FileResponse(path)
    if cacheable:
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    if path.suffix.lower() == ".html":
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
    return response


if _DIST_DIR:
    @app.get("/", include_in_schema=False)
    def _serve_index() -> FileResponse:
        return _static_response(_DIST_DIR / "index.html", cacheable=False)

    @app.get("/{path:path}", include_in_schema=False)
    def _serve_spa(path: str) -> FileResponse:
        if path == "health" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")
        candidate = (_DIST_DIR / path).resolve()
        if candidate.is_file() and str(candidate).startswith(str(_DIST_DIR.resolve())):
            cacheable = path.startswith("assets/")
            return _static_response(candidate, cacheable)
        return _static_response(_DIST_DIR / "index.html", cacheable=False)
