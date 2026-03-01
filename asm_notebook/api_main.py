from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .init_db import init_db
import json

from sqlalchemy import func, or_, select

from .services import company_service, scan_service, cve_service
from .db import SessionLocal
from .models import Company, ScanArtifact, ScanRun
from .security import Principal, forbidden_response, get_principal, public_company_slugs

logger = logging.getLogger("asm_notebook.auth")

app = FastAPI(
    title="ASM Notebook API",
    docs_url="/v1/docs",
    redoc_url="/v1/redoc",
    openapi_url="/v1/openapi.json",
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


class DomainReplace(BaseModel):
    domains: list[str]


class ScanRequest(BaseModel):
    deep_scan: bool = False


class CompanyUpdate(BaseModel):
    name: str


@app.on_event("startup")
def _startup() -> None:
    init_db()


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


def _principal_for_log(principal: Principal) -> str:
    return f"{principal.role}:{principal.email or '-'}"


def _allowed_company_slugs(session: SessionLocal, principal: Principal) -> list[str]:
    public_slugs = public_company_slugs()
    if principal.role == "admin":
        rows = session.execute(select(Company.slug)).scalars().all()
        return sorted({*rows})
    if principal.role == "user" and principal.email:
        rows = session.execute(
            select(Company.slug).where(
                or_(
                    Company.slug.in_(public_slugs),
                    Company.owner_email == principal.email,
                )
            )
        ).scalars().all()
        return sorted({*rows})
    return public_slugs


def _enforce_company_access(
    session: SessionLocal,
    principal: Principal,
    slug: str,
    write: bool = False,
    scan: bool = False,
) -> Company:
    company = (
        session.execute(select(Company).where(Company.slug == slug)).scalars().first()
    )
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    if principal.role == "admin":
        return company
    public_slugs = public_company_slugs()
    is_public = company.slug in public_slugs or company.visibility == "public_demo"
    is_owner = bool(principal.email and company.owner_email == principal.email)
    if not is_public and not is_owner:
        raise forbidden_response(principal.role, "Company access denied", company.slug)
    if (write or scan) and not is_owner:
        raise forbidden_response(principal.role, "Company write access denied", company.slug)
    return company


@router.get("/debug/cve")
def cve_debug(
    keywords: str | None = None,
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if principal.role != "admin":
        raise forbidden_response(principal.role, "Admin access required")
    samples = [k.strip() for k in (keywords or "").split(",") if k.strip()]
    return cve_service.get_cve_status(samples or None)


@router.get("/debug/cve/evidence")
def cve_evidence(
    company_slug: str,
    scan_id: int | None = None,
    domain: str | None = None,
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _enforce_company_access(s, principal, company_slug, write=False)
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
def me(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    with SessionLocal() as s:
        allowed = _allowed_company_slugs(s, principal)
        public_slugs = public_company_slugs()
        max_companies = 3 if principal.role == "user" else 0
        if principal.role == "admin":
            max_companies = 0
        owned_count = 0
        if principal.role == "user" and principal.email:
            owned_count = (
                s.execute(
                    select(func.count(Company.id)).where(
                        Company.owner_email == principal.email
                    )
                )
                .scalars()
                .first()
                or 0
            )
        return {
            "role": principal.role,
            "email": principal.email,
            "allowed_company_slugs": allowed,
            "public_company_slugs": public_slugs,
            "max_companies": max_companies,
            "owned_company_count": owned_count,
            "scan_limits": _scan_limits(principal.role),
        }


@router.post("/companies", status_code=201)
def create_company(
    payload: CompanyCreate, principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    if principal.role == "public":
        raise forbidden_response(principal.role, "Company creation forbidden")
    owner_email = principal.email if principal.role == "user" else None
    visibility = "private"
    public_slugs = public_company_slugs()
    if principal.role == "admin" and payload.slug.strip().lower() in public_slugs:
        visibility = "public_demo"
        owner_email = None
    if principal.role == "user":
        with SessionLocal() as s:
            owned_count = (
                s.execute(
                    select(func.count(Company.id)).where(
                        Company.owner_email == principal.email
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
    logger.info("create_company role=%s email=%s", principal.role, principal.email)
    return company_service.create_company(
        payload.slug,
        payload.name,
        payload.domains,
        owner_email=owner_email,
        visibility=visibility,
    )


@router.get("/companies")
def list_companies(principal: Principal = Depends(get_principal)) -> list[dict[str, Any]]:
    with SessionLocal() as s:
        allowed = set(_allowed_company_slugs(s, principal))
        if principal.role == "admin":
            companies = (
                s.execute(select(Company).order_by(Company.slug)).scalars().all()
            )
        else:
            companies = (
                s.execute(
                    select(Company)
                    .where(Company.slug.in_(allowed))
                    .order_by(Company.slug)
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
            }
            for company in companies
        ]


@router.get("/companies/{slug}")
def get_company(slug: str, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _enforce_company_access(s, principal, slug, write=False)
        return {
            "id": company.id,
            "slug": company.slug,
            "name": company.name,
            "domains": [d.domain for d in company.domains],
            "owner_email": company.owner_email,
            "visibility": company.visibility,
        }


@router.patch("/companies/{slug}")
def update_company(
    slug: str, payload: CompanyUpdate, principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, write=True)
    logger.info("update_company role=%s email=%s slug=%s", principal.role, principal.email, slug)
    return company_service.update_company(slug, payload.name)


@router.put("/companies/{slug}/domains")
def replace_domains(
    slug: str, payload: DomainReplace, principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, write=True)
    logger.info("replace_domains role=%s email=%s slug=%s", principal.role, principal.email, slug)
    return company_service.replace_domains(slug, payload.domains)


@router.delete("/companies/{slug}", status_code=204)
def delete_company(slug: str, principal: Principal = Depends(get_principal)) -> None:
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, write=True)
    logger.info("delete_company role=%s email=%s slug=%s", principal.role, principal.email, slug)
    company_service.delete_company(slug)


@router.post("/companies/{slug}/scans", status_code=201)
def trigger_scan(
    slug: str,
    background_tasks: BackgroundTasks,
    payload: ScanRequest | None = None,
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    if principal.role == "public":
        raise forbidden_response(principal.role, "Scan creation forbidden", slug)
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, scan=True)
    deep_scan = bool(payload.deep_scan) if payload else False
    logger.info("trigger_scan role=%s email=%s slug=%s", principal.role, principal.email, slug)
    return scan_service.trigger_scan(
        slug, background_tasks, deep_scan=deep_scan, principal=principal
    )


@router.get("/companies/{slug}/scans")
def list_scans(slug: str, principal: Principal = Depends(get_principal)) -> list[dict[str, Any]]:
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, write=False)
    return scan_service.list_scans(slug)


@router.get("/companies/{slug}/scans/latest")
def get_latest_scan(slug: str, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, write=False)
    return scan_service.get_latest_scan(slug)


@router.get("/companies/{slug}/scans/{scan_id}")
def get_company_scan(
    slug: str, scan_id: int, principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, write=False)
    return scan_service.get_company_scan(slug, scan_id)


@router.get("/companies/{slug}/scans/by-number/{company_scan_number}")
def get_company_scan_by_number(
    slug: str,
    company_scan_number: int,
    principal: Principal = Depends(get_principal),
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, write=False)
    return scan_service.get_company_scan_by_number(slug, company_scan_number)


@router.get("/companies/{slug}/scans/{scan_id}/artifacts")
def get_company_scan_artifacts(
    slug: str, scan_id: int, principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, write=False)
    return scan_service.get_company_scan_artifacts(slug, scan_id)


@router.delete("/companies/{slug}/scans/{scan_id}", status_code=204)
def delete_company_scan(
    slug: str, scan_id: int, principal: Principal = Depends(get_principal)
) -> None:
    if principal.role == "public":
        raise forbidden_response(principal.role, "Scan deletion forbidden", slug)
    with SessionLocal() as s:
        _enforce_company_access(s, principal, slug, scan=True)
    logger.info("delete_scan role=%s email=%s slug=%s scan_id=%s", principal.role, principal.email, slug, scan_id)
    scan_service.delete_company_scan(slug, scan_id)


app.include_router(router, prefix="/v1")
