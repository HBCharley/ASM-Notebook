from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, BackgroundTasks, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .init_db import init_db
import json

from sqlalchemy import select

from .services import company_service, scan_service, cve_service
from .db import SessionLocal
from .models import Company, ScanArtifact, ScanRun

app = FastAPI(
    title="ASM Notebook API",
    docs_url="/v1/docs",
    redoc_url="/v1/redoc",
    openapi_url="/v1/openapi.json",
)
router = APIRouter()


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


@router.get("/debug/cve")
def cve_debug(keywords: str | None = None) -> dict[str, Any]:
    samples = [k.strip() for k in (keywords or "").split(",") if k.strip()]
    return cve_service.get_cve_status(samples or None)


@router.get("/debug/cve/evidence")
def cve_evidence(
    company_slug: str,
    scan_id: int | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    with SessionLocal() as s:
        company = (
            s.execute(select(Company).where(Company.slug == company_slug))
            .scalars()
            .first()
        )
        if not company:
            return {"error": "company_not_found"}
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


@router.post("/companies", status_code=201)
def create_company(payload: CompanyCreate) -> dict[str, Any]:
    return company_service.create_company(payload.slug, payload.name, payload.domains)


@router.get("/companies")
def list_companies() -> list[dict[str, Any]]:
    return company_service.list_companies()


@router.get("/companies/{slug}")
def get_company(slug: str) -> dict[str, Any]:
    return company_service.get_company(slug)


@router.patch("/companies/{slug}")
def update_company(slug: str, payload: CompanyUpdate) -> dict[str, Any]:
    return company_service.update_company(slug, payload.name)


@router.put("/companies/{slug}/domains")
def replace_domains(slug: str, payload: DomainReplace) -> dict[str, Any]:
    return company_service.replace_domains(slug, payload.domains)


@router.delete("/companies/{slug}", status_code=204)
def delete_company(slug: str) -> None:
    company_service.delete_company(slug)


@router.post("/companies/{slug}/scans", status_code=201)
def trigger_scan(
    slug: str, background_tasks: BackgroundTasks, payload: ScanRequest | None = None
) -> dict[str, Any]:
    deep_scan = bool(payload.deep_scan) if payload else False
    return scan_service.trigger_scan(slug, background_tasks, deep_scan=deep_scan)


@router.get("/companies/{slug}/scans")
def list_scans(slug: str) -> list[dict[str, Any]]:
    return scan_service.list_scans(slug)


@router.get("/companies/{slug}/scans/latest")
def get_latest_scan(slug: str) -> dict[str, Any]:
    return scan_service.get_latest_scan(slug)


@router.get("/companies/{slug}/scans/{scan_id}")
def get_company_scan(slug: str, scan_id: int) -> dict[str, Any]:
    return scan_service.get_company_scan(slug, scan_id)


@router.get("/companies/{slug}/scans/by-number/{company_scan_number}")
def get_company_scan_by_number(slug: str, company_scan_number: int) -> dict[str, Any]:
    return scan_service.get_company_scan_by_number(slug, company_scan_number)


@router.get("/companies/{slug}/scans/{scan_id}/artifacts")
def get_company_scan_artifacts(slug: str, scan_id: int) -> dict[str, Any]:
    return scan_service.get_company_scan_artifacts(slug, scan_id)


@router.delete("/companies/{slug}/scans/{scan_id}", status_code=204)
def delete_company_scan(slug: str, scan_id: int) -> None:
    scan_service.delete_company_scan(slug, scan_id)


app.include_router(router, prefix="/v1")
