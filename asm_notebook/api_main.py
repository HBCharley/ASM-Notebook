from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, BackgroundTasks, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .init_db import init_db
from .services import company_service, scan_service

app = FastAPI(
    title="ASM Notebook API",
    docs_url="/v1/docs",
    redoc_url="/v1/redoc",
    openapi_url="/v1/openapi.json",
)
router = APIRouter()


def _cors_origins() -> list[str]:
    raw = os.getenv("ASM_CORS_ALLOW_ORIGINS", "").strip()
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
