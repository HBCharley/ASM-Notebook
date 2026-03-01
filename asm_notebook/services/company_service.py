from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy import select

from ..db import SessionLocal
from ..models import Company, CompanyDomain


def normalize_domain(value: str) -> str:
    return value.strip().lower().strip(".")


def _company_by_slug(session: SessionLocal, slug: str) -> Company | None:
    return session.execute(
        select(Company).where(Company.slug == slug)
    ).scalar_one_or_none()


def create_company(
    slug: str,
    name: str,
    domains: list[str],
    owner_email: str | None = None,
    visibility: str = "private",
) -> dict[str, Any]:
    slug = slug.strip()
    name = name.strip()
    clean_domains = [normalize_domain(d) for d in domains if d and d.strip()]

    if not slug or not name or not clean_domains:
        raise HTTPException(status_code=400, detail="slug, name, domains are required")

    with SessionLocal() as session:
        existing = session.execute(
            select(Company).where(Company.slug == slug)
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=409, detail="Company slug already exists")

        company = Company(
            slug=slug, name=name, owner_email=owner_email, visibility=visibility
        )
        session.add(company)
        session.flush()
        for domain in clean_domains:
            session.add(CompanyDomain(company_id=company.id, domain=domain))
        session.commit()
        return {
            "id": company.id,
            "slug": company.slug,
            "name": company.name,
            "domains": clean_domains,
            "owner_email": company.owner_email,
            "visibility": company.visibility,
        }


def list_companies() -> list[dict[str, Any]]:
    with SessionLocal() as session:
        companies = (
            session.execute(select(Company).order_by(Company.slug)).scalars().all()
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


def get_company(slug: str) -> dict[str, Any]:
    with SessionLocal() as session:
        company = _company_by_slug(session, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        return {
            "id": company.id,
            "slug": company.slug,
            "name": company.name,
            "domains": [d.domain for d in company.domains],
            "owner_email": company.owner_email,
            "visibility": company.visibility,
        }


def update_company(slug: str, name: str) -> dict[str, Any]:
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name must not be empty")

    with SessionLocal() as session:
        company = _company_by_slug(session, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        company.name = name
        session.commit()
        return {
            "id": company.id,
            "slug": company.slug,
            "name": company.name,
            "domains": [d.domain for d in company.domains],
            "owner_email": company.owner_email,
            "visibility": company.visibility,
        }


def replace_domains(slug: str, domains: list[str]) -> dict[str, Any]:
    clean_domains = list(
        dict.fromkeys([normalize_domain(d) for d in domains if d and d.strip()])
    )
    if not clean_domains:
        raise HTTPException(status_code=400, detail="domains must not be empty")

    with SessionLocal() as session:
        company = _company_by_slug(session, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        for domain in list(company.domains):
            session.delete(domain)
        session.flush()
        for domain in clean_domains:
            session.add(CompanyDomain(company_id=company.id, domain=domain))
        session.commit()

    return {"slug": slug, "domains": clean_domains}


def delete_company(slug: str) -> None:
    with SessionLocal() as session:
        company = _company_by_slug(session, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        session.delete(company)
        session.commit()
