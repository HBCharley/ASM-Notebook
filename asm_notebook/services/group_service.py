from __future__ import annotations

from typing import Iterable
import uuid

from fastapi import HTTPException
from sqlalchemy import select

from ..db import SessionLocal
from ..models import Company, CompanyGroup, Group, User

UNAUTH_GROUP = "Unauthenticated"
DEFAULT_GROUP = "Default"


def normalize_group_name(name: str) -> str:
    return name.strip()


def get_or_create_group(session: SessionLocal, name: str) -> Group:
    normalized = normalize_group_name(name)
    if not normalized:
        raise HTTPException(status_code=400, detail="Group name is required")
    group = session.execute(
        select(Group).where(Group.name == normalized)
    ).scalar_one_or_none()
    if group:
        return group
    group = Group(name=normalized)
    session.add(group)
    session.flush()
    return group


def resolve_group_id(name: str):
    with SessionLocal() as session:
        group = session.execute(
            select(Group).where(Group.name == normalize_group_name(name))
        ).scalar_one_or_none()
        if not group:
            group = get_or_create_group(session, name)
            session.commit()
        return group.id


def list_groups() -> list[str]:
    with SessionLocal() as session:
        rows = session.execute(select(Group.name).order_by(Group.name)).scalars().all()
        return list(rows)


def create_group(name: str) -> dict[str, str]:
    with SessionLocal() as session:
        group = get_or_create_group(session, name)
        session.commit()
        return {"name": group.name}


def delete_group(name: str) -> dict[str, str]:
    normalized = normalize_group_name(name)
    with SessionLocal() as session:
        group = session.execute(
            select(Group).where(Group.name == normalized)
        ).scalar_one_or_none()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        session.delete(group)
        session.commit()
        return {"name": normalized, "deleted": True}


def set_company_groups(
    company: Company, group_names: Iterable[str], session: SessionLocal | None = None
) -> list[str]:
    names = [normalize_group_name(n) for n in group_names if normalize_group_name(n)]
    if not names:
        raise HTTPException(status_code=400, detail="At least one group is required")
    owns_session = session is None
    session = session or SessionLocal()
    try:
        company = session.get(Company, company.id)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        groups = [get_or_create_group(session, name) for name in names]
        existing = {
            (cg.company_id, cg.group_id): cg for cg in company.company_groups
        }
        desired = {(company.id, g.id): g for g in groups}
        for key, cg in list(existing.items()):
            if key not in desired:
                session.delete(cg)
        for key, group in desired.items():
            if key not in existing:
                session.add(CompanyGroup(company_id=company.id, group_id=group.id))
        if owns_session:
            session.commit()
        return [g.name for g in groups]
    finally:
        if owns_session:
            session.close()


def set_company_groups_by_ids(
    company_id: str, group_ids: Iterable[str], session: SessionLocal | None = None
) -> list[str]:
    ids = [uuid.UUID(str(gid)) for gid in group_ids if gid]
    if not ids:
        raise HTTPException(status_code=400, detail="At least one group is required")
    owns_session = session is None
    session = session or SessionLocal()
    try:
        company = session.get(Company, uuid.UUID(str(company_id)))
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        groups = (
            session.execute(select(Group).where(Group.id.in_(ids))).scalars().all()
        )
        if len(groups) != len(set(ids)):
            raise HTTPException(status_code=404, detail="Group not found")
        existing = {
            (cg.company_id, cg.group_id): cg for cg in company.company_groups
        }
        desired = {(company.id, g.id): g for g in groups}
        for key, cg in list(existing.items()):
            if key not in desired:
                session.delete(cg)
        for key, group in desired.items():
            if key not in existing:
                session.add(CompanyGroup(company_id=company.id, group_id=group.id))
        if owns_session:
            session.commit()
        return [g.name for g in groups]
    finally:
        if owns_session:
            session.close()


def get_company_groups(company: Company) -> list[str]:
    return [g.name for g in company.groups]


def set_user_group(user_id: str, group_name: str) -> dict[str, str]:
    with SessionLocal() as session:
        group = get_or_create_group(session, group_name)
        user = session.get(User, uuid.UUID(str(user_id)))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.is_admin:
            user.is_admin = False
        user.group_id = group.id
        session.commit()
        return {"user_id": str(user.id), "group": group.name}


def list_user_groups() -> list[dict[str, str]]:
    with SessionLocal() as session:
        rows = (
            session.execute(
                select(User.id, User.email, Group.name)
                .join(Group, Group.id == User.group_id)
                .order_by(User.email.asc())
            )
            .all()
        )
        return [
            {"user_id": str(user_id), "email": email, "group": group}
            for user_id, email, group in rows
        ]


def resolve_user_group(user: User | None):
    if not user:
        return resolve_group_id(UNAUTH_GROUP)
    if user.is_admin:
        return None
    if user.group_id:
        return user.group_id
    return resolve_group_id(DEFAULT_GROUP)


def ensure_default_groups() -> None:
    with SessionLocal() as session:
        for name in (UNAUTH_GROUP, DEFAULT_GROUP):
            get_or_create_group(session, name)
        session.commit()
