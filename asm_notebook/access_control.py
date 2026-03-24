from __future__ import annotations

from sqlalchemy import select

from .db import SessionLocal
from .models import Company, CompanyGroup
from .security import CurrentUser
from .services import group_service


def get_effective_group(current_user: CurrentUser | None):
    if current_user is None:
        return group_service.resolve_group_id(group_service.UNAUTH_GROUP)
    if current_user.is_admin:
        return None
    return current_user.group_id


def query_companies_with_access(session: SessionLocal, current_user: CurrentUser | None):
    if current_user is not None and current_user.is_admin:
        return select(Company)
    group_id = get_effective_group(current_user)
    return (
        select(Company)
        .join(CompanyGroup, CompanyGroup.company_id == Company.id)
        .where(CompanyGroup.group_id == group_id)
    )
