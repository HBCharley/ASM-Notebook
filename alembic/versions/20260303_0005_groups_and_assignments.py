"""Add groups and group assignments.

Revision ID: 20260303_0005
Revises: 20260302_0004
Create Date: 2026-03-03
"""

from __future__ import annotations

import os
import sqlalchemy as sa
from alembic import op

revision = "20260303_0005"
down_revision = "20260302_0004"
branch_labels = None
depends_on = None


UNAUTH_GROUP = "Unauthenticated"
DEFAULT_GROUP = "default"


def _public_slugs() -> list[str]:
    raw = os.getenv("PUBLIC_COMPANY_SLUGS", "company-a,company-b")
    return [s.strip().lower() for s in raw.split(",") if s.strip()]


def upgrade() -> None:
    op.create_table(
        "groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("name", name="uq_groups_name"),
    )
    op.create_index(op.f("ix_groups_name"), "groups", ["name"], unique=True)

    op.create_table(
        "company_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("company_id", sa.Integer(), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"]),
        sa.UniqueConstraint("company_id", "group_id", name="uq_company_group"),
    )
    op.create_index(op.f("ix_company_groups_company_id"), "company_groups", ["company_id"])
    op.create_index(op.f("ix_company_groups_group_id"), "company_groups", ["group_id"])

    op.create_table(
        "user_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"]),
        sa.UniqueConstraint("email", name="uq_user_group_email"),
    )
    op.create_index(op.f("ix_user_groups_email"), "user_groups", ["email"], unique=True)
    op.create_index(op.f("ix_user_groups_group_id"), "user_groups", ["group_id"])

    bind = op.get_bind()
    bind.execute(
        sa.text("INSERT INTO groups (name) VALUES (:name) ON CONFLICT DO NOTHING"),
        {"name": UNAUTH_GROUP},
    )
    bind.execute(
        sa.text("INSERT INTO groups (name) VALUES (:name) ON CONFLICT DO NOTHING"),
        {"name": DEFAULT_GROUP},
    )

    unauth_id = bind.execute(
        sa.text("SELECT id FROM groups WHERE name = :name"),
        {"name": UNAUTH_GROUP},
    ).scalar_one()
    default_id = bind.execute(
        sa.text("SELECT id FROM groups WHERE name = :name"),
        {"name": DEFAULT_GROUP},
    ).scalar_one()

    public_slugs = _public_slugs()
    if public_slugs:
        bind.execute(
            sa.text(
                "INSERT INTO company_groups (company_id, group_id) "
                "SELECT id, :group_id FROM companies "
                "WHERE lower(slug) = ANY(:slugs) "
                "ON CONFLICT DO NOTHING"
            ),
            {"group_id": unauth_id, "slugs": public_slugs},
        )

    bind.execute(
        sa.text(
            "INSERT INTO company_groups (company_id, group_id) "
            "SELECT id, :group_id FROM companies "
            "WHERE id NOT IN (SELECT company_id FROM company_groups) "
            "ON CONFLICT DO NOTHING"
        ),
        {"group_id": default_id},
    )

    bind.execute(
        sa.text(
            "INSERT INTO user_groups (email, group_id) "
            "SELECT email, :group_id FROM auth_allowlist "
            "WHERE role = 'user' "
            "ON CONFLICT DO NOTHING"
        ),
        {"group_id": default_id},
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_user_groups_group_id"), table_name="user_groups")
    op.drop_index(op.f("ix_user_groups_email"), table_name="user_groups")
    op.drop_table("user_groups")
    op.drop_index(op.f("ix_company_groups_group_id"), table_name="company_groups")
    op.drop_index(op.f("ix_company_groups_company_id"), table_name="company_groups")
    op.drop_table("company_groups")
    op.drop_index(op.f("ix_groups_name"), table_name="groups")
    op.drop_table("groups")
