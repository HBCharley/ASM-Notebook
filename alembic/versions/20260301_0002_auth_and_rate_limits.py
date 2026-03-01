"""Add company ownership/visibility and scan rate limits.

Revision ID: 20260301_0002
Revises: 20260224_0001
Create Date: 2026-03-01
"""

from __future__ import annotations

import os
from datetime import datetime

import sqlalchemy as sa
from alembic import op

revision = "20260301_0002"
down_revision = "20260224_0001"
branch_labels = None
depends_on = None


def _public_slugs() -> list[str]:
    raw = os.getenv("PUBLIC_COMPANY_SLUGS", "company-a,company-b")
    return [s.strip().lower() for s in raw.split(",") if s.strip()]


def upgrade() -> None:
    op.add_column("companies", sa.Column("owner_email", sa.String(length=255), nullable=True))
    op.add_column(
        "companies",
        sa.Column(
            "visibility",
            sa.String(length=32),
            nullable=False,
            server_default="private",
        ),
    )

    op.create_table(
        "scan_rate_limits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_allowed_at", sa.DateTime(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("scope", "key", "window_start", name="uq_scan_rate_limit"),
    )
    op.create_index("ix_scan_rate_limits_key", "scan_rate_limits", ["key"])
    op.create_index("ix_scan_rate_limits_window_start", "scan_rate_limits", ["window_start"])

    bind = op.get_bind()
    public_slugs = _public_slugs()
    if public_slugs:
        bind.execute(
            sa.text(
                "UPDATE companies SET visibility = 'public_demo', owner_email = NULL "
                "WHERE lower(slug) = ANY(:slugs)"
            ),
            {"slugs": public_slugs},
        )
    bind.execute(
        sa.text(
            "UPDATE companies SET visibility = 'private' "
            "WHERE visibility IS NULL OR visibility = ''"
        )
    )


def downgrade() -> None:
    op.drop_index("ix_scan_rate_limits_window_start", table_name="scan_rate_limits")
    op.drop_index("ix_scan_rate_limits_key", table_name="scan_rate_limits")
    op.drop_table("scan_rate_limits")
    op.drop_column("companies", "visibility")
    op.drop_column("companies", "owner_email")
