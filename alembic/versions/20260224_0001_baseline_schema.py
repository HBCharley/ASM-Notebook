"""baseline schema

Revision ID: 20260224_0001
Revises:
Create Date: 2026-02-24 12:30:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260224_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "companies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index(op.f("ix_companies_slug"), "companies", ["slug"], unique=True)

    op.create_table(
        "company_domains",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("company_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("company_id", "domain", name="uq_company_domain"),
    )
    op.create_index(op.f("ix_company_domains_company_id"), "company_domains", ["company_id"], unique=False)
    op.create_index(op.f("ix_company_domains_domain"), "company_domains", ["domain"], unique=False)

    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("company_id", sa.Integer(), nullable=False),
        sa.Column("company_scan_number", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("notes", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("company_id", "company_scan_number", name="uq_company_scan_number"),
    )
    op.create_index(op.f("ix_scan_runs_company_id"), "scan_runs", ["company_id"], unique=False)

    op.create_table(
        "scan_artifacts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("artifact_type", sa.String(length=64), nullable=False),
        sa.Column("json_text", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "artifact_type", name="uq_scan_artifact_type"),
    )
    op.create_index(op.f("ix_scan_artifacts_scan_id"), "scan_artifacts", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_artifacts_scan_id"), table_name="scan_artifacts")
    op.drop_table("scan_artifacts")
    op.drop_index(op.f("ix_scan_runs_company_id"), table_name="scan_runs")
    op.drop_table("scan_runs")
    op.drop_index(op.f("ix_company_domains_domain"), table_name="company_domains")
    op.drop_index(op.f("ix_company_domains_company_id"), table_name="company_domains")
    op.drop_table("company_domains")
    op.drop_index(op.f("ix_companies_slug"), table_name="companies")
    op.drop_table("companies")
