"""UUID users/groups/companies and group-based access.

Revision ID: 20260303_0006
Revises: 20260303_0005
Create Date: 2026-03-03
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260303_0006"
down_revision = "20260303_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.execute("UPDATE groups SET name = 'Default' WHERE name = 'default'")

    op.add_column(
        "groups",
        sa.Column(
            "id_uuid",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
    )
    op.add_column(
        "companies",
        sa.Column(
            "id_uuid",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
    )
    op.execute("UPDATE groups SET id_uuid = gen_random_uuid() WHERE id_uuid IS NULL")
    op.execute("UPDATE companies SET id_uuid = gen_random_uuid() WHERE id_uuid IS NULL")

    op.add_column(
        "companies",
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )

    op.add_column(
        "company_groups",
        sa.Column("company_id_uuid", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "company_groups",
        sa.Column("group_id_uuid", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "company_domains",
        sa.Column("company_id_uuid", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "scan_runs",
        sa.Column("company_id_uuid", postgresql.UUID(as_uuid=True), nullable=True),
    )

    op.execute(
        "UPDATE company_groups cg SET company_id_uuid = c.id_uuid "
        "FROM companies c WHERE cg.company_id = c.id"
    )
    op.execute(
        "UPDATE company_groups cg SET group_id_uuid = g.id_uuid "
        "FROM groups g WHERE cg.group_id = g.id"
    )
    op.execute(
        "UPDATE company_domains cd SET company_id_uuid = c.id_uuid "
        "FROM companies c WHERE cd.company_id = c.id"
    )
    op.execute(
        "UPDATE scan_runs sr SET company_id_uuid = c.id_uuid "
        "FROM companies c WHERE sr.company_id = c.id"
    )

    op.drop_constraint("company_groups_company_id_fkey", "company_groups", type_="foreignkey")
    op.drop_constraint("company_groups_group_id_fkey", "company_groups", type_="foreignkey")
    op.drop_constraint("uq_company_group", "company_groups", type_="unique")
    op.drop_constraint("company_groups_pkey", "company_groups", type_="primary")
    op.drop_index("ix_company_groups_company_id", table_name="company_groups")
    op.drop_index("ix_company_groups_group_id", table_name="company_groups")
    op.drop_column("company_groups", "company_id")
    op.drop_column("company_groups", "group_id")
    op.drop_column("company_groups", "id")
    op.alter_column(
        "company_groups",
        "company_id_uuid",
        new_column_name="company_id",
        nullable=False,
    )
    op.alter_column(
        "company_groups",
        "group_id_uuid",
        new_column_name="group_id",
        nullable=False,
    )

    op.drop_constraint("company_domains_company_id_fkey", "company_domains", type_="foreignkey")
    op.drop_constraint("uq_company_domain", "company_domains", type_="unique")
    op.drop_index("ix_company_domains_company_id", table_name="company_domains")
    op.drop_column("company_domains", "company_id")
    op.alter_column(
        "company_domains",
        "company_id_uuid",
        new_column_name="company_id",
        nullable=False,
    )

    op.drop_constraint("scan_runs_company_id_fkey", "scan_runs", type_="foreignkey")
    op.drop_constraint("uq_company_scan_number", "scan_runs", type_="unique")
    op.drop_index("ix_scan_runs_company_id", table_name="scan_runs")
    op.drop_column("scan_runs", "company_id")
    op.alter_column(
        "scan_runs",
        "company_id_uuid",
        new_column_name="company_id",
        nullable=False,
    )

    op.drop_constraint("user_groups_group_id_fkey", "user_groups", type_="foreignkey")

    op.execute(
        "INSERT INTO groups (id_uuid, name, created_at) "
        "SELECT gen_random_uuid(), 'Unauthenticated', CURRENT_TIMESTAMP "
        "WHERE NOT EXISTS (SELECT 1 FROM groups WHERE name = 'Unauthenticated')"
    )
    op.execute(
        "INSERT INTO groups (id_uuid, name, created_at) "
        "SELECT gen_random_uuid(), 'Default', CURRENT_TIMESTAMP "
        "WHERE NOT EXISTS (SELECT 1 FROM groups WHERE name = 'Default')"
    )

    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column(
            "is_admin",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("group_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_group_id", "users", ["group_id"])

    op.execute(
        "INSERT INTO users (id, email, is_admin, group_id, created_at) "
        "SELECT gen_random_uuid(), ug.email, false, g.id_uuid, CURRENT_TIMESTAMP "
        "FROM user_groups ug JOIN groups g ON g.id = ug.group_id "
        "ON CONFLICT (email) DO NOTHING"
    )
    op.execute(
        "INSERT INTO users (id, email, is_admin, group_id, created_at) "
        "SELECT gen_random_uuid(), a.email, (a.role = 'admin'), "
        "CASE WHEN a.role = 'admin' THEN NULL ELSE g.id_uuid END, CURRENT_TIMESTAMP "
        "FROM auth_allowlist a "
        "LEFT JOIN groups g ON g.name = 'Default' "
        "ON CONFLICT (email) DO NOTHING"
    )
    op.execute(
        "UPDATE users SET is_admin = true, group_id = NULL "
        "WHERE email IN (SELECT email FROM auth_allowlist WHERE role = 'admin')"
    )
    op.execute(
        "UPDATE users SET group_id = g.id_uuid "
        "FROM groups g "
        "WHERE users.group_id IS NULL AND users.is_admin = false AND g.name = 'Default'"
    )

    op.execute(
        "UPDATE companies c SET created_by_user_id = u.id "
        "FROM users u WHERE c.owner_email = u.email"
    )

    op.drop_constraint("companies_pkey", "companies", type_="primary")
    op.drop_column("companies", "id")
    op.alter_column("companies", "id_uuid", new_column_name="id", nullable=False)
    op.create_primary_key("companies_pkey", "companies", ["id"])

    op.drop_constraint("groups_pkey", "groups", type_="primary")
    op.drop_column("groups", "id")
    op.alter_column("groups", "id_uuid", new_column_name="id", nullable=False)
    op.create_primary_key("groups_pkey", "groups", ["id"])

    op.create_foreign_key(
        "fk_company_groups_company_id",
        "company_groups",
        "companies",
        ["company_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_company_groups_group_id",
        "company_groups",
        "groups",
        ["group_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_primary_key(
        "company_groups_pkey", "company_groups", ["company_id", "group_id"]
    )
    op.create_unique_constraint(
        "uq_company_group", "company_groups", ["company_id", "group_id"]
    )
    op.create_index(
        "ix_company_groups_company_id", "company_groups", ["company_id"]
    )
    op.create_index("ix_company_groups_group_id", "company_groups", ["group_id"])

    op.create_foreign_key(
        "fk_company_domains_company_id",
        "company_domains",
        "companies",
        ["company_id"],
        ["id"],
    )
    op.create_unique_constraint(
        "uq_company_domain", "company_domains", ["company_id", "domain"]
    )
    op.create_index(
        "ix_company_domains_company_id", "company_domains", ["company_id"]
    )

    op.create_foreign_key(
        "fk_scan_runs_company_id",
        "scan_runs",
        "companies",
        ["company_id"],
        ["id"],
    )
    op.create_unique_constraint(
        "uq_company_scan_number",
        "scan_runs",
        ["company_id", "company_scan_number"],
    )
    op.create_index("ix_scan_runs_company_id", "scan_runs", ["company_id"])

    op.create_foreign_key(
        "fk_users_group_id",
        "users",
        "groups",
        ["group_id"],
        ["id"],
    )

    op.drop_index("ix_user_groups_group_id", table_name="user_groups")
    op.drop_index("ix_user_groups_email", table_name="user_groups")
    op.drop_table("user_groups")

    op.create_foreign_key(
        "fk_companies_created_by_user_id",
        "companies",
        "users",
        ["created_by_user_id"],
        ["id"],
    )


def downgrade() -> None:
    raise RuntimeError("Downgrade not supported for UUID migration.")
