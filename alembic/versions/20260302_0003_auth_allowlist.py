"""add auth allowlist table

Revision ID: 20260302_0003
Revises: 20260301_0002
Create Date: 2026-03-02
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260302_0003"
down_revision = "20260301_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_allowlist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("email", name="uq_auth_allowlist_email"),
    )
    op.create_index(
        "ix_auth_allowlist_email", "auth_allowlist", ["email"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_auth_allowlist_email", table_name="auth_allowlist")
    op.drop_table("auth_allowlist")
