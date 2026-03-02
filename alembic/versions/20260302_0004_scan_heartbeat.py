"""add scan heartbeat timestamp

Revision ID: 20260302_0004
Revises: 20260302_0003
Create Date: 2026-03-02
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260302_0004"
down_revision = "20260302_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("heartbeat_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_runs", "heartbeat_at")
