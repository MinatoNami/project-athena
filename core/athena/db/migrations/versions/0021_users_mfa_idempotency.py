from __future__ import annotations

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE app_user ADD COLUMN IF NOT EXISTS mfa_last_counter bigint")


def downgrade() -> None:
    op.drop_column("app_user", "mfa_last_counter")
