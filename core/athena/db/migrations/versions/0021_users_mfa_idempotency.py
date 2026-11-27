from __future__ import annotations

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE app_user ADD COLUMN IF NOT EXISTS mfa_last_counter bigint")
    op.execute(
        "ALTER TABLE app_user ADD COLUMN IF NOT EXISTS password_change_required boolean"
        " NOT NULL DEFAULT false"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE app_user DROP COLUMN IF EXISTS password_change_required")
    op.execute("ALTER TABLE app_user DROP COLUMN IF EXISTS mfa_last_counter")
