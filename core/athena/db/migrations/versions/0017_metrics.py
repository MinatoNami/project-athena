from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("intel_source", sa.Column("first_success_at", sa.DateTime(timezone=True)))
    op.execute(
        """
        UPDATE intel_source
           SET first_success_at = LEAST(
                 last_success_at,
                 COALESCE((SELECT min(first_seen) FROM finding), last_success_at)
               )
         WHERE last_success_at IS NOT NULL
        """
    )


def downgrade() -> None:
    op.drop_column("intel_source", "first_success_at")
