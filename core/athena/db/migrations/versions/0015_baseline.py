from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("asset", sa.Column("baseline_at", sa.DateTime(timezone=True)))
    op.add_column("asset", sa.Column("baseline_by", sa.Text))
    op.create_index(
        "asset_baseline_idx",
        "asset",
        ["baseline_at"],
        postgresql_where=sa.text("baseline_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("asset_baseline_idx", table_name="asset")
    op.drop_column("asset", "baseline_by")
    op.drop_column("asset", "baseline_at")
