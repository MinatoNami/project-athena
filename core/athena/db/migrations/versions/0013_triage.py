from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("finding", sa.Column("triage_disposition", sa.String(16)))
    op.add_column("finding", sa.Column("triage_reason", sa.Text))
    op.add_column("finding", sa.Column("triage_confidence", sa.Float))
    op.add_column("finding", sa.Column("triaged_at", sa.DateTime(timezone=True)))
    op.create_index(
        "finding_triage_idx", "finding", ["triage_disposition"],
        postgresql_where=sa.text("triage_disposition IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("finding_triage_idx", table_name="finding")
    for column in ("triaged_at", "triage_confidence", "triage_reason", "triage_disposition"):
        op.drop_column("finding", column)
