from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS cvss_scoring_vector text")
    _backfill()
    op.execute("ALTER TYPE finding_state ADD VALUE IF NOT EXISTS 'unmatched'")


def _backfill() -> None:
    from athena.intel.cvss import base_score

    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, cvss_vector, cvss_score FROM vulnerability"
            " WHERE cvss_score IS NOT NULL AND cvss_scoring_vector IS NULL"
            "   AND cvss_vector LIKE 'CVSS:3%'"
        )
    ).all()
    update = sa.text("UPDATE vulnerability SET cvss_scoring_vector = :vector WHERE id = :id")
    batch = []
    for vuln_id, vector, score in rows:
        if base_score(vector) == score:
            batch.append({"id": vuln_id, "vector": vector})
        if len(batch) >= 2000:
            bind.execute(update, batch)
            batch.clear()
    if batch:
        bind.execute(update, batch)


def downgrade() -> None:
    op.execute("UPDATE finding SET state = 'discovered' WHERE state::text = 'unmatched'")
    op.drop_column("vulnerability", "cvss_scoring_vector")
