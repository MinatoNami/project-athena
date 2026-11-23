"""The vector a CVSS score was computed from.

A record often publishes v4.0 and v3.1 side by side. `cvss_vector` keeps the first,
while the score is computed from the v3.1 one — so the finding page compared the
score with the wrong vector and presented Athena's number as the advisory's own.
`cvss_scoring_vector` is written with the score, and only when Athena computed it.

Its own revision rather than an edit to 0018, which has already been released: a
database that ran 0018 would never see a column added there.

Revision ID: 0019
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS: a development database may have run an unreleased 0018 that
    # carried this column for a few hours.
    op.execute("ALTER TABLE vulnerability ADD COLUMN IF NOT EXISTS cvss_scoring_vector text")
    _backfill()


def _backfill() -> None:
    """Record the vector for every stored score that it computes to.

    That covers the scores 0018 computed and those ingested since. A score computed
    from a vector that was not stored (the v3.1 behind a stored v4.0) cannot be
    traced back here and stays unattributed until its advisory is next ingested —
    which the page reads as "published by the advisory", the cautious reading.
    """
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
    op.drop_column("vulnerability", "cvss_scoring_vector")
