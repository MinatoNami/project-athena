"""Record a triage disposition separately from an investigated verdict.

Triage is a single cheap model call with no tools. It decides what deserves a full
investigation; it never decides whether a vulnerability applies. Conflating the two
would let a glance with no evidence behind it close a finding, which is precisely
what this system exists not to do.

Revision ID: 0013
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # investigate | deprioritise. Deliberately not a finding state: a deprioritised
    # finding is still `discovered`, still listed, and still says it has not been
    # investigated.
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
