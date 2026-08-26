"""Record when each intelligence source was first fetched successfully.

Detection latency is the time between an advisory becoming known and Athena finding
the affected asset. Measuring it needs a start line: an advisory published two years
before this system existed did not take two years to detect, and counting it that way
would make the metric describe the backfill rather than the watch.

`last_success_at` cannot answer that — it is overwritten on every poll, so it always
says "now". This adds the moment that never moves.

Backfilled to the earliest thing that proves Athena was already running with
intelligence in hand: its first finding, or the last successful fetch, whichever is
earlier. Approximate for existing deployments, exact from here on.

Revision ID: 0017
"""
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
