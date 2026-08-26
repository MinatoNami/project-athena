"""Baselines: separating the situation you inherited from the one you are creating.

Connecting to a real estate produces hundreds of findings at once. None of them are
new in any useful sense — they are the accumulated state of the world — and showing
them beside a finding that appeared yesterday is what produces the wall of red that
makes people stop looking.

A baseline marks the moment an asset's backlog was accepted as "what was already
here". It is stored on the asset rather than stamped on each finding for two
reasons: correlation upserts findings, so the moment survives re-evaluation without
anything having to re-mark them; and onboarding a new host six months from now
should not flood the queue with its history, which falls out of a per-asset moment
for free.

A baseline is a lens, not a suppression. Nothing is hidden and nothing needs a
reason — pre-existing findings stay listed, counted, and one filter away. Dismissing
something on its merits is what suppression is for, and it requires an argument.

Revision ID: 0015
"""
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
    # The default view filters on this for every asset on every request.
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
