"""Record how a fix is delivered, and keep match provenance on the finding.

Two problems:

Ubuntu publishes fixes for older or extended-support packages only through Ubuntu
Pro (versions carrying ~esm or fips). Presenting those as an ordinary upgrade tells
an operator to install something they may have no entitlement to.

affected_range rows are replaced wholesale whenever an advisory is revised, so
finding.matched_range_id dangles as soon as that happens and the evidence chain
loses which range drove the match. The identifying facts are denormalised onto the
finding, which is the durable place for them.

Revision ID: 0008
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("affected_range", sa.Column("channel", sa.String(16), nullable=False,
                                              server_default="standard"))
    op.create_index("affected_range_channel_idx", "affected_range", ["channel"])

    op.add_column("finding", sa.Column("fix_channel", sa.String(16)))
    op.add_column("finding", sa.Column("matched_source", sa.String(32)))
    op.add_column("finding", sa.Column("matched_release", sa.String(32)))


def downgrade() -> None:
    op.drop_column("finding", "matched_release")
    op.drop_column("finding", "matched_source")
    op.drop_column("finding", "fix_channel")
    op.drop_index("affected_range_channel_idx", table_name="affected_range")
    op.drop_column("affected_range", "channel")
