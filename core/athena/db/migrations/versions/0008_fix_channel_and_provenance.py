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
