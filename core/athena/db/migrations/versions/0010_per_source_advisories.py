from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("affected_range", sa.Column("source_record", sa.Text))
    op.create_index(
        "affected_range_source_idx", "affected_range", ["vulnerability_id", "source_record"]
    )

    op.create_table(
        "advisory_source",
        sa.Column("vulnerability_id", sa.Text, sa.ForeignKey("vulnerability.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("source_record", sa.Text, primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("modified_at", sa.DateTime(timezone=True)),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.execute("DELETE FROM affected_range")
    op.execute("UPDATE vulnerability SET content_hash = '', revision = 1, revised_at = NULL")


def downgrade() -> None:
    op.drop_table("advisory_source")
    op.drop_index("affected_range_source_idx", table_name="affected_range")
    op.drop_column("affected_range", "source_record")
