"""Record every outbound model call, including the ones refused.

"What has left my network?" must be answerable from a table rather than inferred
from logs, on a tool that holds a map of every weakness in the estate.

Revision ID: 0011
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "egress_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("endpoint", sa.Text, nullable=False),
        sa.Column("model", sa.Text, nullable=False),
        sa.Column("local", sa.Boolean, nullable=False),
        sa.Column("data_classes", pg.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("blocked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("reason", sa.Text),
        # The payload itself is never stored — only a digest, so a call can be
        # correlated without the log becoming a copy of everything sent.
        sa.Column("payload_hash", sa.Text, nullable=False),
        sa.Column("bytes_out", sa.Integer, nullable=False, server_default="0"),
        sa.Column("prompt_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_index("egress_log_at_idx", "egress_log", ["at"])
    op.create_index("egress_log_blocked_idx", "egress_log", ["blocked"],
                    postgresql_where=sa.text("blocked"))


def downgrade() -> None:
    op.drop_table("egress_log")
