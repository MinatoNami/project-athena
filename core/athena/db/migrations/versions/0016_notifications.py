from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(48), nullable=False),
        sa.Column("group_key", sa.Text, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("urgency", sa.String(16), nullable=False, server_default="routine"),
        sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("subjects", JSONB, nullable=False, server_default="[]"),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("channel", sa.String(32)),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "state IN ('pending','sent','digested','read')", name="notification_state_check"
        ),
        sa.CheckConstraint(
            "urgency IN ('urgent','routine')", name="notification_urgency_check"
        ),
    )

    op.create_index(
        "notification_pending_group_idx",
        "notification",
        ["group_key"],
        unique=True,
        postgresql_where=sa.text("state = 'pending'"),
    )
    op.create_index("notification_state_idx", "notification", ["state", "created_at"])
    op.create_index(
        "notification_unread_idx",
        "notification",
        ["created_at"],
        postgresql_where=sa.text("read_at IS NULL AND state IN ('sent','digested')"),
    )


def downgrade() -> None:
    op.drop_index("notification_unread_idx", table_name="notification")
    op.drop_index("notification_state_idx", table_name="notification")
    op.drop_index("notification_pending_group_idx", table_name="notification")
    op.drop_table("notification")
