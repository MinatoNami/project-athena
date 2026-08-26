"""Notifications, grouped by the thing that happened rather than by each row it touched.

One advisory affecting fourteen hosts is one thing to be told about. Sending
fourteen messages is how a useful alert becomes something people filter to a folder
they never open — and the first week of that decides whether the tool survives.

Three columns carry the design. `group_key` is what makes a second occurrence
coalesce into an existing pending notification instead of creating another.
`occurrence_count` is how many were folded in, so the message can say "across 14
assets" rather than pretending it was one. `state` distinguishes something that was
sent from something deliberately held for the digest, so a throttle never looks like
a delivery failure.

Revision ID: 0016
"""
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
        # What makes two occurrences the same notification. For a new finding it is
        # the vulnerability, never the finding — that is the whole point.
        sa.Column("group_key", sa.Text, nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        # urgent bypasses quiet hours and the throttle; routine does not.
        sa.Column("urgency", sa.String(16), nullable=False, server_default="routine"),
        sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
        # The assets, findings, or sources folded in. Rendered into the message.
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

    # At most one pending notification per group. This is the grouping guarantee
    # expressed where it cannot be forgotten: two concurrent emits for the same CVE
    # cannot both create a row.
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
