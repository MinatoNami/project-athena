"""Node enrolment, task dispatch, and replay protection.

Revision ID: 0005
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", pg.UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="SET NULL")),
        sa.Column("display_name", sa.Text, nullable=False),
        # The node generates its keypair locally and sends only the public half, so
        # the private key never exists anywhere but the protected host.
        sa.Column("public_key", sa.LargeBinary, nullable=False, unique=True),
        sa.Column("agent_version", sa.Text),
        sa.Column("platform", sa.Text),
        sa.Column("arch", sa.Text),
        sa.Column("capabilities", pg.JSONB, nullable=False, server_default='[]'),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("node_last_seen_idx", "node", ["last_seen_at"])

    op.create_table(
        "node_enrolment_token",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
        sa.Column("tier", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("created_by", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("consumed_by_node", pg.UUID(as_uuid=True)),
    )

    op.create_table(
        "node_task",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("node_id", pg.UUID(as_uuid=True), sa.ForeignKey("node.id", ondelete="CASCADE"), nullable=False),
        sa.Column("capability", sa.String(64), nullable=False),
        sa.Column("args", pg.JSONB, nullable=False, server_default="{}"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("nonce", sa.Text, nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("succeeded", sa.Boolean),
        sa.Column("result", pg.JSONB),
        sa.Column("error", sa.Text),
        sa.Column("scan_run_id", pg.UUID(as_uuid=True)),
    )
    op.create_index(
        "node_task_pending_idx", "node_task", ["node_id", "issued_at"],
        postgresql_where=sa.text("completed_at IS NULL"),
    )

    # Replay protection: a signed request may be accepted exactly once. Rows older
    # than the clock-skew window are swept by the scheduler.
    op.create_table(
        "node_nonce",
        sa.Column("node_id", pg.UUID(as_uuid=True), sa.ForeignKey("node.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("nonce", sa.Text, primary_key=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("node_nonce_seen_idx", "node_nonce", ["seen_at"])


def downgrade() -> None:
    for t in ("node_nonce", "node_task", "node_enrolment_token", "node"):
        op.drop_table(t)
