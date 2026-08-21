"""Share investigations between assets whose relevant state matches.

Fourteen identical hosts carrying the same package at the same version, with the same
exposure and tier, pose one question — not fourteen. Without this, investigating a
fleet costs a model call per host and takes proportionally as long.

Revision ID: 0012
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "investigation",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        # Hash of the facts that could change the verdict. Two findings sharing it
        # share the answer.
        sa.Column("fingerprint", sa.Text, nullable=False, unique=True),
        sa.Column("vulnerability_id", sa.Text, nullable=False),
        sa.Column("advisory_revision", sa.Integer, nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("verdict_confidence", sa.Float, nullable=False),
        sa.Column("signals", pg.JSONB, nullable=False, server_default="{}"),
        sa.Column("rationale", sa.Text),
        sa.Column("uncertainties", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("corrections", pg.JSONB, nullable=False, server_default="[]"),
        # Everything needed to replay the conclusion. A verdict nobody can
        # reconstruct is not evidence.
        sa.Column("model", sa.Text, nullable=False),
        sa.Column("prompt_hash", sa.Text, nullable=False),
        sa.Column("tool_calls", pg.JSONB, nullable=False, server_default="[]"),
        sa.Column("prompt_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer, nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("reused", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_index("investigation_vuln_idx", "investigation", ["vulnerability_id"])

    op.add_column("finding", sa.Column("investigation_id", pg.UUID(as_uuid=True)))


def downgrade() -> None:
    op.drop_column("finding", "investigation_id")
    op.drop_table("investigation")
