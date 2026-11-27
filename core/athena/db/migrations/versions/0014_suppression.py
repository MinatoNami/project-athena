from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "suppression",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("vulnerability_id", sa.Text,
                  sa.ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE")),
        sa.Column("component_id", UUID(as_uuid=True),
                  sa.ForeignKey("component.id", ondelete="CASCADE")),
        sa.Column("created_from_finding_id", UUID(as_uuid=True)),
        sa.Column("reason_code", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("premise", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_by", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by", sa.Text),
        sa.Column("invalidated_at", sa.DateTime(timezone=True)),
        sa.Column("invalidated_reason", sa.Text),
        sa.CheckConstraint(
            "reason_code IN ('not_applicable','compensating_control','accepted_risk',"
            "'false_positive','fix_scheduled')",
            name="suppression_reason_code_check",
        ),
        sa.CheckConstraint("length(btrim(reason)) >= 8", name="suppression_reason_length_check"),
        sa.CheckConstraint(
            "component_id IS NULL OR asset_id IS NOT NULL",
            name="suppression_component_needs_asset_check",
        ),
    )

    op.create_index(
        "suppression_match_idx", "suppression", ["vulnerability_id", "asset_id", "component_id"]
    )
    op.create_index(
        "suppression_active_idx",
        "suppression",
        ["vulnerability_id"],
        postgresql_where=sa.text("revoked_at IS NULL AND invalidated_at IS NULL"),
    )
    op.create_index(
        "suppression_unique_live_idx",
        "suppression",
        ["vulnerability_id", "asset_id", "component_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL AND invalidated_at IS NULL"),
        postgresql_nulls_not_distinct=True,
    )


def downgrade() -> None:
    op.drop_index("suppression_unique_live_idx", table_name="suppression")
    op.drop_index("suppression_active_idx", table_name="suppression")
    op.drop_index("suppression_match_idx", table_name="suppression")
    op.drop_table("suppression")
