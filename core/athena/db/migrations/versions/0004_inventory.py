"""Inventory: assets, components, scan provenance, merge candidates.

Revision ID: 0004
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("identity_key", sa.Text, nullable=False),
        sa.Column("display_name", sa.Text, nullable=False),
        sa.Column("tier", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("exposure", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("criticality", sa.SmallInteger),
        sa.Column("owner", sa.Text),
        sa.Column("attributes", pg.JSONB, nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_inventoried_at", sa.DateTime(timezone=True)),
        sa.Column("tombstoned_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("kind", "identity_key", name="asset_identity_uniq"),
    )
    op.create_index("asset_kind_idx", "asset", ["kind"])
    # Coverage queries ask "what is stale or never inventoried?" on every dashboard load.
    op.execute(
        "CREATE INDEX asset_freshness_idx ON asset (last_inventoried_at NULLS FIRST) "
        "WHERE tombstoned_at IS NULL"
    )

    op.create_table(
        "asset_edge",
        sa.Column("src_id", pg.UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("dst_id", pg.UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("relation", sa.String(32), primary_key=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("confidence", sa.Float, nullable=False, server_default="1.0"),
    )
    op.create_index("asset_edge_dst_idx", "asset_edge", ["dst_id"])

    op.create_table(
        "component",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("purl", sa.Text),
        sa.Column("cpe", sa.Text),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("version", sa.Text, nullable=False),
        sa.UniqueConstraint("ecosystem", "name", "version", name="component_identity_uniq"),
    )
    # Reverse correlation (M2) looks components up by ecosystem+name when an advisory
    # arrives, rather than rescanning assets.
    op.create_index("component_lookup_idx", "component", ["ecosystem", "name"])
    op.create_index("component_purl_idx", "component", ["purl"])

    op.create_table(
        "asset_component",
        sa.Column("asset_id", pg.UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("component_id", pg.UUID(as_uuid=True), sa.ForeignKey("component.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("scope", sa.String(16), primary_key=True),
        sa.Column("install_path", sa.Text),
        sa.Column("is_running", sa.Boolean),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("scan_run_id", pg.UUID(as_uuid=True), nullable=False),
    )
    op.create_index("asset_component_by_component_idx", "asset_component", ["component_id"])

    op.create_table(
        "scan_run",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", pg.UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE")),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("tool", sa.Text, nullable=False),
        sa.Column("tool_version", sa.Text),
        sa.Column("status", sa.String(16), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text),
        sa.Column("stats", pg.JSONB, nullable=False, server_default="{}"),
    )
    op.create_index("scan_run_asset_idx", "scan_run", ["asset_id", "started_at"])

    # A scan is running, or it succeeded, or it partly failed, or it failed. There is
    # no state that means "we did not look but assume it is fine".
    op.create_check_constraint(
        "scan_run_status_known",
        "scan_run",
        "status IN ('running','succeeded','partial','failed','timeout')",
    )

    op.create_table(
        "merge_candidate",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", pg.UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE"), nullable=False),
        sa.Column("other_asset_id", pg.UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE"), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("resolution", sa.String(16)),
        sa.UniqueConstraint("asset_id", "other_asset_id", name="merge_candidate_pair_uniq"),
    )


def downgrade() -> None:
    for t in ("merge_candidate", "scan_run", "asset_component", "component", "asset_edge", "asset"):
        op.drop_table(t)
