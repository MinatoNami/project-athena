"""Vulnerability intelligence, findings, and evidence.

Revision ID: 0006
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

FINDING_STATES = (
    "discovered", "investigating", "confirmed", "remediation_found", "patch_prepared",
    "awaiting_approval", "remediating", "verifying", "resolved",
    "false_positive", "mitigated", "accepted_risk", "deferred", "no_fix_available",
    "regressed",
)


def upgrade() -> None:
    op.create_table(
        "vulnerability",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("aliases", pg.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("summary", sa.Text),
        sa.Column("details", sa.Text),
        sa.Column("cwe", pg.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("cvss_vector", sa.Text),
        sa.Column("cvss_score", sa.Float),
        sa.Column("severity", sa.String(16)),
        sa.Column("epss_score", sa.Float),
        sa.Column("epss_percentile", sa.Float),
        sa.Column("epss_updated_at", sa.DateTime(timezone=True)),
        sa.Column("kev", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("kev_ransomware", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("kev_added_at", sa.DateTime(timezone=True)),
        sa.Column("exploit_public", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("modified_at", sa.DateTime(timezone=True)),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True)),
        sa.Column("references", pg.JSONB, nullable=False, server_default="[]"),
        # Bumped only when something that could change a verdict changes, so a
        # cosmetic edit upstream does not re-correlate the whole estate.
        sa.Column("revision", sa.Integer, nullable=False, server_default="1"),
        sa.Column("revised_at", sa.DateTime(timezone=True)),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("first_ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("vulnerability_kev_idx", "vulnerability", ["kev"], postgresql_where=sa.text("kev"))
    op.create_index("vulnerability_modified_idx", "vulnerability", ["modified_at"])
    op.execute("CREATE INDEX vulnerability_aliases_idx ON vulnerability USING gin (aliases)")

    op.create_table(
        "affected_range",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("vulnerability_id", sa.Text, sa.ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("package", sa.Text, nullable=False),
        sa.Column("introduced", sa.Text),
        sa.Column("fixed", sa.Text),
        sa.Column("last_affected", sa.Text),
        sa.Column("source", sa.String(32), nullable=False),
        # See athena/intel/authority.py. A distro tracker outranks an upstream
        # advisory for a distro package, because only it knows about backports.
        sa.Column("authority", sa.SmallInteger, nullable=False),
        sa.Column("distro", sa.String(32)),
        sa.Column("distro_release", sa.String(32)),
    )
    op.create_index("affected_range_lookup_idx", "affected_range", ["ecosystem", "package"])
    op.create_index("affected_range_vuln_idx", "affected_range", ["vulnerability_id"])

    op.create_table(
        "intel_source",
        sa.Column("name", sa.String(32), primary_key=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text),
        sa.Column("cursor", sa.Text),
        sa.Column("advisories", sa.Integer, nullable=False, server_default="0"),
    )

    finding_state = pg.ENUM(*FINDING_STATES, name="finding_state")
    finding_state.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "finding",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        # One vulnerability across many assets is one group with many instances.
        sa.Column("group_key", sa.Text, nullable=False),
        sa.Column("vulnerability_id", sa.Text, sa.ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", pg.UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE"), nullable=False),
        sa.Column("component_id", pg.UUID(as_uuid=True), sa.ForeignKey("component.id", ondelete="CASCADE"), nullable=False),
        sa.Column("state", finding_state, nullable=False, server_default="discovered"),
        sa.Column("match_method", sa.String(32), nullable=False),
        sa.Column("match_confidence", sa.Float, nullable=False),
        sa.Column("matched_range_id", sa.BigInteger),
        sa.Column("fixed_version", sa.Text),
        sa.Column("risk_score", sa.SmallInteger),
        sa.Column("risk_band", sa.String(16)),
        sa.Column("confidence", sa.Float),
        # The advisory revision this finding was evaluated against, so a revised
        # advisory can be re-correlated without rescanning anything.
        sa.Column("advisory_revision", sa.Integer, nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("state_changed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("due_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("vulnerability_id", "asset_id", "component_id", name="finding_instance_uniq"),
    )
    op.create_index("finding_state_idx", "finding", ["state"])
    op.create_index("finding_group_idx", "finding", ["group_key"])
    op.create_index("finding_asset_idx", "finding", ["asset_id"])

    op.create_table(
        "evidence",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", pg.UUID(as_uuid=True), sa.ForeignKey("finding.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("claim", sa.Text, nullable=False),
        sa.Column("value", pg.JSONB, nullable=False, server_default="{}"),
        sa.Column("source_ref", sa.Text),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("evidence_finding_idx", "evidence", ["finding_id"])

    # A finding must never be created already confirmed: correlation produces
    # candidates, and only investigation (M3) can confirm one.
    op.create_check_constraint(
        "finding_confidence_bounded", "finding",
        "match_confidence >= 0 AND match_confidence <= 1",
    )


def downgrade() -> None:
    for t in ("evidence", "finding", "intel_source", "affected_range", "vulnerability"):
        op.drop_table(t)
    op.execute("DROP TYPE IF EXISTS finding_state")
