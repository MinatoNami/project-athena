"""Suppressions: a decision to stop showing a finding, and what that decision rested on.

A suppression is not a deletion. It is a record that somebody looked at something and
decided it did not need attention *given what was true at the time* — so the premise
is stored alongside it. When the premise stops holding, the suppression stops
applying and the finding comes back with an explanation of why.

That is the difference between suppression and hiding. An isolated service that
becomes internet-facing, or a flaw that later joins the known-exploited catalogue,
invalidates the reasoning that dismissed it; without capturing the premise there is
no way to notice, and a one-line "accepted" from six months ago silently outlives
the situation it was about.

Scope is expressed by which columns are set rather than by a mode flag: a null
asset_id means "on any asset", a null component_id means "in any component". The
vulnerability is always required — a suppression that names no vulnerability is a
blindfold, not a decision.

Revision ID: 0014
"""
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
        # Null widens the scope. Both null means "this CVE, everywhere".
        sa.Column("asset_id", UUID(as_uuid=True), sa.ForeignKey("asset.id", ondelete="CASCADE")),
        sa.Column("component_id", UUID(as_uuid=True),
                  sa.ForeignKey("component.id", ondelete="CASCADE")),
        # Provenance only: findings are recreated by correlation, so a suppression
        # keyed on a finding id would evaporate the next time the estate was scanned.
        sa.Column("created_from_finding_id", UUID(as_uuid=True)),
        sa.Column("reason_code", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        # What was true when the decision was made. Compared on review.
        sa.Column("premise", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_by", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        # Null means no expiry, which the API requires an explicit acknowledgement for.
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
        # A suppression with no stated reason is unreviewable six months later.
        sa.CheckConstraint("length(btrim(reason)) >= 8", name="suppression_reason_length_check"),
        # A component-scoped suppression that names no asset would silently mean
        # "this component everywhere", which is not a scope anyone asks for.
        sa.CheckConstraint(
            "component_id IS NULL OR asset_id IS NOT NULL",
            name="suppression_component_needs_asset_check",
        ),
    )

    # The lookup the findings query makes on every request.
    op.create_index(
        "suppression_match_idx", "suppression", ["vulnerability_id", "asset_id", "component_id"]
    )
    # Partial index over live rows only: the query never asks about dead ones, and
    # revoked suppressions accumulate for the audit trail rather than being deleted.
    op.create_index(
        "suppression_active_idx",
        "suppression",
        ["vulnerability_id"],
        postgresql_where=sa.text("revoked_at IS NULL AND invalidated_at IS NULL"),
    )
    # One live suppression per exact scope. Without this, clicking twice creates two
    # rows and revoking one leaves the finding still hidden with no visible cause.
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
