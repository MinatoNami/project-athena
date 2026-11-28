from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerability",
        sa.Column("malicious", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("vulnerability", sa.Column("kev_date_added", sa.Date()))
    op.add_column("vulnerability", sa.Column("kev_due_date", sa.Date()))
    op.add_column("vulnerability", sa.Column("kev_forensic_triage", sa.Boolean()))
    op.add_column("vulnerability", sa.Column("ssvc_cisa", JSONB()))
    op.add_column("vulnerability", sa.Column("ssvc_checked_at", sa.DateTime(timezone=True)))

    op.execute(
        """
        UPDATE vulnerability
           SET malicious = true
         WHERE id LIKE 'MAL-%'
            OR EXISTS (SELECT 1 FROM unnest(aliases) a WHERE a LIKE 'MAL-%')
        """
    )

    op.execute(
        """
        UPDATE finding
           SET state = 'discovered', state_changed_at = now()
         WHERE state = 'no_fix_available'
           AND vulnerability_id IN (SELECT id FROM vulnerability WHERE malicious)
        """
    )

    _backfill_cvss_scores()

    op.create_table(
        "code_finding",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            UUID(as_uuid=True),
            sa.ForeignKey("asset.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("tool", sa.Text(), nullable=False),
        sa.Column("tool_version", sa.Text()),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer()),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("detail", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("scan_run_id", UUID(as_uuid=True), nullable=False),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("asset_id", "fingerprint", name="uq_code_finding_identity"),
    )
    op.create_index(
        "ix_code_finding_open",
        "code_finding",
        ["asset_id", "kind"],
        postgresql_where=sa.text("resolved_at IS NULL"),
    )

    op.execute(
        """
        INSERT INTO job (kind, key, payload, priority)
        VALUES ('rescore.findings', 'migration-0018-cvss', '{}'::jsonb, 6)
        ON CONFLICT DO NOTHING
        """
    )


def _backfill_cvss_scores() -> None:
    from athena.intel.cvss import base_score

    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, cvss_vector FROM vulnerability "
            " WHERE cvss_score IS NULL AND cvss_vector LIKE 'CVSS:3%'"
        )
    ).all()
    update = sa.text("UPDATE vulnerability SET cvss_score = :score WHERE id = :id")
    batch = []
    for vuln_id, vector in rows:
        computed = base_score(vector)
        if computed is not None:
            batch.append({"id": vuln_id, "score": computed})
        if len(batch) >= 2000:
            bind.execute(update, batch)
            batch.clear()
    if batch:
        bind.execute(update, batch)


def downgrade() -> None:
    op.drop_index("ix_code_finding_open", table_name="code_finding")
    op.drop_table("code_finding")
    op.drop_column("vulnerability", "ssvc_checked_at")
    op.drop_column("vulnerability", "ssvc_cisa")
    op.drop_column("vulnerability", "kev_forensic_triage")
    op.drop_column("vulnerability", "kev_due_date")
    op.drop_column("vulnerability", "kev_date_added")
    op.drop_column("vulnerability", "malicious")
