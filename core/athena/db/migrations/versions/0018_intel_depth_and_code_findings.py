"""Deeper intelligence, and findings that are not about a package version.

Four changes, one theme: facts Athena was already receiving and discarding.

* `vulnerability.cvss_score` was never computed from the vector. It is backfilled
  here for every v3 vector, and a rescore is queued so stored bands follow — the
  score feeds the risk function's base factor, so a backfill that left bands alone
  would show one number on the page and rank by another.

* `vulnerability.malicious`. OSV carries the OpenSSF malicious-packages feed as
  `MAL-` records, and they were correlated like any vulnerability — which produced
  "no fixed version has been published yet" for a typosquat. Malware is not a flaw
  awaiting a patch; it needs its own remediation and its own floor.

* `vulnerability.kev_due_date` / `kev_date_added` / `kev_forensic_triage`. CISA's
  catalogue states when it added a flaw, the deadline it set (BOD 26-04 since June
  2026), and whether it requires forensic triage. `kev_added_at` records when
  *Athena* noticed, which is a different fact and stays.

* `vulnerability.ssvc_cisa`. CISA's per-CVE SSVC assessment (Vulnrichment), which
  outranks Athena's own mapping from the CVSS vector wherever it exists.

* `code_finding`. Secrets and misconfigurations found in a repository have no
  advisory and no component version, so the `finding` table — keyed on both — cannot
  hold them. They get a table of their own rather than placeholder rows in that one.

Revision ID: 0018
"""

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
    # BOD 26-04 added `forensicTriage` to the catalogue: CISA's judgement that a fix
    # alone is not enough and the asset must be checked for prior compromise.
    op.add_column("vulnerability", sa.Column("kev_forensic_triage", sa.Boolean()))
    # CISA's own SSVC assessment from its Vulnrichment ADP container, when one exists.
    # Preferred over Athena's mapping from the CVSS vector; `ssvc_checked_at` is set
    # even when CISA has none, so "looked and found nothing" is not "never looked".
    op.add_column("vulnerability", sa.Column("ssvc_cisa", JSONB()))
    op.add_column("vulnerability", sa.Column("ssvc_checked_at", sa.DateTime(timezone=True)))
    # The vector `cvss_score` was computed from, when Athena computed it. A record
    # often publishes v4.0 and v3.1 side by side; `cvss_vector` keeps the first, the
    # score comes from the v3 one, and without this the page compared the score
    # with the wrong vector and called it the advisory's own number.
    op.add_column("vulnerability", sa.Column("cvss_scoring_vector", sa.Text()))

    op.execute(
        """
        UPDATE vulnerability
           SET malicious = true
         WHERE id LIKE 'MAL-%'
            OR EXISTS (SELECT 1 FROM unnest(aliases) a WHERE a LIKE 'MAL-%')
        """
    )

    # Malware findings were filed as `no_fix_available` — excluded from the default
    # view and the triage queue — because their records carry no fixed version.
    # There is no version to wait for; removal is available now.
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
        # secret | misconfiguration
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("tool", sa.Text(), nullable=False),
        sa.Column("tool_version", sa.Text()),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer()),
        # Identity across scans. Never derived from a secret's value: the value is
        # redacted before it leaves the sandbox and is not available to hash.
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("detail", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("scan_run_id", UUID(as_uuid=True), nullable=False),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        # Set when a *successful* scan no longer reports it. A failed or partial scan
        # never resolves anything — absence from a scan that did not finish is not
        # evidence of absence.
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("asset_id", "fingerprint", name="uq_code_finding_identity"),
    )
    op.create_index(
        "ix_code_finding_open",
        "code_finding",
        ["asset_id", "kind"],
        postgresql_where=sa.text("resolved_at IS NULL"),
    )

    # The bands stored on investigated findings were computed with no CVSS score.
    # Queue the rescore that brings them into line; deduplicated by key, so running
    # this migration twice cannot queue it twice.
    op.execute(
        """
        INSERT INTO job (kind, key, payload, priority)
        VALUES ('rescore.findings', 'migration-0018-cvss', '{}'::jsonb, 6)
        ON CONFLICT DO NOTHING
        """
    )


def _backfill_cvss_scores() -> None:
    """Compute the base score for every stored v3 vector that has none.

    Imports the calculator rather than restating it: two copies of a scoring formula
    is exactly the drift the risk module warns about, and this one was checked
    against an independent implementation over every v3 base vector.
    """
    from athena.intel.cvss import base_score

    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, cvss_vector FROM vulnerability "
            " WHERE cvss_score IS NULL AND cvss_vector LIKE 'CVSS:3%'"
        )
    ).all()
    update = sa.text(
        "UPDATE vulnerability SET cvss_score = :score, cvss_scoring_vector = :vector WHERE id = :id"
    )
    batch = []
    for vuln_id, vector in rows:
        computed = base_score(vector)
        if computed is not None:
            batch.append({"id": vuln_id, "score": computed, "vector": vector})
        if len(batch) >= 2000:
            bind.execute(update, batch)
            batch.clear()
    if batch:
        bind.execute(update, batch)


def downgrade() -> None:
    op.drop_index("ix_code_finding_open", table_name="code_finding")
    op.drop_table("code_finding")
    op.drop_column("vulnerability", "cvss_scoring_vector")
    op.drop_column("vulnerability", "ssvc_checked_at")
    op.drop_column("vulnerability", "ssvc_cisa")
    op.drop_column("vulnerability", "kev_forensic_triage")
    op.drop_column("vulnerability", "kev_due_date")
    op.drop_column("vulnerability", "kev_date_added")
    op.drop_column("vulnerability", "malicious")
    # cvss_score is left as computed: removing it would restore a known defect, and
    # the column predates this revision.
