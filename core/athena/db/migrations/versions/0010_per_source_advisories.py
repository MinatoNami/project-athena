"""Keep each source's ranges separately instead of letting them overwrite each other.

Canonicalising onto the CVE means UBUNTU-CVE-2014-3613 and DEBIAN-CVE-2014-3613 both
become CVE-2014-3613 — which is the point, because the authority rule needs an
upstream range and a distribution range for the same flaw side by side.

But ingestion replaced *all* ranges for the vulnerability on every write, so the two
records clobbered each other: whichever was ingested last won, the other
distribution's ranges vanished, and the pair flipped the content hash back and forth
so every advisory looked revised on every poll (observed: revision 49, mean 2.89).

For an Ubuntu host whose CVE was last written by the Debian record, the Ubuntu range
was simply absent — a false negative on the exact case this milestone exists for.

Ranges now record which source record produced them and are replaced per source, and
per-source ingestion state is tracked so a revision means that source actually
changed.

Revision ID: 0010
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("affected_range", sa.Column("source_record", sa.Text))
    op.create_index(
        "affected_range_source_idx", "affected_range", ["vulnerability_id", "source_record"]
    )

    op.create_table(
        "advisory_source",
        sa.Column("vulnerability_id", sa.Text, sa.ForeignKey("vulnerability.id", ondelete="CASCADE"),
                  primary_key=True),
        # The originating record id (UBUNTU-CVE-…, GHSA-…), not the canonical CVE.
        sa.Column("source_record", sa.Text, primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("content_hash", sa.Text, nullable=False),
        sa.Column("modified_at", sa.DateTime(timezone=True)),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    # Existing rows predate per-source tracking and are incomplete by construction:
    # every CVE covered by more than one source is missing all but the last writer's
    # ranges. Clearing the state forces one clean re-ingest rather than leaving
    # silently wrong data in place.
    op.execute("DELETE FROM affected_range")
    op.execute("UPDATE vulnerability SET content_hash = '', revision = 1, revised_at = NULL")


def downgrade() -> None:
    op.drop_table("advisory_source")
    op.drop_index("affected_range_source_idx", table_name="affected_range")
    op.drop_column("affected_range", "source_record")
