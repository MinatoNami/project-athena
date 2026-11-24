"""Which source records classify their advisory as malware.

`vulnerability.malicious` is the OR of every source ever ingested, and nothing kept
which source said so. Retracting one source (a withdrawn report merged under a CVE)
could then only guess whether the flag still stood — by `MAL-` ids, which misses a
GHSA that carries a true `MAL-` alias. The classification is now kept per source,
and the flag is recomputed from the sources still standing.

NULL means "ingested before this was recorded": unknown, and read as possibly
malware, so a retraction never clears a flag an unexamined source may hold.

Revision ID: 0020
"""

from __future__ import annotations

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE advisory_source ADD COLUMN IF NOT EXISTS malicious boolean")
    # What can be known from what is stored. A malware report is one by its id.
    op.execute(
        "UPDATE advisory_source SET malicious = true"
        " WHERE malicious IS NULL AND upper(source_record) LIKE 'MAL-%'"
    )
    # An advisory never flagged had no source that classified it as malware.
    op.execute(
        """
        UPDATE advisory_source s SET malicious = false
          FROM vulnerability v
         WHERE v.id = s.vulnerability_id AND NOT v.malicious AND s.malicious IS NULL
        """
    )
    # The rest — other sources of a flagged advisory — stay unknown until next
    # ingested, which records them.


def downgrade() -> None:
    op.drop_column("advisory_source", "malicious")
