from __future__ import annotations

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE advisory_source ADD COLUMN IF NOT EXISTS malicious boolean")
    op.execute(
        "UPDATE advisory_source SET malicious = true"
        " WHERE malicious IS NULL AND upper(source_record) LIKE 'MAL-%'"
    )
    op.execute(
        """
        UPDATE advisory_source s SET malicious = false
          FROM vulnerability v
         WHERE v.id = s.vulnerability_id AND NOT v.malicious AND s.malicious IS NULL
        """
    )


def downgrade() -> None:
    op.drop_column("advisory_source", "malicious")
