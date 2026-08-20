"""Deduplicate only pending jobs, not completed ones.

UNIQUE (kind, key) covered finished rows, so once a job had run — successfully or
not — nothing with that key could ever be enqueued again. The scheduler buckets its
keys by interval, so a single failure suppressed that task for the whole bucket, and
a completed hourly poll blocked the next one until the hour rolled over. On a
deployment this looked like the scheduler having stopped: no queue depth, no errors,
no work.

Revision ID: 0007
"""
from __future__ import annotations

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("job_kind_key_uniq", "job", type_="unique")
    # Idempotency is about not queueing the same work twice while it is outstanding.
    # Once a job is finished, the same key must be free to be used again.
    op.execute(
        "CREATE UNIQUE INDEX job_pending_uniq ON job (kind, key) WHERE finished_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS job_pending_uniq")
    op.create_unique_constraint("job_kind_key_uniq", "job", ["kind", "key"])
