from __future__ import annotations

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("job_kind_key_uniq", "job", type_="unique")
    op.execute(
        "CREATE UNIQUE INDEX job_pending_uniq ON job (kind, key) WHERE finished_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS job_pending_uniq")
    op.create_unique_constraint("job_kind_key_uniq", "job", ["kind", "key"])
