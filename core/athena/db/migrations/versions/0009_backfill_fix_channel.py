from __future__ import annotations

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE affected_range
           SET channel = 'esm'
         WHERE channel = 'standard'
           AND (fixed ILIKE '%~esm%' OR fixed ILIKE '%+esm%')
        """
    )
    op.execute(
        """
        UPDATE affected_range
           SET channel = 'fips'
         WHERE channel = 'standard' AND fixed ILIKE '%fips%'
        """
    )
    op.execute(
        """
        UPDATE finding f
           SET fix_channel = 'esm'
         WHERE f.fixed_version ILIKE '%~esm%' OR f.fixed_version ILIKE '%+esm%'
        """
    )
    op.execute(
        """
        UPDATE finding f
           SET fix_channel = 'fips'
         WHERE f.fix_channel IS DISTINCT FROM 'esm' AND f.fixed_version ILIKE '%fips%'
        """
    )


def downgrade() -> None:
    op.execute("UPDATE affected_range SET channel = 'standard'")
    op.execute("UPDATE finding SET fix_channel = NULL")
