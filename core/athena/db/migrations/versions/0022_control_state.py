from __future__ import annotations

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE control_state (
            id        smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            halted    boolean NOT NULL DEFAULT false,
            reason    text,
            set_by    text,
            set_at    timestamptz
        )
        """
    )
    op.execute("INSERT INTO control_state (id, halted) VALUES (1, false)")
    op.execute(
        """
        CREATE TABLE investigation_hold (
            finding_id uuid PRIMARY KEY REFERENCES finding(id) ON DELETE CASCADE,
            held_by    text NOT NULL,
            held_at    timestamptz NOT NULL DEFAULT now()
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS investigation_hold")
    op.execute("DROP TABLE IF EXISTS control_state")
