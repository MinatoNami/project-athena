from __future__ import annotations

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

EXECUTOR_TABLES_RW = ("audit_event",)
EXECUTOR_TABLES_RO = ("job", "secret")


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'athena_executor') THEN
                EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM athena_executor';
                EXECUTE 'GRANT USAGE ON SCHEMA public TO athena_executor';
                EXECUTE 'GRANT SELECT, INSERT ON audit_event TO athena_executor';
                EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE audit_event_seq_seq TO athena_executor';
                EXECUTE 'GRANT SELECT ON job TO athena_executor';
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'athena_executor') THEN
                EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM athena_executor';
            END IF;
        END $$;
        """
    )
