"""Enforce append-only audit at the database level.

The application must not be able to rewrite history even with a bug, so this is a
trigger rather than a convention.

Revision ID: 0002
"""
from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION audit_event_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_event is append-only (attempted %)', TG_OP
                USING ERRCODE = 'restrict_violation';
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER audit_event_no_update BEFORE UPDATE OR DELETE ON audit_event
            FOR EACH ROW EXECUTE FUNCTION audit_event_immutable();

        CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON audit_event
            EXECUTE FUNCTION audit_event_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_event_no_truncate ON audit_event")
    op.execute("DROP TRIGGER IF EXISTS audit_event_no_update ON audit_event")
    op.execute("DROP FUNCTION IF EXISTS audit_event_immutable()")
