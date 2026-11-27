from __future__ import annotations

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE idempotency_key (
            user_id         uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
            key             varchar(128) NOT NULL,
            method          text NOT NULL,
            path            text NOT NULL,
            body_sha256     text NOT NULL,
            response_status integer NOT NULL,
            response_body   jsonb,
            created_at      timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (user_id, key)
        )
        """
    )
    op.execute("CREATE INDEX idempotency_key_created_at ON idempotency_key (created_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS idempotency_key")
