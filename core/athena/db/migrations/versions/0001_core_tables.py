"""Core M0 tables.

Revision ID: 0001
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_user",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default="admin"),
        sa.Column("mfa_secret", sa.Text),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "app_session",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", pg.UUID(as_uuid=True), sa.ForeignKey("app_user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("step_up_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("app_session_user_idx", "app_session", ["user_id"])

    op.create_table(
        "bootstrap_token",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "job",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("key", sa.Text, nullable=False),
        sa.Column("payload", pg.JSONB, nullable=False, server_default="{}"),
        sa.Column("priority", sa.SmallInteger, nullable=False, server_default="5"),
        sa.Column("run_after", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("succeeded", sa.Boolean),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer, nullable=False, server_default="5"),
        sa.Column("last_error", sa.Text),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("result", pg.JSONB),
        sa.UniqueConstraint("kind", "key", name="job_kind_key_uniq"),
    )
    op.execute(
        "CREATE INDEX job_claimable_idx ON job (priority, run_after) WHERE finished_at IS NULL"
    )

    op.create_table(
        "audit_event",
        sa.Column("seq", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor", sa.Text, nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("detail", pg.JSONB, nullable=False, server_default="{}"),
        sa.Column("prev_hash", sa.LargeBinary, nullable=False),
        sa.Column("hash", sa.LargeBinary, nullable=False),
    )
    op.create_index("audit_event_at_idx", "audit_event", ["at"])

    op.create_table(
        "secret",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("wrapped_dek", sa.LargeBinary, nullable=False),
        sa.Column("dek_nonce", sa.LargeBinary, nullable=False),
        sa.Column("ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("nonce", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("rotated_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "outbox",
        sa.Column("seq", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("topic", sa.Text, nullable=False),
        sa.Column("subject_id", sa.Text, nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
    )
    op.create_index("outbox_topic_seq_idx", "outbox", ["topic", "seq"])

    # NOTIFY on insert so the API relay wakes without polling.
    op.execute(
        """
        CREATE FUNCTION outbox_notify() RETURNS trigger AS $$
        BEGIN
            PERFORM pg_notify('athena_events',
                json_build_object('topic', NEW.topic, 'id', NEW.subject_id,
                                  'version', NEW.version, 'seq', NEW.seq)::text);
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER outbox_notify_trg AFTER INSERT ON outbox
            FOR EACH ROW EXECUTE FUNCTION outbox_notify();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS outbox_notify_trg ON outbox")
    op.execute("DROP FUNCTION IF EXISTS outbox_notify()")
    for t in ("outbox", "secret", "audit_event", "job", "bootstrap_token", "app_session", "app_user"):
        op.drop_table(t)
