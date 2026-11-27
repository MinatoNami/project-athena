from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from athena import cli
from athena.api import auth as A
from athena.db.models import AuditEvent, Session_, User


@pytest.fixture
def email(engine):
    return f"glass-{uuid.uuid4().hex[:12]}@example.com"


def _credential(stderr: str) -> str:
    match = re.search(r"password  (\S+)", stderr)
    assert match, stderr
    return match.group(1)


def _events(session, user_id, action):
    session.expire_all()
    return (
        session.execute(
            select(AuditEvent)
            .where(AuditEvent.subject == f"user:{user_id}", AuditEvent.action == action)
            .order_by(AuditEvent.seq)
        )
        .scalars()
        .all()
    )


def _audit_count(session):
    session.expire_all()
    return session.execute(select(func.count()).select_from(AuditEvent)).scalar_one()


@pytest.mark.parametrize(
    "extra",
    [
        ["--reason", "locked out"],
        ["--confirm"],
        ["--confirm", "--reason", "   "],
    ],
)
def test_refuses_without_confirm_and_reason(session, email, capsys, extra):
    before = _audit_count(session)
    assert cli.main(["break-glass", "--email", email, "--create", *extra]) == 2
    assert "refused" in capsys.readouterr().err
    assert _audit_count(session) == before
    assert session.execute(select(User).where(User.email == email)).first() is None


def test_refuses_to_create_without_the_create_flag(session, email, capsys):
    before = _audit_count(session)
    assert cli.main(["break-glass", "--email", email, "--confirm", "--reason", "x"]) == 1
    assert "--create" in capsys.readouterr().err
    assert _audit_count(session) == before


def test_creates_an_admin_and_audits_the_reason(session, email, capsys):
    code = cli.main(
        ["break-glass", "--email", email, "--create", "--confirm", "--reason", "sole admin left"]
    )
    assert code == 0
    credential = _credential(capsys.readouterr().err)

    session.expire_all()
    user = session.execute(select(User).where(User.email == email)).scalar_one()
    assert user.role == "admin"
    assert user.password_change_required is True
    assert A.verify_password(user.password_hash, credential)

    [event] = _events(session, user.id, "BREAK_GLASS")
    assert event.actor == cli.BREAK_GLASS_ACTOR
    assert event.detail["reason"] == "sole admin left"
    assert event.detail["outcome"] == "created"
    assert event.detail["operator"]


def test_resets_password_mfa_role_and_sessions_of_an_existing_user(session, email, capsys):
    user = User(
        email=email,
        password_hash=A.hash_password("old-password-123"),
        role="viewer",
        mfa_secret="sealed-v1.a.b.c.d",  # noqa: S106
        mfa_enabled=True,
        mfa_last_counter=42,
        disabled_at=datetime.now(UTC),
    )
    session.add(user)
    session.flush()
    session.add(
        Session_(
            user_id=user.id,
            token_hash=uuid.uuid4().bytes,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    session.commit()

    code = cli.main(
        ["break-glass", "--email", email.upper(), "--confirm", "--reason", "lost authenticator"]
    )
    assert code == 0
    credential = _credential(capsys.readouterr().err)

    session.expire_all()
    restored = session.get(User, user.id)
    assert restored.role == "admin"
    assert restored.disabled_at is None
    assert restored.mfa_enabled is False
    assert restored.mfa_secret is None
    assert restored.mfa_last_counter is None
    assert restored.password_change_required is True
    assert A.verify_password(restored.password_hash, credential)
    assert not A.verify_password(restored.password_hash, "old-password-123")
    live = session.execute(
        select(func.count())
        .select_from(Session_)
        .where(Session_.user_id == user.id, Session_.revoked_at.is_(None))
    ).scalar_one()
    assert live == 0

    [event] = _events(session, user.id, "BREAK_GLASS")
    assert event.detail["outcome"] == "reset"
    assert event.detail["previous_role"] == "viewer"
    assert event.detail["was_disabled"] is True
    assert event.detail["mfa_reset"] is True
    assert event.detail["sessions_revoked"] == 1
    assert event.detail["reason"] == "lost authenticator"
    [reset] = _events(session, user.id, "MFA_RESET")
    assert reset.detail["via"] == "break-glass"


def test_each_run_prints_a_different_credential(session, email, capsys):
    argv = ["break-glass", "--email", email, "--create", "--confirm", "--reason", "drill"]
    assert cli.main(argv) == 0
    first = _credential(capsys.readouterr().err)
    assert cli.main(argv) == 0
    second = _credential(capsys.readouterr().err)
    assert first != second

    session.expire_all()
    user = session.execute(select(User).where(User.email == email)).scalar_one()
    assert not A.verify_password(user.password_hash, first)
    assert A.verify_password(user.password_hash, second)
