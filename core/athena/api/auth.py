"""Authentication.

No default credentials, ever. First run mints a single-use bootstrap token that is
printed once to the log; the admin account is created interactively from it.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.audit import record
from athena.config import get_settings
from athena.db.models import BootstrapToken, Session_, User

_hasher = PasswordHasher()

SESSION_COOKIE = "athena_session"
BOOTSTRAP_TTL = timedelta(hours=24)
MIN_PASSWORD_LENGTH = 12


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    return True


# --- bootstrap ------------------------------------------------------------------


def any_user_exists(session: Session) -> bool:
    return session.execute(select(User.id).limit(1)).first() is not None


def live_bootstrap_token_exists(session: Session) -> bool:
    """A previously minted token that is still usable.

    `athena bootstrap` runs on every deploy, so it must not mint a fresh token each
    time — that would leave a trail of valid admin-creation credentials.
    """
    return (
        session.execute(
            select(BootstrapToken.id).where(
                BootstrapToken.consumed_at.is_(None),
                BootstrapToken.expires_at > datetime.now(UTC),
            ).limit(1)
        ).first()
        is not None
    )


def mint_bootstrap_token(session: Session) -> str:
    token = secrets.token_urlsafe(32)
    session.add(
        BootstrapToken(
            token_hash=hash_token(token),
            expires_at=datetime.now(UTC) + BOOTSTRAP_TTL,
        )
    )
    record(
        session,
        actor="system:api",
        action="BOOTSTRAP_TOKEN_MINTED",
        subject="bootstrap",
        detail={"ttl_hours": int(BOOTSTRAP_TTL.total_seconds() // 3600)},
    )
    return token


def consume_bootstrap_token(session: Session, token: str) -> BootstrapToken | None:
    row = session.execute(
        select(BootstrapToken).where(BootstrapToken.token_hash == hash_token(token))
    ).scalar_one_or_none()
    if row is None or row.consumed_at is not None:
        return None
    if row.expires_at < datetime.now(UTC):
        return None
    row.consumed_at = datetime.now(UTC)
    return row


# --- sessions -------------------------------------------------------------------


def create_session(session: Session, user: User) -> str:
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    session.add(
        Session_(
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=datetime.now(UTC) + timedelta(hours=settings.session_ttl_hours),
        )
    )
    return token


def resolve_session(session: Session, token: str | None) -> tuple[User, Session_] | None:
    """Return the live session, applying both idle and absolute timeouts."""
    if not token:
        return None
    row = session.execute(
        select(Session_).where(Session_.token_hash == hash_token(token))
    ).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return None

    now = datetime.now(UTC)
    settings = get_settings()
    if row.expires_at < now:
        return None
    if row.last_seen_at < now - timedelta(minutes=settings.session_idle_minutes):
        row.revoked_at = now
        return None

    user = session.get(User, row.user_id)
    if user is None or user.disabled_at is not None:
        return None

    row.last_seen_at = now
    return user, row


def revoke_session(session: Session, token: str | None) -> None:
    if not token:
        return
    row = session.execute(
        select(Session_).where(Session_.token_hash == hash_token(token))
    ).scalar_one_or_none()
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)


def has_fresh_step_up(sess: Session_) -> bool:
    if sess.step_up_at is None:
        return False
    ttl = get_settings().step_up_ttl_seconds
    return sess.step_up_at > datetime.now(UTC) - timedelta(seconds=ttl)


def validate_password_strength(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return None
