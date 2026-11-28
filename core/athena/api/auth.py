from __future__ import annotations

import hashlib
import math
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.api import totp
from athena.audit import record
from athena.config import get_settings
from athena.db.models import AuditEvent, BootstrapToken, Session_, User

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


def any_user_exists(session: Session) -> bool:
    return session.execute(select(User.id).limit(1)).first() is not None


def live_bootstrap_token_exists(session: Session) -> bool:
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


def mfa_lockout_retry_after(
    session: Session, user: User, *, now: datetime | None = None
) -> int | None:
    settings = get_settings()
    threshold = settings.mfa_lockout_failures
    window = timedelta(seconds=settings.mfa_lockout_window_seconds)
    if threshold <= 0:
        return None
    current = now or datetime.now(UTC)
    since = current - window
    last_seq_before_window = (
        select(AuditEvent.seq)
        .where(AuditEvent.at < since)
        .order_by(AuditEvent.seq.desc())
        .limit(1)
        .scalar_subquery()
    )
    recent_failures = (
        session.execute(
            select(AuditEvent.at)
            .where(
                AuditEvent.seq > func.coalesce(last_seq_before_window, 0),
                AuditEvent.at >= since,
                AuditEvent.at <= current,
                AuditEvent.action == "MFA_FAILED",
                AuditEvent.subject == f"user:{user.id}",
            )
            .order_by(AuditEvent.seq.desc())
            .limit(threshold)
        )
        .scalars()
        .all()
    )
    if len(recent_failures) < threshold:
        return None
    unlocks_at = min(recent_failures) + window
    return max(1, math.ceil((unlocks_at - current).total_seconds()))


SINGLE_USE_CREDENTIAL_ISSUERS = ("USER_INVITED", "BREAK_GLASS")


def single_use_credential_expired(
    session: Session, user: User, *, now: datetime | None = None
) -> bool:
    since = (now or datetime.now(UTC)) - timedelta(
        hours=get_settings().single_use_credential_ttl_hours
    )
    last_seq_before_ttl = (
        select(AuditEvent.seq)
        .where(AuditEvent.at < since)
        .order_by(AuditEvent.seq.desc())
        .limit(1)
        .scalar_subquery()
    )
    issued_within_ttl = session.execute(
        select(AuditEvent.seq)
        .where(
            AuditEvent.seq > func.coalesce(last_seq_before_ttl, 0),
            AuditEvent.at >= since,
            AuditEvent.action.in_(SINGLE_USE_CREDENTIAL_ISSUERS),
            AuditEvent.subject == f"user:{user.id}",
        )
        .limit(1)
    ).first()
    return issued_within_ttl is None


def verify_totp(session: Session, user: User, code: str | None) -> bool:
    if not user.mfa_secret or not code:
        return False
    session.refresh(user, with_for_update=True)
    if not user.mfa_secret:
        return False
    key = totp.decode_secret(totp.unseal_secret(user.id, user.mfa_secret))
    counter = totp.matching_counter(key, code, last_counter=user.mfa_last_counter)
    if counter is None:
        return False
    user.mfa_last_counter = counter
    return True


def clear_mfa(user: User) -> None:
    user.mfa_secret = None
    user.mfa_enabled = False
    user.mfa_last_counter = None
