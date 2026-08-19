"""Hash-chained audit trail.

Each row commits to its predecessor, so removing or altering history is detectable.
Append-only is additionally enforced in the database by a trigger (migration 0003) —
the application cannot rewrite history even with a bug.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from athena.db.models import AuditEvent

GENESIS = b"\x00" * 32


def _canonical(
    *, at: datetime, actor: str, action: str, subject: str, detail: dict[str, Any], prev: bytes
) -> bytes:
    body = json.dumps(
        {
            "at": at.isoformat(),
            "actor": actor,
            "action": action,
            "subject": subject,
            "detail": detail,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return prev + body


def record(
    session: Session,
    *,
    actor: str,
    action: str,
    subject: str,
    detail: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append one event. Serialised so concurrent writers cannot fork the chain."""
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext('athena.audit'))"))

    prev = session.execute(
        select(AuditEvent.hash).order_by(AuditEvent.seq.desc()).limit(1)
    ).scalar_one_or_none()
    prev = prev or GENESIS

    at = session.execute(select(func_now())).scalar_one()
    detail = detail or {}
    digest = hashlib.sha256(
        _canonical(at=at, actor=actor, action=action, subject=subject, detail=detail, prev=prev)
    ).digest()

    event = AuditEvent(
        at=at,
        actor=actor,
        action=action,
        subject=subject,
        detail=detail,
        prev_hash=prev,
        hash=digest,
    )
    session.add(event)
    session.flush()
    return event


def func_now():  # small indirection so tests can freeze time
    from sqlalchemy import func

    return func.now()


def record_isolated(
    *,
    actor: str,
    action: str,
    subject: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append an event in its own transaction.

    Rejections (failed login, rejected bootstrap token, failed step-up) raise, which
    rolls back the request transaction — and would take the audit record with it. The
    events most worth auditing are exactly the ones that fail, so they are committed
    independently of the outcome they describe.
    """
    from athena.db.base import session_scope

    with session_scope() as isolated:
        record(isolated, actor=actor, action=action, subject=subject, detail=detail)


def _broken(checked: int, seq: int, reason: str) -> dict[str, Any]:
    return {"intact": False, "checked": checked, "broken_at": seq, "reason": reason}


def verify_chain(session: Session) -> dict[str, Any]:
    """Recompute the chain. Returns the first divergence, if any."""
    rows = session.execute(
        select(
            AuditEvent.seq,
            AuditEvent.at,
            AuditEvent.actor,
            AuditEvent.action,
            AuditEvent.subject,
            AuditEvent.detail,
            AuditEvent.prev_hash,
            AuditEvent.hash,
        ).order_by(AuditEvent.seq)
    ).all()

    prev = GENESIS
    for r in rows:
        if bytes(r.prev_hash) != prev:
            return _broken(len(rows), r.seq, "prev_hash mismatch")
        expected = hashlib.sha256(
            _canonical(
                at=r.at,
                actor=r.actor,
                action=r.action,
                subject=r.subject,
                detail=r.detail,
                prev=prev,
            )
        ).digest()
        if bytes(r.hash) != expected:
            return _broken(len(rows), r.seq, "hash mismatch")
        prev = expected

    return {"intact": True, "checked": len(rows), "head": prev.hex() if rows else None}
