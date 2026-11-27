from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, can_read, db
from athena.audit import verify_chain
from athena.db.models import AuditEvent

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_events(
    limit: int = Query(default=100, le=500),
    before_seq: int | None = None,
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict:
    stmt = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(limit)
    if before_seq is not None:
        stmt = stmt.where(AuditEvent.seq < before_seq)
    rows = session.execute(stmt).scalars().all()

    user_ids = {e.actor.split(":", 1)[1] for e in rows if e.actor.startswith("user:")}
    emails: dict[str, str] = {}
    if user_ids:
        from athena.db.models import User

        valid = []
        for uid in user_ids:
            try:
                valid.append(uuid.UUID(uid))
            except ValueError:
                continue
        emails = {
            str(u.id): u.email
            for u in session.execute(select(User).where(User.id.in_(valid))).scalars()
        }

    def label(actor: str) -> str:
        kind, _, ident = actor.partition(":")
        if kind == "user":
            return emails.get(ident, "a deleted user")
        if kind == "system":
            return f"Athena ({ident})" if ident else "Athena"
        return actor

    return {
        "events": [
            {
                "seq": e.seq,
                "at": e.at,
                "actor": e.actor,
                "actor_label": label(e.actor),
                "action": e.action,
                "subject": e.subject,
                "detail": e.detail,
                "hash": e.hash.hex(),
            }
            for e in rows
        ],
        "next_before_seq": rows[-1].seq if rows else None,
    }


@router.get("/verify")
def verify(
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict:
    return verify_chain(session)
