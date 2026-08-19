from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.audit import verify_chain
from athena.db.models import AuditEvent

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_events(
    limit: int = Query(default=100, le=500),
    before_seq: int | None = None,
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict:
    stmt = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(limit)
    if before_seq is not None:
        stmt = stmt.where(AuditEvent.seq < before_seq)
    rows = session.execute(stmt).scalars().all()
    return {
        "events": [
            {
                "seq": e.seq,
                "at": e.at,
                "actor": e.actor,
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
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict:
    """Recompute the hash chain from genesis and report the first divergence, if any."""
    return verify_chain(session)
