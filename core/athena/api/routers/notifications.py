from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from athena.api.deps import Principal, can_operate, can_read, db
from athena.db.models import Notification

router = APIRouter(tags=["notifications"])


def _serialise(n: Notification) -> dict[str, Any]:
    listed = list(n.subjects or [])
    return {
        "id": str(n.id),
        "kind": n.kind,
        "title": n.title,
        "body": n.body,
        "urgency": n.urgency,
        "occurrence_count": n.occurrence_count,
        "subjects": listed,
        "subjects_truncated": n.occurrence_count > len(listed),
        "state": n.state,
        "digested": n.state == "digested",
        "channel": n.channel,
        "created_at": n.created_at,
        "sent_at": n.sent_at,
        "read_at": n.read_at,
    }


@router.get("/notifications")
def list_notifications(
    unread_only: bool = False,
    limit: int = Query(default=50, le=200),
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict[str, Any]:
    stmt = (
        select(Notification)
        .where(Notification.state.in_(("sent", "digested", "read")))
        .order_by(
            (Notification.urgency != "urgent"),
            Notification.read_at.is_not(None),
            Notification.sent_at.desc().nullslast(),
            Notification.created_at.desc(),
        )
        .limit(limit)
    )
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    rows = session.execute(stmt).scalars().all()

    unread = session.execute(
        select(func.count())
        .select_from(Notification)
        .where(
            Notification.state.in_(("sent", "digested")), Notification.read_at.is_(None)
        )
    ).scalar_one()
    urgent_unread = session.execute(
        select(func.count())
        .select_from(Notification)
        .where(
            Notification.state.in_(("sent", "digested")),
            Notification.read_at.is_(None),
            Notification.urgency == "urgent",
        )
    ).scalar_one()
    held = session.execute(
        select(func.count())
        .select_from(Notification)
        .where(Notification.state == "digested", Notification.read_at.is_(None))
    ).scalar_one()

    return {
        "notifications": [_serialise(n) for n in rows],
        "unread": unread,
        "urgent_unread": urgent_unread,
        "held_for_digest": held,
    }


@router.post("/notifications/{notification_id}/read")
def mark_read(
    notification_id: str,
    _: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
    notification = session.get(Notification, notification_id)
    if notification is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such notification")
    if notification.read_at is None:
        notification.read_at = datetime.now(UTC)
    return _serialise(notification)


@router.post("/notifications/read-all")
def mark_all_read(
    _: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
    result = session.execute(
        update(Notification)
        .where(
            Notification.state.in_(("sent", "digested")), Notification.read_at.is_(None)
        )
        .values(read_at=datetime.now(UTC))
    )
    return {"marked": result.rowcount or 0}
