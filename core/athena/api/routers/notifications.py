"""Reading notifications.

Delivery is in-app: a notification "sends" by becoming visible here. Anything
external is egress, which is a policy decision this deployment has not made — the
`channel` column exists so it has somewhere to land when it is.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
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
        # The count, not the list: a message naming two hundred assets is not more
        # informative than one naming a few and saying how many there were.
        "occurrence_count": n.occurrence_count,
        "subjects": listed,
        "subjects_truncated": n.occurrence_count > len(listed),
        "state": n.state,
        # Held for the digest is not the same as failed to send, and the UI needs to
        # be able to say which.
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
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    stmt = (
        select(Notification)
        .where(Notification.state.in_(("sent", "digested", "read")))
        # Urgent first, then unread, then recency. Ordering by time alone buries an
        # actively exploited flaw under whatever routine assessments happened to be
        # dispatched in the same pass — they all carry the same timestamp, so the
        # tie-break was effectively arbitrary.
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
    # Counted so the digest can say what it is a digest of.
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
    _: Principal = Depends(current_principal),
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
    _: Principal = Depends(current_principal),
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
