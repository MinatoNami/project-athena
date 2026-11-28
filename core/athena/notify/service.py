from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
from typing import Any

import structlog
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from athena.config import get_settings
from athena.db.models import Notification

log = structlog.get_logger(__name__)

URGENT, ROUTINE = "urgent", "routine"

MAX_LISTED_SUBJECTS = 12


def in_quiet_hours(now: datetime | None = None, spec: str | None = None) -> bool:
    raw = (spec if spec is not None else get_settings().notify_quiet_hours).strip()
    if not raw or "-" not in raw:
        return False
    try:
        start_s, end_s = raw.split("-", 1)
        start = time.fromisoformat(start_s.strip())
        end = time.fromisoformat(end_s.strip())
    except ValueError:
        log.warning("notify.quiet_hours_unparsable", spec=raw)
        return False

    moment = (now or datetime.now(UTC)).time()
    if start <= end:
        return start <= moment < end
    return moment >= start or moment < end


def emit(
    session: Session,
    *,
    kind: str,
    group_key: str,
    title: str,
    body: str,
    subject: str | None = None,
    urgency: str = ROUTINE,
) -> Notification:
    now = datetime.now(UTC)
    stmt = (
        insert(Notification)
        .values(
            kind=kind,
            group_key=group_key,
            title=title,
            body=body,
            urgency=urgency,
            occurrence_count=1,
            subjects=[subject] if subject else [],
            state="pending",
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=[Notification.group_key],
            index_where=text("state = 'pending'"),
            set_={
                "occurrence_count": Notification.occurrence_count + 1,
                "updated_at": now,
            },
        )
        .returning(Notification.id)
    )
    notification_id = session.execute(stmt).scalar_one()
    notification = session.get(Notification, notification_id)

    if subject and subject not in (notification.subjects or []):
        existing = list(notification.subjects or [])
        if len(existing) < MAX_LISTED_SUBJECTS:
            existing.append(subject)
            notification.subjects = existing
    if urgency == URGENT:
        notification.urgency = URGENT
    return notification


def _sent_in_window(session: Session, *, minutes: int) -> int:
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    return session.execute(
        select(func.count())
        .select_from(Notification)
        .where(Notification.state == "sent", Notification.sent_at >= since)
    ).scalar_one()


def dispatch(session: Session, *, now: datetime | None = None) -> dict[str, Any]:
    settings = get_settings()
    moment = now or datetime.now(UTC)
    quiet = in_quiet_hours(moment)

    pending = session.execute(
        select(Notification)
        .where(Notification.state == "pending")
        .order_by(
            (Notification.urgency != URGENT),
            Notification.created_at,
        )
    ).scalars().all()

    budget = max(0, settings.notify_max_per_window - _sent_in_window(
        session, minutes=settings.notify_window_minutes
    ))
    sent, digested = 0, 0

    for notification in pending:
        urgent = notification.urgency == URGENT
        if urgent:
            notification.state = "sent"
            notification.sent_at = moment
            notification.channel = "inapp"
            sent += 1
            continue
        if quiet or budget <= 0:
            notification.state = "digested"
            notification.sent_at = moment
            notification.channel = "digest"
            digested += 1
            continue
        notification.state = "sent"
        notification.sent_at = moment
        notification.channel = "inapp"
        sent += 1
        budget -= 1

    outcome = {
        "sent": sent,
        "digested": digested,
        "quiet_hours": quiet,
        "pending_before": len(pending),
    }
    if sent or digested:
        log.info("notify.dispatched", **outcome)
    return outcome
