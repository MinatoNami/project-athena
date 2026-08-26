"""Deciding what to tell somebody, and how often.

Three rules, in the order they apply.

**Group by what happened, not by what it touched.** One advisory affecting fourteen
hosts is one thing to be told about. A second occurrence folds into the pending
notification and raises its count; the message then says "across 14 assets" rather
than arriving fourteen times pretending to be fourteen events.

**Throttle, and say so.** Beyond a small number per window the rest are held for a
digest rather than sent. This is not about bandwidth. Somebody who receives forty
messages in an afternoon stops reading any of them, and the fortieth is as likely to
matter as the first — so the throttle protects the value of the ones that do send.
Held notifications are marked `digested`, never dropped, so a throttle can never be
mistaken for a delivery failure.

**Urgency bypasses both.** Known-exploited, or measured critical, sends immediately
and through quiet hours. A quiet-hours policy that silenced an actively exploited
flaw would be the mechanism doing harm rather than reducing noise.

Delivery here is in-app only. Sending to an external service is egress, which is a
policy decision this deployment has deliberately not made — the channel column exists
so that decision has somewhere to land.
"""

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

# Folded into a pending notification rather than listed in full: a message naming
# two hundred assets is not more informative than one naming five and a count.
MAX_LISTED_SUBJECTS = 12


def in_quiet_hours(now: datetime | None = None, spec: str | None = None) -> bool:
    """Is it currently a time we agreed not to interrupt?

    A malformed or empty spec means "no quiet hours". Failing open is deliberate:
    the failure mode of a misconfigured quiet period should be a notification
    somebody did not want, never one they needed and did not get.
    """
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
    # Crosses midnight.
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
    """Record something worth telling somebody, folding it into any pending peer.

    The fold is done by the database rather than by a read-then-write, because two
    workers finishing investigations on the same advisory at the same moment is the
    normal case, not a rare one — and a lost race here is a duplicate message, which
    is the exact thing this module exists to prevent.
    """
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
            # A literal, not a bound parameter: Postgres matches ON CONFLICT to a
            # partial index by comparing predicates, and a placeholder matches
            # nothing — which fails as "no unique or exclusion constraint matching",
            # naming the index it is in fact looking straight at.
            index_where=text("state = 'pending'"),
            # The upsert does only what must be atomic: claim the group and count
            # the occurrence. Merging subjects and promoting urgency read badly as
            # SQL expressions and are done below, on the row this statement locked.
            set_={
                "occurrence_count": Notification.occurrence_count + 1,
                "updated_at": now,
            },
        )
        .returning(Notification.id)
    )
    notification_id = session.execute(stmt).scalar_one()
    notification = session.get(Notification, notification_id)

    # Subject accumulation is done here rather than in SQL: appending to a JSONB
    # array while de-duplicating and capping is unreadable as an expression, and
    # this row is already locked by the upsert above.
    if subject and subject not in (notification.subjects or []):
        existing = list(notification.subjects or [])
        if len(existing) < MAX_LISTED_SUBJECTS:
            existing.append(subject)
            notification.subjects = existing
    # An urgent occurrence promotes the whole group: fourteen routine instances plus
    # one on an internet-facing host is an urgent event, not a routine one.
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
    """Send what should go now; hold the rest for the digest.

    Urgent first, and unconditionally: the throttle exists to protect attention, and
    spending the window's budget on routine notifications while an exploited flaw
    waits behind them would invert its purpose.
    """
    settings = get_settings()
    moment = now or datetime.now(UTC)
    quiet = in_quiet_hours(moment)

    pending = session.execute(
        select(Notification)
        .where(Notification.state == "pending")
        .order_by(
            # urgent sorts before routine alphabetically, which is luck rather than
            # design, so it is stated explicitly.
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
            # Held, not dropped. It still appears, in the digest, with its count.
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
