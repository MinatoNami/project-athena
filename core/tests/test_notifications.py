"""Notification grouping and throttling.

The two properties from the milestone checkpoint are asserted literally — one CVE
across fourteen hosts sends one notification, and a two-hundred-finding burst does
not produce two hundred messages — because both are the difference between an alert
somebody reads and one they filter to a folder they never open.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from athena.db.models import Notification
from athena.notify import dispatch, emit, in_quiet_hours

pytestmark = pytest.mark.usefixtures("engine")


def _pending(session):
    return session.execute(
        select(Notification).where(Notification.state == "pending")
    ).scalars().all()


def _counts(session):
    rows = session.execute(
        select(Notification.state, func.count()).group_by(Notification.state)
    ).all()
    return dict(rows)


# ── grouping ─────────────────────────────────────────────────────────────────


def test_one_advisory_across_fourteen_hosts_is_one_notification(session):
    cve = f"CVE-N-{uuid.uuid4().hex[:8]}"
    for n in range(14):
        emit(
            session, kind="finding.assessed", group_key=f"finding.assessed:{cve}",
            title=f"{cve} scored high", body="a flaw", subject=f"host-{n}",
        )
    session.flush()

    pending = [n for n in _pending(session) if cve in n.group_key]
    assert len(pending) == 1, "fourteen hosts produced more than one notification"
    assert pending[0].occurrence_count == 14


def test_the_message_can_say_how_many_without_listing_them_all(session):
    cve = f"CVE-N-{uuid.uuid4().hex[:8]}"
    for n in range(40):
        emit(
            session, kind="finding.assessed", group_key=f"finding.assessed:{cve}",
            title=f"{cve} scored high", body="a flaw", subject=f"host-{n}",
        )
    session.flush()
    one = next(n for n in _pending(session) if cve in n.group_key)
    assert one.occurrence_count == 40
    # Capped: naming forty assets is not more informative than naming a few.
    assert 0 < len(one.subjects) <= 12


def test_different_advisories_stay_separate(session):
    a, b = f"CVE-A-{uuid.uuid4().hex[:6]}", f"CVE-B-{uuid.uuid4().hex[:6]}"
    for cve in (a, b):
        emit(session, kind="finding.assessed", group_key=f"finding.assessed:{cve}",
             title=cve, body="", subject="host")
    session.flush()
    keys = {n.group_key for n in _pending(session)}
    assert f"finding.assessed:{a}" in keys
    assert f"finding.assessed:{b}" in keys


def test_a_sent_notification_does_not_absorb_later_occurrences(session):
    """Grouping coalesces what has not gone out yet. Folding into something already
    read would silently change a message somebody has acted on."""
    cve = f"CVE-N-{uuid.uuid4().hex[:8]}"
    key = f"finding.assessed:{cve}"
    emit(session, kind="finding.assessed", group_key=key, title=cve, body="", subject="a")
    session.flush()
    dispatch(session)
    session.flush()

    emit(session, kind="finding.assessed", group_key=key, title=cve, body="", subject="b")
    session.flush()
    assert len([n for n in _pending(session) if n.group_key == key]) == 1


def test_one_urgent_occurrence_promotes_the_group(session):
    """Fourteen routine instances plus one on an internet-facing host is an urgent
    event, not a routine one."""
    cve = f"CVE-N-{uuid.uuid4().hex[:8]}"
    key = f"finding.assessed:{cve}"
    for n in range(5):
        emit(session, kind="finding.assessed", group_key=key, title=cve, body="",
             subject=f"h{n}", urgency="routine")
    emit(session, kind="finding.assessed", group_key=key, title=cve, body="",
         subject="exposed", urgency="urgent")
    session.flush()
    assert next(n for n in _pending(session) if n.group_key == key).urgency == "urgent"


# ── throttling ───────────────────────────────────────────────────────────────


def test_a_burst_does_not_become_a_flood(session, monkeypatch):
    """Two hundred distinct findings must not produce two hundred messages."""
    from athena.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "notify_max_per_window", 10, raising=False)
    monkeypatch.setattr(settings, "notify_quiet_hours", "", raising=False)

    for n in range(200):
        emit(session, kind="finding.assessed",
             group_key=f"burst:{uuid.uuid4().hex}", title=f"finding {n}", body="")
    session.flush()

    outcome = dispatch(session)
    session.flush()
    assert outcome["sent"] <= 10, "the throttle did not hold"
    assert outcome["digested"] >= 190


def test_throttled_notifications_are_held_not_dropped(session, monkeypatch):
    """A throttle that lost messages would be indistinguishable from a broken one."""
    from athena.config import get_settings

    monkeypatch.setattr(get_settings(), "notify_max_per_window", 3, raising=False)
    monkeypatch.setattr(get_settings(), "notify_quiet_hours", "", raising=False)
    for n in range(20):
        emit(session, kind="finding.assessed",
             group_key=f"held:{uuid.uuid4().hex}", title=f"n{n}", body="")
    session.flush()
    dispatch(session)
    session.flush()

    states = _counts(session)
    assert states.get("pending", 0) == 0, "nothing may be left in limbo"
    assert states.get("digested", 0) >= 17


def test_urgent_bypasses_the_throttle(session, monkeypatch):
    """The throttle protects attention. Spending its budget on routine notices while
    an exploited flaw queues behind them would invert its purpose."""
    from athena.config import get_settings

    monkeypatch.setattr(get_settings(), "notify_max_per_window", 2, raising=False)
    monkeypatch.setattr(get_settings(), "notify_quiet_hours", "", raising=False)
    for n in range(10):
        emit(session, kind="finding.assessed",
             group_key=f"routine:{uuid.uuid4().hex}", title=f"r{n}", body="")
    urgent_key = f"urgent:{uuid.uuid4().hex}"
    emit(session, kind="finding.assessed", group_key=urgent_key, title="exploited",
         body="", urgency="urgent")
    session.flush()

    dispatch(session)
    session.flush()
    urgent = session.execute(
        select(Notification).where(Notification.group_key == urgent_key)
    ).scalars().one()
    assert urgent.state == "sent"


# ── quiet hours ──────────────────────────────────────────────────────────────


def test_quiet_hours_hold_routine_notifications(session, monkeypatch):
    from athena.config import get_settings

    monkeypatch.setattr(get_settings(), "notify_max_per_window", 100, raising=False)
    monkeypatch.setattr(get_settings(), "notify_quiet_hours", "00:00-23:59", raising=False)
    emit(session, kind="finding.assessed",
         group_key=f"quiet:{uuid.uuid4().hex}", title="routine", body="")
    session.flush()
    outcome = dispatch(session)
    session.flush()
    assert outcome["quiet_hours"] is True
    assert outcome["sent"] == 0
    assert outcome["digested"] == 1


def test_quiet_hours_never_silence_an_exploited_flaw(session, monkeypatch):
    from athena.config import get_settings

    monkeypatch.setattr(get_settings(), "notify_max_per_window", 100, raising=False)
    monkeypatch.setattr(get_settings(), "notify_quiet_hours", "00:00-23:59", raising=False)
    key = f"quiet-urgent:{uuid.uuid4().hex}"
    emit(session, kind="finding.assessed", group_key=key, title="exploited", body="",
         urgency="urgent")
    session.flush()
    dispatch(session)
    session.flush()
    assert session.execute(
        select(Notification).where(Notification.group_key == key)
    ).scalars().one().state == "sent"


def test_a_window_crossing_midnight_is_understood():
    night = datetime(2026, 8, 26, 23, 30, tzinfo=UTC)
    morning = datetime(2026, 8, 26, 6, 30, tzinfo=UTC)
    midday = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    assert in_quiet_hours(night, "22:00-07:00")
    assert in_quiet_hours(morning, "22:00-07:00")
    assert not in_quiet_hours(midday, "22:00-07:00")


def test_an_unparsable_quiet_window_fails_open():
    """A misconfigured quiet period should cost somebody a notification they did not
    want, never one they needed."""
    assert not in_quiet_hours(datetime.now(UTC), "not a time range")
    assert not in_quiet_hours(datetime.now(UTC), "")
