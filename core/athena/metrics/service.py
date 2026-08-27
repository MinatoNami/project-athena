"""The PRD's success metrics, computed where they can be and refused where they cannot.

Every metric carries three things: a value, the denominator it was computed over, and
a status saying whether that denominator is large enough to mean anything. Most
security dashboards omit the middle one, which is how "0% false positives" comes to
be printed under a sample of two.

Four of the ten cannot be computed on this system yet — remediation has not been
built, and investigation quality needs ground truth a corpus has to supply. They are
reported as `not_implemented` and `unknown` respectively rather than as zero. A zero
and an absence look identical in a chart and mean opposite things, and the whole
product is an argument against letting that happen.

Rates over tiny denominators are refused for the same reason. A percentage computed
over four findings is noise wearing a number's clothes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import Float, and_, case, cast, func, select
from sqlalchemy.orm import Session

from athena.config import get_settings
from athena.db.models import (
    Asset,
    Finding,
    IntelSource,
    InvestigationRecord,
    Notification,
    Suppression,
    Vulnerability,
)

# Below these, a rate is not a measurement. Chosen so a single outcome cannot move
# a headline number by more than a few points.
MIN_FOR_RATE = 20
MIN_FOR_LATENCY = 5


class Status(StrEnum):
    MEETING = "meeting"          # at or better than the MVP target
    MISSING = "missing"          # computed, and short of it
    NO_TARGET = "no_target"      # computed, but the PRD sets no number
    UNKNOWN = "unknown"          # not enough data to say
    NOT_IMPLEMENTED = "not_implemented"


@dataclass
class Metric:
    id: str
    label: str
    description: str
    value: float | None = None
    unit: str = ""
    # Always stated. A rate without one is an assertion.
    denominator: int = 0
    denominator_label: str = ""
    target_mvp: float | None = None
    target_mature: float | None = None
    # Which direction is good, so the UI never has to guess.
    lower_is_better: bool = False
    status: Status = Status.UNKNOWN
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["status"] = str(self.status)
        return out


def _grade(metric: Metric) -> Metric:
    """Compare against the MVP target, and only when the sample supports it."""
    if metric.value is None:
        return metric
    if metric.target_mvp is None:
        metric.status = Status.NO_TARGET
        return metric
    ok = (
        metric.value <= metric.target_mvp
        if metric.lower_is_better
        else metric.value >= metric.target_mvp
    )
    metric.status = Status.MEETING if ok else Status.MISSING
    return metric


# ── computable now ───────────────────────────────────────────────────────────


def detection_latency(session: Session) -> Metric:
    """Advisory published to affected asset identified, in hours.

    Counted only for advisories published after Athena started watching. An advisory
    from before that did not take two years to detect — it was there when the system
    arrived, and including it would measure the backfill rather than the watch.
    """
    m = Metric(
        id="detection_latency",
        label="Detection latency",
        description="Advisory published to affected asset identified.",
        unit="hours",
        target_mvp=24,
        target_mature=2,
        lower_is_better=True,
        denominator_label="advisories published since Athena started watching",
    )
    watching_since = session.execute(
        select(func.min(IntelSource.first_success_at))
    ).scalar_one_or_none()
    if watching_since is None:
        m.note = "No intelligence source has ever fetched successfully."
        return m

    rows = session.execute(
        select(
            func.count(),
            func.percentile_cont(0.5).within_group(
                cast(
                    func.extract("epoch", Finding.first_seen - Vulnerability.published_at),
                    Float,
                )
            ),
        )
        .select_from(Finding)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(
            Vulnerability.published_at.is_not(None),
            Vulnerability.published_at > watching_since,
            Finding.first_seen >= Vulnerability.published_at,
        )
    ).one()
    count, median_seconds = rows
    m.denominator = count or 0
    if m.denominator < MIN_FOR_LATENCY:
        m.note = (
            f"Only {m.denominator} advisories have been published since watching began "
            f"on {watching_since.date()}. Too few to describe a latency."
        )
        return m
    m.value = round((median_seconds or 0) / 3600, 2)
    return _grade(m)


def coverage(session: Session) -> Metric:
    """Registered assets with a recent inventory."""
    from athena.inventory.service import coverage as inventory_coverage

    c = inventory_coverage(session)
    m = Metric(
        id="coverage",
        label="Asset coverage",
        description="Registered assets inventoried within their freshness window.",
        unit="%",
        target_mvp=90,
        target_mature=99,
        denominator=c["assets_total"],
        denominator_label="registered assets",
    )
    if not m.denominator:
        m.note = "No assets are registered."
        return m
    m.value = round(100 * c["assets_fresh"] / c["assets_total"], 1)
    note = [
        f"{c['assets_never_scanned']} never inventoried, {c['assets_stale']} stale. "
        "Neither is a clean result."
    ]
    if c.get("assets_inherited"):
        # Said rather than folded in silently: these were established by scanning the
        # image a container came from, so a package installed into a running
        # container after it started would not appear.
        note.append(
            f"{c['assets_inherited']} containers are covered by their image rather "
            "than scanned directly, so a runtime install would not be seen."
        )
    m.note = " ".join(note)
    return _grade(m)


def false_positive_rate(session: Session) -> Metric:
    """Assessed findings a person dismissed as not real."""
    m = Metric(
        id="false_positive_rate",
        label="False positive rate",
        description="Assessed findings dismissed as wrong, by a person.",
        unit="%",
        target_mvp=30,
        target_mature=10,
        lower_is_better=True,
        denominator_label="findings with a verdict",
    )
    assessed = session.execute(
        select(func.count()).select_from(Finding).where(Finding.investigation_id.is_not(None))
    ).scalar_one()
    m.denominator = assessed
    if assessed < MIN_FOR_RATE:
        m.note = f"Only {assessed} findings have been assessed. Too few to rate."
        return m
    dismissed = session.execute(
        select(func.count(func.distinct(Suppression.id))).where(
            Suppression.reason_code == "false_positive"
        )
    ).scalar_one()
    m.value = round(100 * dismissed / assessed, 1)
    if dismissed == 0:
        m.note = (
            "Nothing has been dismissed as a false positive yet. That may mean the "
            "matching is good, or that nobody has disagreed with it yet."
        )
    return _grade(m)


def suppression_durability(session: Session) -> Metric:
    """Dismissed findings that stayed dismissed.

    A falling rate is a correlation defect, not a user problem: findings that keep
    coming back were dismissed for reasons that never held.
    """
    m = Metric(
        id="suppression_durability",
        label="Suppression durability",
        description="Dismissals that were not later invalidated or revoked.",
        unit="%",
        lower_is_better=False,
        denominator_label="suppressions created",
    )
    total = session.execute(select(func.count()).select_from(Suppression)).scalar_one()
    m.denominator = total
    if total < MIN_FOR_RATE:
        m.note = f"Only {total} suppressions exist. Too few to rate."
        return m
    held = session.execute(
        select(func.count())
        .select_from(Suppression)
        .where(Suppression.invalidated_at.is_(None), Suppression.revoked_at.is_(None))
    ).scalar_one()
    m.value = round(100 * held / total, 1)
    return _grade(m)


def notification_precision(session: Session) -> Metric:
    """Notifications somebody opened.

    Deliberately labelled as read rather than acted on. Reading is what this system
    can observe; claiming it measures action would overstate what the number knows.
    """
    m = Metric(
        id="notification_precision",
        label="Notification engagement",
        description="Delivered notifications that were opened.",
        unit="%",
        target_mvp=50,
        target_mature=70,
        denominator_label="notifications delivered",
    )
    delivered = session.execute(
        select(func.count())
        .select_from(Notification)
        .where(Notification.state.in_(("sent", "digested", "read")))
    ).scalar_one()
    m.denominator = delivered
    if delivered < MIN_FOR_RATE:
        m.note = f"Only {delivered} notifications have been delivered. Too few to rate."
        return m
    read = session.execute(
        select(func.count()).select_from(Notification).where(Notification.read_at.is_not(None))
    ).scalar_one()
    m.value = round(100 * read / delivered, 1)
    m.note = "Measures opening, not acting. Acting is not something this system can see."
    return _grade(m)


def model_cost(session: Session) -> Metric:
    """Tokens spent on investigation over the last 30 days.

    Reported in tokens rather than currency: this deployment runs a local model, so
    the marginal cost is electricity and time, and putting a price on it would be an
    invented number.
    """
    m = Metric(
        id="model_cost",
        label="Investigation cost",
        description="Model tokens spent on investigation in the last 30 days.",
        unit="tokens",
        denominator_label="investigations in the window",
    )
    since = datetime.now(UTC) - timedelta(days=30)
    count, tokens = session.execute(
        select(
            func.count(),
            func.coalesce(
                func.sum(
                    InvestigationRecord.prompt_tokens + InvestigationRecord.completion_tokens
                ),
                0,
            ),
        ).where(InvestigationRecord.created_at >= since)
    ).one()
    m.denominator = count or 0
    if not m.denominator:
        m.note = "No investigations ran in the last 30 days."
        return m
    m.value = int(tokens or 0)
    m.status = Status.NO_TARGET
    m.note = (
        f"{round((tokens or 0) / m.denominator):,} tokens per investigation. "
        "Local model, so this is time and electricity rather than a bill."
    )
    return m


# ── not computable yet, and saying so ────────────────────────────────────────


def investigation_quality(session: Session) -> Metric:
    """Needs ground truth, which only a labelled corpus supplies."""
    m = Metric(
        id="investigation_quality",
        label="Investigation quality",
        description="Matches correctly classified as applicable, not applicable, or uncertain.",
        unit="%",
        target_mvp=85,
        target_mature=95,
        denominator_label="findings with a human judgement recorded",
        status=Status.UNKNOWN,
    )
    m.note = (
        "Cannot be computed from production data: it needs cases where the right "
        "answer is known independently. The eval corpus measures this against "
        "hand-labelled cases; agreement with human judgement on real findings needs "
        "somewhere for a person to disagree, which does not exist yet."
    )
    return m


def mean_time_to_remediation(session: Session) -> Metric:
    m = Metric(
        id="mttr",
        label="Mean time to remediation",
        description="Confirmed finding to verified resolution.",
        unit="days",
        lower_is_better=True,
        # Stated even though nothing can be counted yet: a gap is described by what
        # would fill it, not just by being empty.
        denominator_label="findings taken from confirmed to verified resolution",
        status=Status.NOT_IMPLEMENTED,
    )
    m.note = "Nothing can be remediated yet. Arrives with approval and execution in M5."
    return m


def patch_success_rate(session: Session) -> Metric:
    m = Metric(
        id="patch_success_rate",
        label="Patch success rate",
        description="Prepared patches that build and pass validation.",
        unit="%",
        target_mvp=70,
        target_mature=90,
        denominator_label="patches Athena prepared",
        status=Status.NOT_IMPLEMENTED,
    )
    m.note = "No patches are prepared yet. Arrives with remediation preparation in M4."
    return m


# ── service levels ───────────────────────────────────────────────────────────


def sla_report(session: Session) -> dict[str, Any]:
    """How long open findings have been waiting, against a target per band.

    The targets are defaults, not requirements handed down by the PRD — it sets
    numbers for detection and accuracy but says nothing about how long a confirmed
    finding may sit. They are configurable so they can be argued with rather than
    quietly ignored.
    """
    settings = get_settings()
    targets = {
        "critical": settings.sla_days_critical,
        "high": settings.sla_days_high,
        "medium": settings.sla_days_medium,
    }
    now = datetime.now(UTC)
    bands: list[dict[str, Any]] = []

    for band, days in targets.items():
        deadline = now - timedelta(days=days)
        total, late, oldest = session.execute(
            select(
                func.count(),
                func.count().filter(Finding.first_seen < deadline),
                func.min(Finding.first_seen),
            )
            .select_from(Finding)
            .where(
                Finding.risk_band == band,
                # Open means somebody could still act. Dismissed and unfixable
                # findings are not late; they are elsewhere, and counted there.
                Finding.state.notin_(("resolved", "false_positive", "no_fix_available")),
            )
        ).one()
        bands.append(
            {
                "band": band,
                "target_days": days,
                "open": total or 0,
                "late": late or 0,
                "oldest_days": round((now - oldest).total_seconds() / 86400, 1) if oldest else None,
                # Stated rather than implied: no open findings in a band is not
                # compliance, it is an absence of anything to comply about.
                "status": "none_open" if not total else ("late" if late else "within_target"),
            }
        )

    return {
        "bands": bands,
        "targets_are_defaults": True,
        "note": (
            "Targets are configurable defaults. The PRD sets numbers for detection "
            "and accuracy but none for how long a confirmed finding may stay open."
        ),
    }


def all_metrics(session: Session) -> list[dict[str, Any]]:
    return [
        m(session).as_dict()
        for m in (
            detection_latency,
            coverage,
            investigation_quality,
            false_positive_rate,
            mean_time_to_remediation,
            patch_success_rate,
            suppression_durability,
            notification_precision,
            model_cost,
        )
    ]
