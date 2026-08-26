"""Success metrics.

What is tested is the honesty, not the arithmetic. A metrics page that prints a
confident zero where it means "nothing has happened yet" is worse than no page:
it is the empty-findings-list-means-clean failure wearing a chart.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from athena.db.models import Asset, Finding, IntelSource, Notification, Suppression, Vulnerability
from athena.metrics import all_metrics, sla_report
from athena.metrics.service import (
    MIN_FOR_RATE,
    Status,
    detection_latency,
    false_positive_rate,
    investigation_quality,
    mean_time_to_remediation,
    notification_precision,
    patch_success_rate,
)

pytestmark = pytest.mark.usefixtures("engine")


def _by_id(session):
    return {m["id"]: m for m in all_metrics(session)}


# ── refusing to guess ────────────────────────────────────────────────────────


def test_unbuilt_features_report_as_unimplemented_never_as_zero(session):
    """A zero and an absence look identical in a chart and mean opposite things."""
    for metric in (mean_time_to_remediation(session), patch_success_rate(session)):
        assert metric.status is Status.NOT_IMPLEMENTED
        assert metric.value is None, "an unbuilt feature must not report a number"
        assert metric.note, "it must say why"


def test_investigation_quality_admits_it_needs_ground_truth(session):
    m = investigation_quality(session)
    assert m.status is Status.UNKNOWN
    assert m.value is None
    assert "ground truth" in m.note or "known independently" in m.note


def test_a_rate_over_a_tiny_denominator_is_refused(session):
    """A percentage computed over four findings is noise wearing a number."""
    m = false_positive_rate(session)
    if m.denominator < MIN_FOR_RATE:
        assert m.value is None
        assert str(m.denominator) in m.note


def test_every_metric_states_its_denominator(session):
    for metric in all_metrics(session):
        assert metric["denominator_label"], f"{metric['id']} has no denominator label"
        if metric["value"] is not None:
            assert metric["denominator"] > 0, f"{metric['id']} reported a value over nothing"


def test_every_metric_says_which_direction_is_good(session):
    """So the UI never has to guess whether a number rising is good news."""
    for metric in all_metrics(session):
        assert isinstance(metric["lower_is_better"], bool)


def test_nothing_reports_a_value_without_a_status(session):
    valid = {str(s) for s in Status}
    for metric in all_metrics(session):
        assert metric["status"] in valid, metric


# ── detection latency measures the watch, not the backfill ───────────────────


def test_latency_ignores_advisories_older_than_the_watch(session):
    """An advisory published two years before this system existed did not take two
    years to detect. Counting it would measure the backfill."""
    source = session.get(IntelSource, "osv") or IntelSource(name="osv")
    source.first_success_at = datetime.now(UTC) - timedelta(days=1)
    source.last_success_at = datetime.now(UTC)
    session.merge(source)
    session.flush()

    asset = Asset(
        kind="host", identity_key=f"m:{uuid.uuid4()}", display_name="h",
        tier="production", exposure="internal", last_inventoried_at=datetime.now(UTC),
    )
    session.add(asset)
    session.flush()

    ancient = Vulnerability(
        id=f"CVE-OLD-{uuid.uuid4().hex[:6]}", summary="s", content_hash="h",
        published_at=datetime.now(UTC) - timedelta(days=900),
    )
    session.add(ancient)
    session.flush()
    from athena.db.models import Component

    component = Component(ecosystem="deb", name=f"p{uuid.uuid4().hex[:6]}", version="1")
    session.add(component)
    session.flush()
    now = datetime.now(UTC)
    session.add(Finding(
        group_key=ancient.id, vulnerability_id=ancient.id, asset_id=asset.id,
        component_id=component.id, state="discovered", match_method="distro_advisory",
        match_confidence=0.95, advisory_revision=1, first_seen=now, state_changed_at=now,
    ))
    session.flush()

    m = detection_latency(session)
    # The ancient advisory contributes nothing, so either the sample stays too small
    # or the median is not measured in years.
    assert m.value is None or m.value < 24 * 30


def test_latency_says_so_when_nothing_has_ever_been_fetched(session):
    session.execute(select(IntelSource))
    for source in session.execute(select(IntelSource)).scalars().all():
        source.first_success_at = None
    session.flush()
    m = detection_latency(session)
    assert m.value is None
    assert m.note


# ── service levels ───────────────────────────────────────────────────────────


def test_no_open_findings_is_reported_as_absence_not_compliance(session):
    """An empty band is not a band meeting its target."""
    report = sla_report(session)
    for band in report["bands"]:
        if band["open"] == 0:
            assert band["status"] == "none_open"


def test_sla_targets_are_declared_as_defaults(session):
    """They are not in the PRD. Pretending otherwise would launder a guess into a
    requirement."""
    report = sla_report(session)
    assert report["targets_are_defaults"] is True
    assert all(b["target_days"] > 0 for b in report["bands"])


def test_a_late_finding_is_counted_late(session):
    asset = Asset(
        kind="host", identity_key=f"m:{uuid.uuid4()}", display_name="late-host",
        tier="production", exposure="internet", last_inventoried_at=datetime.now(UTC),
    )
    vulnerability = Vulnerability(
        id=f"CVE-L-{uuid.uuid4().hex[:6]}", summary="s", content_hash="h",
        published_at=datetime.now(UTC),
    )
    from athena.db.models import Component

    component = Component(ecosystem="deb", name=f"p{uuid.uuid4().hex[:6]}", version="1")
    session.add_all([asset, vulnerability, component])
    session.flush()
    old = datetime.now(UTC) - timedelta(days=400)
    session.add(Finding(
        group_key=vulnerability.id, vulnerability_id=vulnerability.id, asset_id=asset.id,
        component_id=component.id, state="confirmed", match_method="distro_advisory",
        match_confidence=0.95, advisory_revision=1, first_seen=old, state_changed_at=old,
        risk_band="critical", risk_score=90, investigation_id=uuid.uuid4(),
    ))
    session.flush()

    critical = next(b for b in sla_report(session)["bands"] if b["band"] == "critical")
    assert critical["late"] >= 1
    assert critical["status"] == "late"
    assert critical["oldest_days"] >= 399


def test_dismissed_and_unfixable_findings_are_not_late(session):
    """They are not waiting on anybody, and counting them as overdue would make the
    number describe the backlog rather than the work."""
    asset = Asset(
        kind="host", identity_key=f"m:{uuid.uuid4()}", display_name="nofix-host",
        tier="production", exposure="internal", last_inventoried_at=datetime.now(UTC),
    )
    vulnerability = Vulnerability(
        id=f"CVE-F-{uuid.uuid4().hex[:6]}", summary="s", content_hash="h",
        published_at=datetime.now(UTC),
    )
    from athena.db.models import Component

    component = Component(ecosystem="deb", name=f"p{uuid.uuid4().hex[:6]}", version="1")
    session.add_all([asset, vulnerability, component])
    session.flush()
    before = next(b for b in sla_report(session)["bands"] if b["band"] == "critical")["late"]
    old = datetime.now(UTC) - timedelta(days=400)
    session.add(Finding(
        group_key=vulnerability.id, vulnerability_id=vulnerability.id, asset_id=asset.id,
        component_id=component.id, state="no_fix_available", match_method="distro_advisory",
        match_confidence=0.95, advisory_revision=1, first_seen=old, state_changed_at=old,
        risk_band="critical", risk_score=90, investigation_id=uuid.uuid4(),
    ))
    session.flush()
    after = next(b for b in sla_report(session)["bands"] if b["band"] == "critical")["late"]
    assert after == before
