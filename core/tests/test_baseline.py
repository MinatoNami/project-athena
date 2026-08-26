"""Baselines.

A baseline separates the situation you inherited from the one you are creating. The
property under test is that it is a *lens* and not a dismissal: nothing is hidden,
the backlog stays countable, and anything that is genuinely an emergency stays in
front of you regardless of how old it is.

A suite that only checked "baselined findings disappear" would pass against a
feature that quietly reproduces the wall of red it exists to prevent.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from athena.db.models import Asset, Component, Finding, Vulnerability
from athena.findings import FindingQuery, query_findings

pytestmark = pytest.mark.usefixtures("engine")


@pytest.fixture
def estate(session):
    asset = Asset(
        kind="host", identity_key=f"b:{uuid.uuid4()}", display_name="inherited",
        tier="production", exposure="internal", last_inventoried_at=datetime.now(UTC),
    )
    session.add(asset)
    session.flush()

    def advisory(suffix, *, kev=False, cvss=5.0):
        v = Vulnerability(
            id=f"CVE-B{suffix}-{uuid.uuid4().hex[:6]}", summary="a flaw", cvss_score=cvss,
            kev=kev, revision=1, content_hash=f"h{suffix}", published_at=datetime.now(UTC),
        )
        session.add(v)
        session.flush()
        return v

    def finding(v, *, seen, band=None, score=None):
        c = Component(ecosystem="deb", name=f"pkg-{uuid.uuid4().hex[:8]}", version="1.0")
        session.add(c)
        session.flush()
        f = Finding(
            group_key=v.id, vulnerability_id=v.id, asset_id=asset.id, component_id=c.id,
            state="discovered", match_method="distro_advisory", match_confidence=0.95,
            fixed_version="1.1", advisory_revision=1, first_seen=seen,
            state_changed_at=seen, risk_band=band, risk_score=score,
            investigation_id=uuid.uuid4() if band else None,
        )
        session.add(f)
        session.flush()
        return f

    long_ago = datetime.now(UTC) - timedelta(days=30)
    old_quiet = advisory("q")
    old_kev = advisory("k", kev=True)
    old_bad = advisory("x", cvss=9.1)
    return {
        "asset": asset,
        "old_quiet": finding(old_quiet, seen=long_ago, band="low", score=4),
        "old_kev": finding(old_kev, seen=long_ago),
        "old_bad": finding(old_bad, seen=long_ago, band="high", score=61),
        "advisory": advisory,
        "finding": finding,
    }


def _visible(session, **kw):
    page = query_findings(session, FindingQuery(limit=200, **kw))
    return {g["vulnerability_id"] for g in page.groups}


def _baseline(session, asset):
    asset.baseline_at = datetime.now(UTC)
    asset.baseline_by = "you"
    session.flush()


# ── the lens ─────────────────────────────────────────────────────────────────


def test_without_a_baseline_everything_is_new(session, estate):
    seen = _visible(session)
    assert estate["old_quiet"].vulnerability_id in seen


def test_a_baseline_takes_the_inherited_backlog_out_of_the_default_view(session, estate):
    _baseline(session, estate["asset"])
    assert estate["old_quiet"].vulnerability_id not in _visible(session)


def test_findings_that_arrive_afterwards_are_new(session, estate):
    _baseline(session, estate["asset"])
    fresh = estate["advisory"]("n")
    estate["finding"](fresh, seen=datetime.now(UTC) + timedelta(seconds=1))
    session.flush()
    assert fresh.id in _visible(session)


def test_the_backlog_stays_countable(session, estate):
    """Held back, never hidden — the same treatment as findings with no fix."""
    _baseline(session, estate["asset"])
    page = query_findings(session, FindingQuery(limit=200))
    assert page.baseline_group_count >= 1
    assert estate["old_quiet"].vulnerability_id in _visible(session, include_baseline=True)


def test_clearing_a_baseline_brings_everything_back(session, estate):
    _baseline(session, estate["asset"])
    assert estate["old_quiet"].vulnerability_id not in _visible(session)
    estate["asset"].baseline_at = None
    session.flush()
    assert estate["old_quiet"].vulnerability_id in _visible(session)


# ── the escape clause, which is the point ────────────────────────────────────


def test_a_known_exploited_finding_is_never_baselined_away(session, estate):
    """An actively exploited flaw is not "state I inherited and accepted". It is an
    emergency that happens to be old."""
    _baseline(session, estate["asset"])
    assert estate["old_kev"].vulnerability_id in _visible(session)


def test_a_high_band_finding_is_never_baselined_away(session, estate):
    _baseline(session, estate["asset"])
    assert estate["old_bad"].vulnerability_id in _visible(session)


def test_an_old_finding_that_becomes_exploited_returns(session, estate):
    """The escape is evaluated on read, so it applies the moment the world changes
    rather than whenever something next happens to run."""
    _baseline(session, estate["asset"])
    quiet = estate["old_quiet"]
    assert quiet.vulnerability_id not in _visible(session)

    session.get(Vulnerability, quiet.vulnerability_id).kev = True
    session.flush()
    assert quiet.vulnerability_id in _visible(session)


def test_an_old_finding_scored_up_returns(session, estate):
    _baseline(session, estate["asset"])
    quiet = estate["old_quiet"]
    quiet.risk_band, quiet.risk_score = "critical", 88
    session.flush()
    assert quiet.vulnerability_id in _visible(session)


# ── it is not a suppression ──────────────────────────────────────────────────


def test_a_baseline_needs_no_reason_and_hides_nothing(session, estate):
    """Deliberately unlike suppression: dismissing something on its merits requires
    an argument, accepting a starting position does not — and one parameter shows
    all of it again."""
    _baseline(session, estate["asset"])
    everything = _visible(session, include_baseline=True)
    for key in ("old_quiet", "old_kev", "old_bad"):
        assert estate[key].vulnerability_id in everything


def test_baselining_one_asset_leaves_others_alone(session, estate):
    other = Asset(
        kind="host", identity_key=f"b:{uuid.uuid4()}", display_name="untouched",
        tier="production", exposure="internal", last_inventoried_at=datetime.now(UTC),
    )
    session.add(other)
    session.flush()
    shared = estate["advisory"]("s")
    component = Component(ecosystem="deb", name=f"p-{uuid.uuid4().hex[:8]}", version="1.0")
    session.add(component)
    session.flush()
    long_ago = datetime.now(UTC) - timedelta(days=30)
    session.add(Finding(
        group_key=shared.id, vulnerability_id=shared.id, asset_id=other.id,
        component_id=component.id, state="discovered", match_method="distro_advisory",
        match_confidence=0.95, fixed_version="1.1", advisory_revision=1,
        first_seen=long_ago, state_changed_at=long_ago,
    ))
    session.flush()

    _baseline(session, estate["asset"])
    assert shared.id in _visible(session), "an unbaselined asset keeps its findings"


def test_unbaselined_assets_are_reported(session, estate):
    """This is what tells the UI whether offering a baseline would achieve anything."""
    before = query_findings(session, FindingQuery(limit=1)).unbaselined_asset_count
    assert before >= 1
    _baseline(session, estate["asset"])
    after = query_findings(session, FindingQuery(limit=1)).unbaselined_asset_count
    assert after == before - 1
