"""Suppression.

The property under test throughout is the difference between suppressing and
hiding: a suppression records what it rested on, and stops applying when that stops
holding. A test suite that only checked "suppressed findings disappear" would pass
against a feature that is simply a delete button.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from athena.db.models import Asset, Component, Finding, Suppression, Vulnerability
from athena.findings import FindingQuery, query_findings
from athena.suppression import (
    SuppressionError,
    create_suppression,
    review_suppressions,
    revoke_suppression,
)

pytestmark = pytest.mark.usefixtures("engine")


@pytest.fixture
def finding(session):
    asset = Asset(
        kind="host", identity_key=f"s:{uuid.uuid4()}", display_name="edge",
        tier="production", exposure="isolated", last_inventoried_at=datetime.now(UTC),
    )
    component = Component(ecosystem="deb", name=f"nginx-{uuid.uuid4().hex[:8]}", version="1.0")
    vulnerability = Vulnerability(
        id=f"CVE-S-{uuid.uuid4().hex[:8]}", summary="a flaw", cvss_score=7.0,
        kev=False, revision=1, content_hash="h", published_at=datetime.now(UTC),
    )
    session.add_all([asset, component, vulnerability])
    session.flush()
    now = datetime.now(UTC)
    f = Finding(
        group_key=vulnerability.id, vulnerability_id=vulnerability.id, asset_id=asset.id,
        component_id=component.id, state="discovered", match_method="distro_advisory",
        match_confidence=0.95, fixed_version=None, advisory_revision=1,
        first_seen=now, state_changed_at=now,
    )
    session.add(f)
    session.flush()
    return f


def _visible(session, **kw):
    page = query_findings(session, FindingQuery(limit=200, **kw))
    return {g["vulnerability_id"] for g in page.groups}


# ── the basics ───────────────────────────────────────────────────────────────


def test_a_suppressed_finding_leaves_the_default_list(session, finding):
    assert finding.vulnerability_id in _visible(session)
    create_suppression(
        session, finding=finding, reason_code="not_applicable",
        reason="the vulnerable module is not compiled in", actor="you",
    )
    session.flush()
    assert finding.vulnerability_id not in _visible(session)


def test_suppressed_findings_are_counted_not_hidden(session, finding):
    create_suppression(
        session, finding=finding, reason_code="not_applicable",
        reason="the vulnerable module is not compiled in", actor="you",
    )
    session.flush()
    page = query_findings(session, FindingQuery(limit=200))
    assert page.suppressed_group_count >= 1
    assert finding.vulnerability_id in _visible(session, include_suppressed=True)


def test_revoking_puts_the_finding_back_and_keeps_the_record(session, finding):
    s = create_suppression(
        session, finding=finding, reason_code="false_positive",
        reason="this matched the wrong package entirely", actor="you",
    )
    session.flush()
    revoke_suppression(session, suppression=s, actor="you")
    session.flush()
    assert finding.vulnerability_id in _visible(session)
    # Kept, not deleted: who changed their mind is part of the trail.
    assert session.get(Suppression, s.id) is not None
    assert session.get(Suppression, s.id).revoked_by == "you"


def test_an_expired_suppression_stops_applying_without_a_sweep(session, finding):
    s = create_suppression(
        session, finding=finding, reason_code="fix_scheduled",
        reason="patching in next week's maintenance window", actor="you",
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    session.flush()
    assert finding.vulnerability_id not in _visible(session)

    # Expiry is evaluated in the query, so it takes effect on time rather than
    # whenever something next happens to run.
    s.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    session.flush()
    assert finding.vulnerability_id in _visible(session)


# ── what makes it a suppression rather than a delete ─────────────────────────


def test_exposure_growing_invalidates_the_dismissal(session, finding):
    """The case the whole mechanism exists for: an isolated service becomes exposed."""
    create_suppression(
        session, finding=finding, reason_code="compensating_control",
        reason="not reachable from anywhere off this host", actor="you",
    )
    session.flush()
    assert finding.vulnerability_id not in _visible(session)

    asset = session.get(Asset, finding.asset_id)
    asset.exposure = "internet"
    session.flush()

    outcome = review_suppressions(session)
    session.flush()
    assert outcome["invalidated"] == 1
    assert finding.vulnerability_id in _visible(session)

    dead = session.execute(select(Suppression)).scalars().first()
    assert "isolated to internet" in dead.invalidated_reason


def test_becoming_known_exploited_invalidates_the_dismissal(session, finding):
    create_suppression(
        session, finding=finding, reason_code="accepted_risk",
        reason="low likelihood, revisit next quarter", actor="you",
        expires_at=datetime.now(UTC) + timedelta(days=90),
    )
    session.flush()
    session.get(Vulnerability, finding.vulnerability_id).kev = True
    session.flush()

    assert review_suppressions(session)["invalidated"] == 1
    session.flush()
    assert finding.vulnerability_id in _visible(session)


def test_the_situation_improving_does_not_invalidate(session, finding):
    """Reinstating findings because things got better would train people to ignore
    the mechanism, which is worse than not having it."""
    create_suppression(
        session, finding=finding, reason_code="accepted_risk",
        reason="acceptable while this stays internal", actor="you",
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    session.flush()
    asset = session.get(Asset, finding.asset_id)
    asset.tier = "development"
    session.flush()

    assert review_suppressions(session)["invalidated"] == 0
    assert finding.vulnerability_id not in _visible(session)


# ── refusals ─────────────────────────────────────────────────────────────────


def test_accepted_risk_must_carry_an_expiry(session, finding):
    """It is a statement about appetite, not about the world, so nothing else will
    ever prompt a review of it."""
    with pytest.raises(SuppressionError, match="expiry"):
        create_suppression(
            session, finding=finding, reason_code="accepted_risk",
            reason="we are fine with this for now", actor="you",
        )


def test_a_reason_nobody_could_act_on_is_refused(session, finding):
    with pytest.raises(SuppressionError, match="eight characters"):
        create_suppression(
            session, finding=finding, reason_code="not_applicable", reason="n/a", actor="you",
        )


def test_an_expiry_in_the_past_is_refused(session, finding):
    with pytest.raises(SuppressionError, match="past"):
        create_suppression(
            session, finding=finding, reason_code="fix_scheduled",
            reason="scheduled for the window last month", actor="you",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )


def test_suppressing_the_same_scope_twice_is_refused(session, finding):
    create_suppression(
        session, finding=finding, reason_code="not_applicable",
        reason="the vulnerable module is not compiled in", actor="you",
    )
    session.flush()
    with pytest.raises(SuppressionError, match="already covers"):
        create_suppression(
            session, finding=finding, reason_code="accepted_risk",
            reason="a second opinion on the same thing", actor="you",
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )


# ── scope ────────────────────────────────────────────────────────────────────


def test_a_broader_scope_covers_findings_created_later(session, finding):
    """Correlation recreates findings, so a suppression keyed on a finding id would
    evaporate on the next scan. Scope is semantic instead."""
    create_suppression(
        session, finding=finding, reason_code="false_positive",
        reason="this advisory does not describe our build", scope="everywhere", actor="you",
    )
    session.flush()

    other = Asset(
        kind="host", identity_key=f"s:{uuid.uuid4()}", display_name="another",
        tier="production", exposure="internal", last_inventoried_at=datetime.now(UTC),
    )
    session.add(other)
    session.flush()
    now = datetime.now(UTC)
    session.add(Finding(
        group_key=finding.vulnerability_id, vulnerability_id=finding.vulnerability_id,
        asset_id=other.id, component_id=finding.component_id, state="discovered",
        match_method="distro_advisory", match_confidence=0.95, advisory_revision=1,
        first_seen=now, state_changed_at=now,
    ))
    session.flush()
    assert finding.vulnerability_id not in _visible(session)


def test_counts_are_not_inflated_when_two_suppressions_overlap(session, finding):
    """A finding can be covered by an exact suppression and a broad one at once. A
    join would return it twice and double every instance count that touched it."""
    create_suppression(
        session, finding=finding, reason_code="not_applicable",
        reason="the vulnerable module is not compiled in", scope="everywhere", actor="you",
    )
    session.flush()
    before = query_findings(session, FindingQuery(limit=200, include_suppressed=True))
    counts = {g["vulnerability_id"]: g["instance_count"] for g in before.groups}

    session.add(Suppression(
        vulnerability_id=finding.vulnerability_id, asset_id=finding.asset_id,
        component_id=finding.component_id, reason_code="accepted_risk",
        reason="also accepted on this host specifically", created_by="you",
        premise={}, expires_at=datetime.now(UTC) + timedelta(days=1),
    ))
    session.flush()

    after = query_findings(session, FindingQuery(limit=200, include_suppressed=True))
    assert {g["vulnerability_id"]: g["instance_count"] for g in after.groups} == counts
