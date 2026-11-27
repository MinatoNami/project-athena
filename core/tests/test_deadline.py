from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from pydantic import ValidationError

from athena import config
from athena.config import Settings
from athena.risk.deadline import (
    RULE_KEV_DUE_DATE,
    RULE_TABLE,
    Windows,
    configured_windows,
    deadline,
)

NET_TOTAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
NET_PARTIAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
LOCAL_TOTAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
LOCAL_PARTIAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"

SEEN = date(2026, 11, 1)


def _due(*, exposed, kev, vector, cisa=None, kev_added=None):
    return deadline(
        exposure="internet" if exposed else "internal",
        kev=kev,
        kev_date_added=kev_added,
        vector=vector,
        cisa_ssvc=cisa,
        first_seen=SEEN,
    )


@pytest.mark.parametrize(
    ("exposed", "kev", "vector", "days", "triage"),
    [
        (True, True, NET_TOTAL, 3, True),
        (True, True, NET_PARTIAL, 3, False),
        (True, True, LOCAL_TOTAL, 3, True),
        (True, True, LOCAL_PARTIAL, 14, False),
        (True, False, NET_TOTAL, 3, False),
        (True, False, NET_PARTIAL, 14, False),
        (True, False, LOCAL_TOTAL, 14, False),
        (True, False, LOCAL_PARTIAL, 60, False),
        (False, True, NET_TOTAL, 3, True),
        (False, True, NET_PARTIAL, 14, False),
        (False, True, LOCAL_TOTAL, 14, False),
        (False, True, LOCAL_PARTIAL, 14, False),
        (False, False, NET_TOTAL, 60, False),
        (False, False, NET_PARTIAL, 60, False),
        (False, False, LOCAL_TOTAL, None, False),
        (False, False, LOCAL_PARTIAL, None, False),
    ],
)
def test_table_one(exposed, kev, vector, days, triage):
    d = _due(exposed=exposed, kev=kev, vector=vector)
    assert (d.days, d.forensic_triage) == (days, triage)


def test_fix_on_upgrade_has_no_date_and_says_so():
    d = _due(exposed=False, kev=False, vector=LOCAL_TOTAL)
    assert d.due is None
    assert any("upgrade" in n for n in d.notes)


def test_clock_starts_at_detection_when_that_is_earlier():
    d = _due(exposed=True, kev=True, vector=NET_TOTAL, kev_added=date(2026, 11, 10))
    assert d.clock_start == SEEN and d.due == date(2026, 11, 4)


def test_clock_starts_at_kev_addition_when_that_is_earlier():
    d = _due(exposed=True, kev=True, vector=NET_TOTAL, kev_added=date(2026, 10, 20))
    assert d.clock_start == date(2026, 10, 20) and d.due == date(2026, 10, 23)


def test_cisa_assessment_outranks_the_vector():
    cisa = {"automatable": "no", "technical_impact": "partial"}
    d = _due(exposed=True, kev=False, vector=NET_TOTAL, cisa=cisa)
    assert d.days == 60
    assert "Vulnrichment" in d.inputs["automatable"].basis


def test_no_assessment_and_no_vector_takes_cisas_defaults():
    d = _due(exposed=True, kev=False, vector=None)
    assert d.inputs["automatable"].value is False
    assert d.inputs["total_impact"].value is True
    assert d.days == 14
    assert {"automatable", "total_impact"} <= {k for k, v in d.inputs.items() if v.assumed}


def test_unclassified_exposure_is_treated_as_exposed_and_marked():
    d = deadline(
        exposure="unknown",
        kev=False,
        kev_date_added=None,
        vector=NET_TOTAL,
        cisa_ssvc=None,
        first_seen=SEEN,
    )
    assert d.inputs["exposed"].value is True and d.inputs["exposed"].assumed
    assert d.days == 3


def test_as_dict_counts_days_left():
    d = _due(exposed=True, kev=True, vector=NET_TOTAL)
    out = d.as_dict(today=date(2026, 11, 6))
    assert out["days_left"] == -2
    assert out["framework"].startswith("CISA BOD 26-04")


def _kev_due(feed_due, *, kev=True, windows=None):
    return deadline(
        exposure="internet",
        kev=kev,
        kev_date_added=None,
        vector=NET_PARTIAL,
        cisa_ssvc=None,
        first_seen=SEEN,
        kev_due_date=feed_due,
        windows=windows,
    )


def test_an_earlier_kev_due_date_sets_the_deadline():
    d = _kev_due(date(2026, 11, 3))
    assert d.computed_due == date(2026, 11, 4)
    assert d.due == date(2026, 11, 3)
    assert d.due_rule == RULE_KEV_DUE_DATE
    assert any("KEV due date" in n for n in d.notes)
    out = d.as_dict(today=date(2026, 11, 1))
    assert (out["due_rule"], out["kev_due_date"], out["days_left"]) == (
        RULE_KEV_DUE_DATE,
        date(2026, 11, 3),
        2,
    )


def test_an_equal_kev_due_date_leaves_the_table_as_the_rule():
    d = _kev_due(date(2026, 11, 4))
    assert (d.due, d.due_rule) == (date(2026, 11, 4), RULE_TABLE)
    assert d.kev_due_date == date(2026, 11, 4)


def test_a_later_kev_due_date_does_not_extend_the_deadline():
    d = _kev_due(date(2026, 11, 22))
    assert (d.due, d.due_rule) == (date(2026, 11, 4), RULE_TABLE)


def test_a_missing_kev_due_date_leaves_the_table_deadline():
    d = _kev_due(None)
    assert (d.due, d.due_rule, d.kev_due_date) == (date(2026, 11, 4), RULE_TABLE, None)
    assert d.as_dict(today=SEEN)["kev_due_date"] is None


def test_a_due_date_is_ignored_once_the_flaw_is_not_in_kev():
    d = _kev_due(date(2026, 11, 2), kev=False)
    assert (d.due, d.due_rule, d.kev_due_date) == (date(2026, 11, 15), RULE_TABLE, None)


def test_windows_default_to_the_values_in_use_today():
    assert Windows() == Windows(short=3, medium=14, long=60)
    settings = Settings()
    assert (
        settings.deadline_window_short_days,
        settings.deadline_window_medium_days,
        settings.deadline_window_long_days,
    ) == (3, 14, 60)


def test_configured_windows_change_the_table_days():
    windows = Windows(short=2, medium=10, long=30)
    assert _kev_due(None, windows=windows).days == 2
    assert _kev_due(None, kev=False, windows=windows).days == 10
    d = deadline(
        exposure="internet",
        kev=False,
        kev_date_added=None,
        vector=LOCAL_PARTIAL,
        cisa_ssvc=None,
        first_seen=SEEN,
        windows=windows,
    )
    assert (d.days, d.due) == (30, date(2026, 12, 1))


def test_settings_from_the_environment_reach_the_deadline(monkeypatch):
    monkeypatch.setenv("ATHENA_DEADLINE_WINDOW_SHORT_DAYS", "2")
    monkeypatch.setenv("ATHENA_DEADLINE_WINDOW_MEDIUM_DAYS", "7")
    monkeypatch.setenv("ATHENA_DEADLINE_WINDOW_LONG_DAYS", "45")
    monkeypatch.setattr(config, "_settings", None)
    assert configured_windows() == Windows(short=2, medium=7, long=45)
    assert _due(exposed=True, kev=True, vector=NET_TOTAL).days == 2


@pytest.mark.parametrize(
    "overrides",
    [
        {"deadline_window_short_days": 0},
        {"deadline_window_medium_days": -14},
        {"deadline_window_long_days": "soon"},
        {"deadline_window_short_days": 20},
        {"deadline_window_medium_days": 90},
        {"deadline_window_long_days": 10},
    ],
)
def test_settings_reject_windows_that_are_not_positive_or_ordered(overrides):
    with pytest.raises(ValidationError):
        Settings(**overrides)


def test_settings_accept_windows_that_share_a_length():
    settings = Settings(deadline_window_short_days=14, deadline_window_medium_days=14)
    assert settings.deadline_window_short_days == settings.deadline_window_medium_days == 14


@pytest.mark.parametrize(
    "windows",
    [
        {"short": 0},
        {"medium": -1},
        {"long": 2.5},
        {"short": True},
        {"short": 15},
        {"long": 13},
    ],
)
def test_windows_reject_values_that_are_not_positive_or_ordered(windows):
    with pytest.raises(ValueError, match="deadline window"):
        Windows(**windows)


def _kev_estate(session, cve):
    from athena.db.models import Asset, Component, Finding, Vulnerability

    asset = Asset(
        kind="host",
        identity_key=f"d:{uuid.uuid4()}",
        display_name=f"edge-{cve}",
        tier="production",
        exposure="internet",
        last_inventoried_at=datetime.now(UTC),
    )
    component = Component(ecosystem="deb", name=f"lib-{uuid.uuid4().hex[:8]}", version="1.0.0")
    vulnerability = Vulnerability(
        id=cve,
        summary=f"summary for {cve}",
        cvss_vector=NET_PARTIAL,
        kev=False,
        content_hash=f"h-{cve}",
        published_at=datetime.now(UTC),
    )
    session.add_all([asset, component, vulnerability])
    session.flush()
    now = datetime.now(UTC)
    finding = Finding(
        group_key=cve,
        vulnerability_id=cve,
        asset_id=asset.id,
        component_id=component.id,
        state="discovered",
        match_method="distro_advisory",
        match_confidence=0.95,
        fixed_version="1.0.1",
        fix_channel="standard",
        advisory_revision=1,
        first_seen=now,
        state_changed_at=now,
    )
    session.add(finding)
    session.flush()
    return finding, vulnerability, asset


def _listed_instance(session, finding):
    from athena.findings import FindingQuery, query_findings

    page = query_findings(
        session, FindingQuery(asset_id=str(finding.asset_id), include_no_fix=True)
    )
    return next(
        instance
        for group in page.groups
        for instance in group["instances"]
        if instance["finding_id"] == str(finding.id)
    )


def test_a_kev_entry_with_an_earlier_due_date_sets_the_findings_deadline(session):
    from athena.api.routers.findings import _prioritization
    from athena.intel.ingest import apply_kev

    cve = f"CVE-2026-{uuid.uuid4().int % 10**6:06d}"
    finding, vulnerability, asset = _kev_estate(session, cve)
    today = finding.first_seen.date()
    table_due = today + timedelta(days=3)
    feed_due = today + timedelta(days=1)

    entry = {"cveID": cve, "dateAdded": today.isoformat(), "dueDate": feed_due.isoformat()}
    assert apply_kev(session, [entry]) == 1
    session.expire_all()

    listed = _listed_instance(session, finding)
    assert (listed["due"], listed["due_rule"]) == (feed_due, RULE_KEV_DUE_DATE)
    shown = _prioritization(vulnerability, asset, finding)["deadline"]
    assert (shown["due"], shown["due_rule"], shown["computed_due"]) == (
        feed_due,
        RULE_KEV_DUE_DATE,
        table_due,
    )

    later = {**entry, "dueDate": (today + timedelta(days=21)).isoformat()}
    assert apply_kev(session, [later]) == 0
    session.expire_all()

    listed = _listed_instance(session, finding)
    assert (listed["due"], listed["due_rule"]) == (table_due, RULE_TABLE)
    shown = _prioritization(vulnerability, asset, finding)["deadline"]
    assert (shown["due"], shown["due_rule"]) == (table_due, RULE_TABLE)
