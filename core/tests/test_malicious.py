"""Malicious packages: the package is the attack, not a flaw awaiting a patch.

OSV carries the OpenSSF malicious-packages feed as `MAL-` records, and before this
they were handled like any advisory — which told the operator a typosquat had "no
fixed version published yet" and scored it as a middling, unrated vulnerability.
Every property asserted here is one of those two failures not recurring.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from athena.intel.ingest import apply_kev, is_malicious, upsert_advisory
from athena.intel.model import NormalisedAdvisory, NormalisedRange, content_hash
from athena.intel.osv import parse
from athena.remediation import RemediationClass, plan_for
from athena.risk import Band, Signals, score

MAL_RECORD = {
    "id": "MAL-2025-4242",
    "summary": "Malicious code in colourama (PyPI)",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "colourama"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        }
    ],
    "modified": "2025-09-16T00:00:00Z",
}


def _sig(**kw) -> Signals:
    defaults = dict(
        malicious=True,
        exposure="isolated",
        tier="development",
        criticality=2,
        service_running=False,
        reachable_in_code="no",
        match_confidence=0.95,
        verdict_confidence=0.9,
        verdict="applicable",
        fix_available=False,
    )
    return Signals(**{**defaults, **kw})


# ── recognising it ───────────────────────────────────────────────────────────


def test_an_osv_mal_record_is_recognised():
    advisory = parse(MAL_RECORD)
    assert advisory is not None
    assert advisory.id == "MAL-2025-4242"
    assert is_malicious(advisory)


def test_a_cve_aliased_to_a_mal_record_is_recognised():
    advisory = NormalisedAdvisory(id="CVE-2025-1", aliases=["MAL-2025-9"], source_record="x")
    assert is_malicious(advisory)


def test_an_ordinary_advisory_is_not_malware():
    advisory = NormalisedAdvisory(id="CVE-2025-1", aliases=["GHSA-aaaa-bbbb-cccc"])
    assert not is_malicious(advisory)


def test_recognition_does_not_move_the_content_hash():
    """Adding the flag must not mark the corpus revised: a revision re-correlates the
    estate and breaks every suppression's premise at once."""
    advisory = parse(MAL_RECORD)
    before = content_hash(advisory)
    advisory.scoring_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert content_hash(advisory) == before


# ── scoring it ───────────────────────────────────────────────────────────────


def test_malware_is_critical_however_isolated_and_unreachable():
    """Every discount in the vulnerability arithmetic presumes a flaw an attacker has
    to reach. Malware's install hook has already run, and it acts outbound."""
    result = score(_sig())
    assert result.band is Band.CRITICAL
    assert any("malicious" in o for o in result.overrides)


def test_the_pinned_factors_are_shown_not_hidden():
    factors = score(_sig()).explain()["factors"]
    for name in ("base", "exploitation", "exposure", "reachability"):
        assert factors[name] == 1.0, name


def test_a_not_applicable_verdict_does_not_close_malware():
    """The model does not hold the authority to dismiss a malware alert."""
    result = score(_sig(verdict="not_applicable"))
    assert result.band is Band.CRITICAL
    assert any("person has to" in o for o in result.overrides)


def test_a_doubtful_match_still_caps_it():
    """ "Named like a malicious package" is not "is the malicious package"."""
    result = score(_sig(match_confidence=0.4))
    assert result.band is Band.MEDIUM


def test_importance_orders_malware_among_itself():
    prod = score(_sig(tier="production", criticality=5))
    dev = score(_sig(tier="development", criticality=1))
    assert prod.value > dev.value
    assert prod.band is dev.band is Band.CRITICAL


# ── fixing it ────────────────────────────────────────────────────────────────


def test_malware_is_removal_and_response_not_an_upgrade():
    plan = plan_for(
        ecosystem="pypi",
        package="colourama",
        installed_version="0.1.6",
        fixed_version=None,
        asset_kind="repository",
        asset_name="acme/api",
        scope="direct",
        fix_channel=None,
        malicious=True,
    )
    assert plan.klass is RemediationClass.MALICIOUS
    assert plan.command is None
    assert "rotate" in plan.summary
    assert "not yet" not in plan.summary
    assert any("credential" in u for u in plan.unknowns)


def test_without_the_flag_the_same_record_still_reads_as_no_fix():
    """The regression this replaces, pinned so the ordering cannot drift back."""
    plan = plan_for(
        ecosystem="pypi",
        package="colourama",
        installed_version="0.1.6",
        fixed_version=None,
        asset_kind="repository",
        asset_name="acme/api",
        scope="direct",
        fix_channel=None,
    )
    assert plan.klass is RemediationClass.NO_FIX


# ── persisting it ────────────────────────────────────────────────────────────


def test_ingest_marks_the_vulnerability_malicious_and_keeps_it(session):
    from athena.db.models import Vulnerability

    mal_id = f"MAL-2025-{uuid.uuid4().hex[:6]}"
    advisory = NormalisedAdvisory(
        id=mal_id,
        source_record=mal_id,
        modified_at=datetime.now(UTC),
        ranges=[NormalisedRange(ecosystem="npm", package="evil-pkg", introduced="0")],
    )
    upsert_advisory(session, advisory)
    session.flush()
    assert session.get(Vulnerability, mal_id).malicious is True

    # A second record for the same id that says nothing of malware is silence, not a
    # retraction.
    quiet = NormalisedAdvisory(
        id=mal_id,
        source_record="OTHER-1",
        modified_at=datetime.now(UTC),
        ranges=[NormalisedRange(ecosystem="npm", package="evil-pkg", introduced="0")],
    )
    upsert_advisory(session, quiet)
    session.flush()
    session.expire_all()
    assert session.get(Vulnerability, mal_id).malicious is True


def test_ingest_computes_the_cvss_score_from_the_vector(session):
    from athena.db.models import Vulnerability

    cve = f"CVE-2099-{uuid.uuid4().hex[:6]}"
    advisory = NormalisedAdvisory(
        id=cve,
        source_record=cve,
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        scoring_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ranges=[NormalisedRange(ecosystem="pypi", package="x", fixed="2")],
    )
    upsert_advisory(session, advisory)
    session.flush()
    assert session.get(Vulnerability, cve).cvss_score == 9.8


def test_kev_records_cisa_dates_and_refreshes_them(session):
    from athena.db.models import Vulnerability

    cve = f"CVE-2099-{uuid.uuid4().hex[:6]}"
    upsert_advisory(
        session,
        NormalisedAdvisory(
            id=cve,
            source_record=cve,
            ranges=[NormalisedRange(ecosystem="pypi", package="x", fixed="2")],
        ),
    )
    session.flush()

    entry = {
        "cveID": cve,
        "dateAdded": "2026-11-01",
        "dueDate": "2026-11-22",
        "knownRansomwareCampaignUse": "Unknown",
    }
    assert apply_kev(session, [entry]) == 1
    session.expire_all()
    v = session.get(Vulnerability, cve)
    assert (v.kev, v.kev_date_added, v.kev_due_date) == (
        True,
        date(2026, 11, 1),
        date(2026, 11, 22),
    )

    # Revised upstream: the page must show CISA's current deadline, and the return
    # value still counts only what is newly known-exploited.
    entry = {**entry, "dueDate": "2026-12-06", "knownRansomwareCampaignUse": "Known"}
    assert apply_kev(session, [entry]) == 0
    session.expire_all()
    v = session.get(Vulnerability, cve)
    assert v.kev_due_date == date(2026, 12, 6)
    assert v.kev_ransomware is True


def test_a_malformed_kev_date_is_absent_not_invented(session):
    from athena.db.models import Vulnerability

    cve = f"CVE-2099-{uuid.uuid4().hex[:6]}"
    upsert_advisory(
        session,
        NormalisedAdvisory(
            id=cve,
            source_record=cve,
            ranges=[NormalisedRange(ecosystem="pypi", package="x", fixed="2")],
        ),
    )
    session.flush()
    apply_kev(session, [{"cveID": cve, "dateAdded": "soon", "dueDate": None}])
    session.expire_all()
    v = session.get(Vulnerability, cve)
    assert v.kev is True
    assert v.kev_date_added is None and v.kev_due_date is None
