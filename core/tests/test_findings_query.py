"""Server-side findings querying.

These assert the properties that make the list trustworthy rather than exact SQL:
that a page boundary never drops or repeats a group, that a filtered view reports
what it is excluding, and that group-level facets are decided over the group rather
than over whichever row the database happened to reach first.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from athena.db.models import Asset, Component, Finding, Vulnerability
from athena.findings import FindingQuery, query_findings

pytestmark = pytest.mark.usefixtures("engine")


def _asset(session, name, *, tier="production", exposure="internal"):
    asset = Asset(
        kind="host", identity_key=f"q:{name}:{uuid.uuid4()}", display_name=name,
        tier=tier, exposure=exposure, last_inventoried_at=datetime.now(UTC),
    )
    session.add(asset)
    session.flush()
    return asset


def _component(session, name, version="1.0.0"):
    component = Component(
        ecosystem="deb", name=f"{name}-{uuid.uuid4().hex[:8]}", version=version
    )
    session.add(component)
    session.flush()
    return component


def _advisory(session, cve, *, kev=False, cvss=None, severity=None):
    vulnerability = Vulnerability(
        id=cve, summary=f"summary for {cve}", cvss_score=cvss, severity=severity,
        kev=kev, content_hash=f"h-{cve}", published_at=datetime.now(UTC),
    )
    session.add(vulnerability)
    session.flush()
    return vulnerability


def _finding(session, vulnerability, asset, component, *, band=None, score=None, fix="1.0.1"):
    now = datetime.now(UTC)
    finding = Finding(
        group_key=vulnerability.id, vulnerability_id=vulnerability.id, asset_id=asset.id,
        component_id=component.id, state="discovered", match_method="distro_advisory",
        match_confidence=0.95, fixed_version=fix, fix_channel="standard",
        advisory_revision=1, first_seen=now, state_changed_at=now,
        risk_band=band, risk_score=score,
        investigation_id=uuid.uuid4() if band else None,
    )
    session.add(finding)
    session.flush()
    return finding


@pytest.fixture
def estate(session):
    """Four vulnerabilities with deliberately awkward shapes."""
    prod = _asset(session, "edge", exposure="internet")
    lap = _asset(session, "laptop", tier="development", exposure="isolated")

    crit = _advisory(session, f"CVE-A-{uuid.uuid4().hex[:6]}", kev=True, cvss=9.8)
    med = _advisory(session, f"CVE-B-{uuid.uuid4().hex[:6]}", cvss=5.0)
    none = _advisory(session, f"CVE-C-{uuid.uuid4().hex[:6]}", severity="high")
    mixed = _advisory(session, f"CVE-D-{uuid.uuid4().hex[:6]}", cvss=7.1)

    _finding(session, crit, prod, _component(session, "nginx"), band="critical", score=78)
    _finding(session, med, lap, _component(session, "curl"), band="low", score=4)
    _finding(session, none, prod, _component(session, "libxml2"))
    # One group, two instances, only one assessed and only one carrying a fix.
    _finding(session, mixed, prod, _component(session, "tar"), band="medium", score=31)
    _finding(session, mixed, lap, _component(session, "tar"), fix=None)
    session.flush()
    return {"crit": crit, "med": med, "none": none, "mixed": mixed}


def _ids(page):
    return [g["vulnerability_id"] for g in page.groups]


def test_a_group_takes_the_worst_of_its_instances(session, estate):
    page = query_findings(session, FindingQuery(limit=100))
    mixed = next(g for g in page.groups if g["vulnerability_id"] == estate["mixed"].id)
    assert mixed["instance_count"] == 2
    assert mixed["investigated_count"] == 1
    # Not an average: averaging would hide the instance worth looking at.
    assert mixed["worst_band"] == "medium"
    assert mixed["worst_score"] == 31


def test_assessed_groups_rank_above_unassessed(session, estate):
    order = _ids(query_findings(session, FindingQuery(limit=100)))
    assert order.index(estate["crit"].id) < order.index(estate["none"].id)
    # A measured `low` still outranks something nobody has looked at.
    assert order.index(estate["med"].id) < order.index(estate["none"].id)


def test_assessment_is_decided_over_the_group_not_one_row(session, estate):
    """`mixed` has an assessed instance and an unassessed one.

    It belongs in `assessed` and must not also appear in `unassessed`; deciding this
    per row would have put it in both.
    """
    assessed = _ids(query_findings(session, FindingQuery(assessed=True, limit=100)))
    unassessed = _ids(query_findings(session, FindingQuery(assessed=False, limit=100)))
    assert estate["mixed"].id in assessed
    assert estate["mixed"].id not in unassessed
    assert estate["none"].id in unassessed
    assert not set(assessed) & set(unassessed)


def test_fix_availability_is_also_a_group_property(session, estate):
    """`mixed` has one instance with a fix and one without: it is fixable."""
    fixable = _ids(query_findings(session, FindingQuery(has_fix=True, limit=100)))
    assert estate["mixed"].id in fixable


def test_paging_covers_every_group_exactly_once(session, estate):
    everything = _ids(query_findings(session, FindingQuery(limit=100)))
    walked: list[str] = []
    cursor = None
    for _ in range(20):
        page = query_findings(session, FindingQuery(limit=1, cursor=cursor))
        walked.extend(_ids(page))
        cursor = page.next_cursor
        if cursor is None:
            break
    assert walked == everything, "a page boundary dropped, repeated or reordered a group"


def test_paging_holds_under_a_different_sort(session, estate):
    everything = _ids(query_findings(session, FindingQuery(sort="spread", limit=100)))
    walked: list[str] = []
    cursor = None
    for _ in range(20):
        page = query_findings(session, FindingQuery(sort="spread", limit=2, cursor=cursor))
        walked.extend(_ids(page))
        cursor = page.next_cursor
        if cursor is None:
            break
    assert walked == everything


def test_the_last_page_offers_no_cursor(session, estate):
    page = query_findings(session, FindingQuery(limit=100))
    assert page.next_cursor is None


def test_a_mangled_cursor_returns_the_first_page(session, estate):
    """It is an opaque token nobody is meant to construct, so a stale one is not an
    error to show a person — it is a reason to start again from the top."""
    first = _ids(query_findings(session, FindingQuery(limit=2)))
    assert _ids(query_findings(session, FindingQuery(limit=2, cursor="not-a-cursor"))) == first


def test_facets_report_both_what_exists_and_what_survives(session, estate):
    filtered = query_findings(session, FindingQuery(kev=True, limit=100))
    assert filtered.matching_group_count < filtered.group_count
    # The population is unchanged by filtering; only `matching` moves.
    unfiltered = query_findings(session, FindingQuery(limit=100))
    assert filtered.group_count == unfiltered.group_count
    assert filtered.facets["assessed"]["total"] == unfiltered.facets["assessed"]["total"]
    assert filtered.facets["assessed"]["matching"] <= filtered.facets["assessed"]["total"]


def test_band_facets_keep_the_unassessed_in_their_own_bucket(session, estate):
    """The distribution chart reads these directly.

    A group nothing has assessed has no band at all. Folding it into
    `informational` would draw the estate's unknown portion as its mildest, which is
    the one thing rule 1 forbids — so it is counted separately and charted
    separately.
    """
    facets = query_findings(session, FindingQuery(limit=100)).facets
    bands = {name: facets[f"band:{name}"]["total"] for name in
             ("critical", "high", "medium", "low", "informational", "unassessed")}
    assert bands == {"critical": 1, "high": 0, "medium": 1, "low": 1,
                     "informational": 0, "unassessed": 1}
    # Every group lands in exactly one bucket, so the chart's total is the estate.
    assert sum(bands.values()) == query_findings(session, FindingQuery(limit=100)).group_count


def test_instances_obey_the_same_filters_as_the_groups(session, estate):
    """Filtering to internet-facing assets and then listing every asset in the group
    would answer a different question from the one asked."""
    page = query_findings(session, FindingQuery(exposure="internet", limit=100))
    mixed = next(g for g in page.groups if g["vulnerability_id"] == estate["mixed"].id)
    assert mixed["instance_count"] == 1
    assert [i["exposure"] for i in mixed["instances"]] == ["internet"]


def test_search_matches_the_identifier_and_the_summary(session, estate):
    by_id = _ids(query_findings(session, FindingQuery(q=estate["crit"].id, limit=100)))
    assert by_id == [estate["crit"].id]
    by_summary = _ids(
        query_findings(session, FindingQuery(q=f"summary for {estate['med'].id}", limit=100))
    )
    assert by_summary == [estate["med"].id]


def test_instance_totals_describe_the_matching_set_not_the_page(session, estate):
    whole = query_findings(session, FindingQuery(limit=100))
    one = query_findings(session, FindingQuery(limit=1))
    assert one.instance_count == whole.instance_count
    assert one.assessed_count == whole.assessed_count
    assert len(one.groups) == 1


def test_needs_attention_includes_unassessed_known_exploited(session, estate):
    """A known-exploited flaw nobody has looked at is the strongest reason to look.

    A queue defined purely on measured band would rank it nowhere, because it has no
    measured band at all.
    """
    unlooked_kev = _advisory(session, f"CVE-E-{uuid.uuid4().hex[:6]}", kev=True)
    host = _asset(session, "unlooked", exposure="internet")
    _finding(session, unlooked_kev, host, _component(session, "openssl"))
    session.flush()

    queue = _ids(query_findings(session, FindingQuery(needs_attention=True, limit=100)))
    assert unlooked_kev.id in queue, "unassessed KEV must reach the queue"
    assert estate["crit"].id in queue
    # A measured `low` is a decision already taken, not work waiting.
    assert estate["med"].id not in queue
    assert estate["none"].id not in queue


def test_the_queue_count_matches_what_the_queue_returns(session, estate):
    page = query_findings(session, FindingQuery(needs_attention=True, limit=100))
    assert page.matching_group_count == len(page.groups)
    assert page.facets["needs_attention"]["matching"] == len(page.groups)


def test_every_facet_respects_group_level_filters(session, estate):
    """Exposure used to be counted outside the group aggregate, so it never saw the
    HAVING clauses: filtering to an empty population still reported the full estate
    as matching on exposure while every other facet correctly reported none."""
    page = query_findings(session, FindingQuery(assessed=False, limit=100))
    assert page.matching_group_count == page.facets["unassessed"]["matching"]
    for name, counts in page.facets.items():
        assert counts["matching"] <= page.matching_group_count, (
            f"facet {name} claims more matches than the query returned"
        )
        assert counts["matching"] <= counts["total"], name


def test_unassessed_malware_leads_the_queue_and_has_its_own_facet(session, estate):
    """A malicious package nothing has assessed yet has no band, and would otherwise
    rank below every assessed low. It is a compromise in progress, so it leads."""
    laptop = _asset(session, "dev-box", tier="development", exposure="isolated")
    mal = Vulnerability(
        id=f"MAL-2099-{uuid.uuid4().hex[:6]}", summary="Malicious code in colourama",
        content_hash="h-mal", malicious=True, published_at=datetime.now(UTC),
    )
    session.add(mal)
    session.flush()
    _finding(session, mal, laptop, _component(session, "colourama"), fix=None)

    queue = query_findings(session, FindingQuery(needs_attention=True, limit=100))
    assert queue.groups[0]["vulnerability_id"] == mal.id
    assert queue.groups[0]["malicious"] is True
    assert queue.groups[0]["instances"][0]["ssvc"] == "attend"

    only = query_findings(session, FindingQuery(malicious=True, limit=100))
    assert [g["vulnerability_id"] for g in only.groups] == [mal.id]
    assert only.facets["malicious"]["matching"] == 1


def test_a_withdrawn_advisory_stops_ranking(session, estate):
    """Its publisher retracted it. A withdrawn malware report must not go on holding
    the top of the queue at critical."""
    host = _asset(session, "ci-runner")
    retracted = Vulnerability(
        id=f"MAL-2099-{uuid.uuid4().hex[:6]}", summary="Malicious code in fastapi",
        content_hash="h-w", malicious=True, withdrawn_at=datetime.now(UTC),
    )
    session.add(retracted)
    session.flush()
    _finding(session, retracted, host, _component(session, "fastapi"), fix=None)

    page = query_findings(session, FindingQuery(limit=200))
    assert retracted.id not in {g["vulnerability_id"] for g in page.groups}
    assert query_findings(session, FindingQuery(malicious=True, limit=10)).groups == []


def test_the_three_today_tabs_partition_the_estate(session, estate):
    """Needs-you, waiting and cleared must not overlap: a known-exploited critical
    listed under "cleared" tells a reader the opposite of the truth."""
    def ids(**kw):
        return {g["vulnerability_id"] for g in query_findings(
            session, FindingQuery(limit=200, **kw)).groups}

    needs = ids(needs_attention=True)
    cleared = ids(fully_assessed=True, needs_attention=False)
    waiting = ids(fully_assessed=False, needs_attention=False)
    assert not (needs & cleared) and not (needs & waiting) and not (cleared & waiting)
    assert needs | cleared | waiting == ids()

    facets = query_findings(session, FindingQuery(limit=1)).facets
    assert facets["needs_attention"]["total"] == len(needs)
    assert facets["cleared"]["total"] == len(cleared)
    assert facets["waiting"]["total"] == len(waiting)


def test_a_partly_assessed_group_is_waiting_not_cleared(session, estate):
    """One of two instances assessed as low, the other never looked at. "Cleared"
    would say the group was dealt with while half of it is unknown."""
    a = _asset(session, "build-1", tier="development", exposure="isolated")
    b = _asset(session, "build-2", tier="development", exposure="isolated")
    partial = _advisory(session, f"CVE-E-{uuid.uuid4().hex[:6]}", cvss=3.1)
    _finding(session, partial, a, _component(session, "zlib"), band="low", score=3)
    _finding(session, partial, b, _component(session, "zlib"))
    session.flush()

    def ids(**kw):
        return {g["vulnerability_id"] for g in query_findings(
            session, FindingQuery(limit=200, **kw)).groups}

    assert partial.id in ids(fully_assessed=False, needs_attention=False)
    assert partial.id not in ids(fully_assessed=True, needs_attention=False)
    # `assessed` keeps its own meaning — any instance — for the findings filter.
    assert partial.id in ids(assessed=True)
