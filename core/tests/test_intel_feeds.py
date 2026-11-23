"""Feed parsing for the sources added alongside the OSV adapter.

Pure parsing only — nothing here touches the network. The shapes are taken from the
published formats: EPSS's daily CSV with its model header, and CVE JSON 5.x records
from CISA's Vulnrichment repository.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from athena.intel.feeds import parse_epss_csv, parse_vulnrichment, vulnrichment_url

EPSS_CSV = """#model_version:v2026.06.15,score_date:2026-11-20T12:03:05Z
cve,epss,percentile
CVE-2021-44228,0.999990000,1.000000000
CVE-2026-0001,0.000430000,0.123400000
garbage,line
"""


def test_epss_scores_and_model_are_both_read():
    scores, meta = parse_epss_csv(EPSS_CSV)
    assert scores["CVE-2021-44228"] == (0.99999, 1.0)
    assert scores["CVE-2026-0001"] == (0.00043, 0.1234)
    assert "garbage" not in scores
    assert meta == {"model_version": "v2026.06.15", "score_date": "2026-11-20T12:03:05Z"}


def test_an_epss_file_without_a_header_still_parses():
    scores, meta = parse_epss_csv("cve,epss,percentile\nCVE-1-1,0.5,0.9\n")
    assert scores == {"CVE-1-1": (0.5, 0.9)} and meta == {}


def test_vulnrichment_paths_follow_the_repository_layout():
    assert vulnrichment_url("CVE-2026-40217").endswith("/2026/40xxx/CVE-2026-40217.json")
    assert vulnrichment_url("CVE-2021-44228").endswith("/2021/44xxx/CVE-2021-44228.json")
    assert vulnrichment_url("CVE-2024-0042").endswith("/2024/0xxx/CVE-2024-0042.json")
    assert vulnrichment_url("CVE-2026-133855").endswith("/2026/133xxx/CVE-2026-133855.json")
    assert vulnrichment_url("GHSA-aaaa-bbbb-cccc") is None
    assert vulnrichment_url("CVE-2026-../../etc") is None


def _record(provider="CISA-ADP", options=None):
    return {
        "cveMetadata": {"cveId": "CVE-2026-40217"},
        "containers": {
            "cna": {
                "metrics": [
                    {
                        "other": {
                            "type": "ssvc",
                            "content": {"options": [{"Exploitation": "active"}]},
                        }
                    }
                ]
            },
            "adp": [
                {"providerMetadata": {"shortName": "CVE"}, "references": []},
                {
                    "providerMetadata": {"shortName": provider},
                    "metrics": [
                        {"other": {"type": "kev", "content": {"dateAdded": "2026-10-01"}}},
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "id": "CVE-2026-40217",
                                    "role": "CISA Coordinator",
                                    "version": "2.0.3",
                                    "timestamp": "2026-10-02T14:00:00Z",
                                    "options": options
                                    if options is not None
                                    else [
                                        {"Exploitation": "poc"},
                                        {"Automatable": "yes"},
                                        {"Technical Impact": "total"},
                                    ],
                                },
                            }
                        },
                    ],
                },
            ],
        },
    }


def test_cisas_ssvc_is_read_from_its_own_adp_container():
    out = parse_vulnrichment(_record())
    assert out["exploitation"] == "poc"
    assert out["automatable"] == "yes"
    assert out["technical_impact"] == "total"
    assert out["version"] == "2.0.3"
    assert out["timestamp"].startswith("2026-10-02")


def test_another_providers_opinion_is_not_cisas():
    """The CNA container also says 'active' here; it must not be read as CISA's."""
    assert parse_vulnrichment(_record(provider="SomeVendor")) is None


def test_an_empty_assessment_is_none_not_an_empty_answer():
    assert parse_vulnrichment(_record(options=[])) is None
    assert parse_vulnrichment({}) is None


def test_no_cisa_assessment_is_stored_as_sql_null(session):
    """JSON `null` is NOT NULL to SQL; counting published assessments relied on it."""
    import uuid
    from datetime import UTC, datetime

    from sqlalchemy import text

    from athena.db.models import Vulnerability

    vid = f"CVE-2099-{uuid.uuid4().hex[:6]}"
    session.add(Vulnerability(id=vid, content_hash="h", ssvc_cisa=None,
                              ssvc_checked_at=datetime.now(UTC)))
    session.flush()
    stored = session.execute(
        text("SELECT ssvc_cisa IS NULL FROM vulnerability WHERE id = :id"), {"id": vid}
    ).scalar_one()
    assert stored is True


# ── which CVEs are worth a request to CISA, and the coverage figure over them ──


@pytest.mark.usefixtures("engine")
def test_ssvc_coverage_counts_exactly_the_cves_the_enrichment_job_looks_up(session):
    """The Intelligence page shows "N of M CVEs" for CISA's assessments. M used to
    count CVEs whose findings were all resolved, which the job never looks up, so
    the figure could not reach its total however long the job ran."""
    from athena.api.routers.findings import intel_sources
    from athena.db.models import Asset, Component, Finding, Vulnerability
    from athena.workers.intel_jobs import vulnrichment_due

    def coverage():
        return intel_sources(_=None, session=session)["cisa_ssvc"]["cves_with_open_findings"]

    before = coverage()
    asset = Asset(kind="host", identity_key=f"h-{uuid.uuid4().hex}", display_name="h")
    component = Component(ecosystem="pypi", name=f"p-{uuid.uuid4().hex[:8]}", version="1.0")
    session.add_all([asset, component])
    session.flush()
    now = datetime.now(UTC)
    ids = {}
    for state in ("discovered", "resolved", "false_positive", "withdrawn"):
        vid = f"CVE-2099-{uuid.uuid4().int % 10**9}"
        session.add(
            Vulnerability(
                id=vid,
                content_hash=f"h{vid}",
                withdrawn_at=datetime.now(UTC) if state == "withdrawn" else None,
            )
        )
        session.flush()
        session.add(
            Finding(
                group_key=vid,
                vulnerability_id=vid,
                asset_id=asset.id,
                component_id=component.id,
                state="discovered" if state == "withdrawn" else state,
                match_method="purl_exact_range",
                match_confidence=0.95,
                advisory_revision=1,
                first_seen=now,
                state_changed_at=now,
            )
        )
        ids[state] = vid
    session.flush()

    due = set(vulnrichment_due(session, limit=100_000))
    assert ids["discovered"] in due
    assert ids["resolved"] not in due and ids["false_positive"] not in due
    assert ids["withdrawn"] not in due, "a withdrawn CVE with an open finding is not asked about"
    assert coverage() - before == 1, "the denominator is the set the job works through"


@pytest.mark.usefixtures("engine")
def test_the_page_names_the_vector_the_score_was_computed_from(session):
    """A record listing v4.0 before v3.1 keeps the v4 vector as `cvss_vector` and
    computes the score from the v3.1. Compared with the v4 vector, the score read as
    the advisory's own published number."""
    from types import SimpleNamespace

    from athena.api.routers.findings import _prioritization
    from athena.db.models import Vulnerability
    from athena.intel.ingest import upsert_advisory
    from athena.intel.osv import parse

    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    advisory = parse(
        {
            "id": f"GHSA-{uuid.uuid4().hex[:4]}-aaaa-bbbb",
            "aliases": [cve],
            "severity": [{"type": "CVSS_V4", "score": v4}, {"type": "CVSS_V3", "score": v31}],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "example"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}
                    ],
                }
            ],
            "modified": "2026-11-01T00:00:00Z",
        }
    )
    assert advisory is not None
    upsert_advisory(session, advisory)
    vulnerability = session.get(Vulnerability, cve)
    assert vulnerability.cvss_score == 9.8
    assert vulnerability.cvss_scoring_vector == v31

    asset = SimpleNamespace(tier="production", criticality=3, exposure="internet")
    finding = SimpleNamespace(first_seen=datetime.now(UTC))
    shown = _prioritization(vulnerability, asset, finding)["cvss"]
    assert shown["computed_from_vector"] is True
    assert shown["vector"] == v31 and shown["version"] == "3.1"
    assert shown["published_vector"] == vulnerability.cvss_vector
