"""Feed parsing for the sources added alongside the OSV adapter.

Pure parsing only — nothing here touches the network. The shapes are taken from the
published formats: EPSS's daily CSV with its model header, and CVE JSON 5.x records
from CISA's Vulnrichment repository.
"""

from __future__ import annotations

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
