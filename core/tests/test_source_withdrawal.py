from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from athena.correlation.engine import correlate_advisory
from athena.db.models import (
    AffectedRange,
    Asset,
    AssetComponent,
    AuditEvent,
    Component,
    Finding,
    ScanRun,
    Vulnerability,
)
from athena.intel.ingest import upsert_advisory
from athena.intel.osv import parse

pytestmark = pytest.mark.usefixtures("engine")


def _record(record_id: str, cve: str, package: str, *, withdrawn: str | None = None) -> dict:
    record = {
        "id": record_id,
        "aliases": [cve],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}
                ],
            }
        ],
        "modified": "2026-11-01T00:00:00Z",
    }
    if withdrawn:
        record["withdrawn"] = withdrawn
        record["modified"] = withdrawn
    return record


def _installed(session, package: str) -> tuple[Asset, Component]:
    asset = Asset(kind="host", identity_key=f"h-{uuid.uuid4().hex}", display_name="h")
    component = Component(ecosystem="pypi", name=package, version="1.0")
    session.add_all([asset, component])
    session.flush()
    run = ScanRun(
        asset_id=asset.id,
        kind="host",
        tool="test",
        status="succeeded",
        finished_at=datetime.now(UTC),
    )
    session.add(run)
    session.flush()
    session.add(
        AssetComponent(
            asset_id=asset.id,
            component_id=component.id,
            scope="direct",
            observed_at=datetime.now(UTC),
            scan_run_id=run.id,
        )
    )
    session.flush()
    return asset, component


def _finding(session, cve: str, asset: Asset) -> Finding:
    return session.query(Finding).filter_by(vulnerability_id=cve, asset_id=asset.id).one()


def test_a_withdrawn_duplicate_clears_only_its_own_ranges(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    shared, only_ghsa = f"shared-{uuid.uuid4().hex[:6]}", f"ghsa-only-{uuid.uuid4().hex[:6]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-aaaa-bbbb"
    pysec = f"PYSEC-{uuid.uuid4().hex[:8]}"

    ghsa_record = _record(ghsa, cve, shared)
    ghsa_record["affected"].append(_record(ghsa, cve, only_ghsa)["affected"][0])
    upsert_advisory(session, parse(ghsa_record))
    upsert_advisory(session, parse(_record(pysec, cve, shared)))

    shared_host, _ = _installed(session, shared)
    ghsa_host, _ = _installed(session, only_ghsa)
    correlate_advisory(session, cve)
    assert _finding(session, cve, shared_host).state in ("discovered", "no_fix_available")
    assert _finding(session, cve, ghsa_host).state in ("discovered", "no_fix_available")

    revision = session.get(Vulnerability, cve).revision
    withdrawn = parse(_record(ghsa, cve, shared, withdrawn="2026-11-10T00:00:00Z"))
    assert upsert_advisory(session, withdrawn) == "revised"

    vulnerability = session.get(Vulnerability, cve)
    session.refresh(vulnerability)
    assert vulnerability.withdrawn_at is None, "the CVE is not what was withdrawn"
    assert vulnerability.revision == revision + 1, "revised, so it is re-correlated"
    sources = {
        r.source_record for r in session.query(AffectedRange).filter_by(vulnerability_id=cve).all()
    }
    assert sources == {pysec}

    result = correlate_advisory(session, cve)
    assert result["unmatched"] == 1
    assert _finding(session, cve, shared_host).state != "unmatched", "PYSEC still covers it"
    assert _finding(session, cve, ghsa_host).state == "unmatched"

    assert upsert_advisory(session, withdrawn) == "unchanged"


def test_an_unmatched_finding_reopens_when_a_range_returns(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-cccc-dddd"
    upsert_advisory(session, parse(_record(ghsa, cve, package)))
    host, _ = _installed(session, package)
    correlate_advisory(session, cve)

    upsert_advisory(session, parse(_record(ghsa, cve, package, withdrawn="2026-11-10T00:00:00Z")))
    correlate_advisory(session, cve)
    assert _finding(session, cve, host).state == "unmatched"

    upsert_advisory(session, parse(_record(f"PYSEC-{uuid.uuid4().hex[:8]}", cve, package)))
    correlate_advisory(session, cve)
    assert _finding(session, cve, host).state == "discovered"


def test_a_withdrawn_duplicate_never_seen_creates_nothing(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    record = _record(
        f"GHSA-{uuid.uuid4().hex[:4]}-eeee-ffff", cve, "x", withdrawn="2026-11-10T00:00:00Z"
    )
    assert upsert_advisory(session, parse(record)) == "unchanged"
    assert session.get(Vulnerability, cve) is None


def test_an_unmatched_finding_does_not_keep_its_advisory_stale(session):
    from athena.correlation.engine import stale_findings

    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-1111-2222"
    upsert_advisory(session, parse(_record(ghsa, cve, package)))
    host, _ = _installed(session, package)
    correlate_advisory(session, cve)
    upsert_advisory(session, parse(_record(ghsa, cve, package, withdrawn="2026-11-10T00:00:00Z")))
    correlate_advisory(session, cve)
    assert _finding(session, cve, host).state == "unmatched"

    upsert_advisory(session, parse(_record(f"PYSEC-{uuid.uuid4().hex[:8]}", cve, "other-pkg")))
    assert cve in stale_findings(session, limit=100_000)
    correlate_advisory(session, cve)
    assert _finding(session, cve, host).state == "unmatched"
    assert cve not in stale_findings(session, limit=100_000)


def test_a_withdrawn_advisory_leaves_the_stale_sweep_once_looked_at(session):
    from athena.correlation.engine import stale_findings

    cve = f"MAL-2099-{uuid.uuid4().hex[:6]}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    upsert_advisory(session, parse(_record(cve, cve, package) | {"aliases": []}))
    _installed(session, package)
    correlate_advisory(session, cve)
    withdrawn = _record(cve, cve, package, withdrawn="2026-11-10T00:00:00Z") | {"aliases": []}
    upsert_advisory(session, parse(withdrawn))
    assert cve in stale_findings(session, limit=100_000)
    assert correlate_advisory(session, cve)["status"] == "withdrawn"
    assert cve not in stale_findings(session, limit=100_000)


def test_a_bound_that_cannot_be_compared_leaves_the_finding_open(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-3333-4444"
    upsert_advisory(session, parse(_record(ghsa, cve, package)))
    host, _ = _installed(session, package)
    correlate_advisory(session, cve)
    before = _finding(session, cve, host).state
    assert before in ("discovered", "no_fix_available")

    revised = _record(ghsa, cve, package)
    revised["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "0"},
        {"fixed": "not a version"},
    ]
    revised["modified"] = "2026-11-12T00:00:00Z"
    assert upsert_advisory(session, parse(revised)) == "revised"

    result = correlate_advisory(session, cve)
    assert result["unmatched"] == 0
    finding = _finding(session, cve, host)
    assert finding.state == before
    assert finding.match_method == "uncomparable"
    assert finding.match_confidence < 0.5
    assert (finding.fixed_version, finding.fix_channel) == (None, None)
    history = (
        session.query(AuditEvent)
        .filter_by(subject=f"finding:{finding.id}", action="FINDING_MATCH_UNDECIDED")
        .all()
    )
    assert len(history) == 1
    assert history[0].detail["previous"]["fixed_version"] == "2.0"

    correlate_advisory(session, cve)
    assert (
        session.query(AuditEvent)
        .filter_by(subject=f"finding:{finding.id}", action="FINDING_MATCH_UNDECIDED")
        .count()
        == 1
    )


def test_a_withdrawn_malware_report_takes_its_flag_with_it(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    mal = f"MAL-2099-{uuid.uuid4().hex[:6]}"
    report = _record(mal, cve, package) | {"aliases": [], "related": [cve]}
    upsert_advisory(session, parse(report))
    upsert_advisory(session, parse(_record(f"PYSEC-{uuid.uuid4().hex[:8]}", cve, package)))
    vulnerability = session.get(Vulnerability, cve)
    assert vulnerability.malicious is True

    withdrawn = _record(mal, cve, package, withdrawn="2026-11-10T00:00:00Z")
    withdrawn |= {"aliases": [], "related": [cve]}
    assert upsert_advisory(session, parse(withdrawn)) == "revised"

    session.refresh(vulnerability)
    assert vulnerability.malicious is False
    assert vulnerability.withdrawn_at is None, "the CVE itself was not withdrawn"


def test_a_withdrawn_duplicate_leaves_a_malware_flag_another_report_still_holds(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    first, second = (f"MAL-2099-{uuid.uuid4().hex[:6]}" for _ in range(2))
    for mal in (first, second):
        upsert_advisory(
            session, parse(_record(mal, cve, package) | {"aliases": [], "related": [cve]})
        )

    withdrawn = _record(first, cve, package, withdrawn="2026-11-10T00:00:00Z")
    upsert_advisory(session, parse(withdrawn | {"aliases": [], "related": [cve]}))

    vulnerability = session.get(Vulnerability, cve)
    session.refresh(vulnerability)
    assert vulnerability.malicious is True, f"{second} still says it is malware"


def test_a_ghsa_with_a_malware_alias_keeps_the_flag_when_the_report_goes(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    mal = f"MAL-2099-{uuid.uuid4().hex[:6]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-5555-6666"
    upsert_advisory(session, parse(_record(mal, cve, package) | {"aliases": [], "related": [cve]}))
    upsert_advisory(session, parse(_record(ghsa, cve, package) | {"aliases": [cve, mal]}))

    withdrawn = _record(mal, cve, package, withdrawn="2026-11-10T00:00:00Z")
    upsert_advisory(session, parse(withdrawn | {"aliases": [], "related": [cve]}))
    vulnerability = session.get(Vulnerability, cve)
    session.refresh(vulnerability)
    assert vulnerability.malicious is True, f"{ghsa} still says it is malware"

    gone = _record(ghsa, cve, package, withdrawn="2026-11-11T00:00:00Z")
    assert upsert_advisory(session, parse(gone | {"aliases": [cve, mal]})) == "revised"
    session.refresh(vulnerability)
    assert vulnerability.malicious is False


def test_a_source_ingested_before_classification_was_kept_holds_the_flag(session):
    from sqlalchemy import text

    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    mal = f"MAL-2099-{uuid.uuid4().hex[:6]}"
    pysec = f"PYSEC-{uuid.uuid4().hex[:8]}"
    upsert_advisory(session, parse(_record(mal, cve, package) | {"aliases": [], "related": [cve]}))
    upsert_advisory(session, parse(_record(pysec, cve, package)))
    session.execute(
        text("UPDATE advisory_source SET malicious = NULL WHERE source_record = :r"),
        {"r": pysec},
    )

    withdrawn = _record(mal, cve, package, withdrawn="2026-11-10T00:00:00Z")
    upsert_advisory(session, parse(withdrawn | {"aliases": [], "related": [cve]}))
    vulnerability = session.get(Vulnerability, cve)
    session.refresh(vulnerability)
    assert vulnerability.malicious is True


def _classification(session, cve: str, record: str):
    from sqlalchemy import text

    return session.execute(
        text(
            "SELECT malicious FROM advisory_source"
            " WHERE vulnerability_id = :id AND source_record = :rec"
        ),
        {"id": cve, "rec": record},
    ).scalar_one()


def _forget_classification(session, record: str) -> None:
    from sqlalchemy import text

    session.execute(
        text("UPDATE advisory_source SET malicious = NULL WHERE source_record = :r"),
        {"r": record},
    )


def test_an_unknown_source_is_classified_on_its_next_poll_even_unchanged(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    mal = f"MAL-2099-{uuid.uuid4().hex[:6]}"
    pysec = _record(f"PYSEC-{uuid.uuid4().hex[:8]}", cve, package)
    upsert_advisory(session, parse(_record(mal, cve, package) | {"aliases": [], "related": [cve]}))
    upsert_advisory(session, parse(pysec))
    _forget_classification(session, pysec["id"])
    withdrawn = _record(mal, cve, package, withdrawn="2026-11-10T00:00:00Z")
    upsert_advisory(session, parse(withdrawn | {"aliases": [], "related": [cve]}))
    vulnerability = session.get(Vulnerability, cve)
    session.refresh(vulnerability)
    assert vulnerability.malicious is True, "held, while PYSEC is unknown"
    revision = vulnerability.revision

    assert upsert_advisory(session, parse(pysec)) == "revised"
    assert _classification(session, cve, pysec["id"]) is False
    session.refresh(vulnerability)
    assert vulnerability.malicious is False
    assert vulnerability.revision == revision + 1, "revised, so it is re-correlated"
    assert upsert_advisory(session, parse(pysec)) == "unchanged"


def test_classifying_an_unknown_source_keeps_a_flag_it_holds(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    ghsa = _record(f"GHSA-{uuid.uuid4().hex[:4]}-9999-aaaa", cve, package)
    ghsa["aliases"] = [cve, f"MAL-2099-{uuid.uuid4().hex[:6]}"]
    upsert_advisory(session, parse(ghsa))
    _forget_classification(session, ghsa["id"])

    assert upsert_advisory(session, parse(ghsa)) == "unchanged"
    assert _classification(session, cve, ghsa["id"]) is True
    assert session.get(Vulnerability, cve).malicious is True


def test_a_withdrawn_report_polled_unchanged_is_classified_as_nothing(session):
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    mal = f"MAL-2099-{uuid.uuid4().hex[:6]}"
    upsert_advisory(session, parse(_record(mal, cve, package) | {"aliases": [], "related": [cve]}))
    withdrawn = _record(mal, cve, package, withdrawn="2026-11-10T00:00:00Z")
    withdrawn |= {"aliases": [], "related": [cve]}
    upsert_advisory(session, parse(withdrawn))
    _forget_classification(session, mal)

    upsert_advisory(session, parse(withdrawn))
    assert _classification(session, cve, mal) is False
