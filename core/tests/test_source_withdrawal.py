"""One source withdrawn under a CVE other sources still describe.

GitHub withdraws duplicate GHSAs routinely. The withdrawal is that record's own: its
ranges must stop matching, findings only it supported must close, and the CVE — with
every other source's ranges and findings — must stand.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from athena.correlation.engine import correlate_advisory
from athena.db.models import (
    AffectedRange,
    Asset,
    AssetComponent,
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

    # The GHSA covers two packages; PYSEC independently covers one of them.
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

    # Polled again, the same withdrawn record changes nothing further.
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
    """A later revision that still does not cover the package must not leave the
    advisory in the hourly stale sweep for good."""
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

    # Another source revises the CVE, for a package this host does not have.
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
    # Withdrawal is itself a revision.
    withdrawn = _record(cve, cve, package, withdrawn="2026-11-10T00:00:00Z") | {"aliases": []}
    upsert_advisory(session, parse(withdrawn))
    assert cve in stale_findings(session, limit=100_000)
    assert correlate_advisory(session, cve)["status"] == "withdrawn"
    assert cve not in stale_findings(session, limit=100_000)
