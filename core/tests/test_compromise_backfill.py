from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from athena.correlation.engine import correlate_advisory
from athena.db.models import (
    Asset,
    AssetComponent,
    AuditEvent,
    Component,
    Evidence,
    Finding,
    ScanRun,
)
from athena.intel.ingest import upsert_advisory
from athena.intel.osv import parse
from athena.investigation.compromise import ASSESSMENT_KIND
from athena.workers import scheduler

pytestmark = pytest.mark.usefixtures("engine")


def _advisory(record_id: str, package: str) -> dict:
    return {
        "id": record_id,
        "summary": "Malicious code in package",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": package},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }
        ],
        "modified": "2026-11-01T00:00:00Z",
    }


def _install(session, component: Component) -> Asset:
    asset = Asset(kind="host", identity_key=f"h-{uuid.uuid4().hex}", display_name="build-01")
    session.add(asset)
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
    return asset


def _malware_findings(session, count: int) -> list[Finding]:
    mal_id = f"MAL-2026-{uuid.uuid4().int % 10**8}"
    package = f"stealer-{uuid.uuid4().hex[:8]}"
    upsert_advisory(session, parse(_advisory(mal_id, package)))
    component = Component(ecosystem="npm", name=package, version="1.0.0")
    session.add(component)
    session.flush()
    assets = [_install(session, component) for _ in range(count)]
    correlate_advisory(session, mal_id)
    return [
        session.query(Finding).filter_by(vulnerability_id=mal_id, asset_id=asset.id).one()
        for asset in assets
    ]


def _assessments(session, finding: Finding) -> int:
    return session.query(Evidence).filter_by(finding_id=finding.id, kind=ASSESSMENT_KIND).count()


def _opened_audits(session, finding: Finding | None = None) -> int:
    query = session.query(AuditEvent).filter_by(action="COMPROMISE_ASSESSMENT_OPENED")
    if finding is not None:
        query = query.filter_by(subject=f"finding:{finding.id}")
    return query.count()


def _sweep(session) -> None:
    scheduler._sweep_compromise_assessments(session, {}, 10**9)


def test_the_sweep_opens_one_assessment_per_open_malware_finding(session):
    findings = _malware_findings(session, 2)
    assert all(_assessments(session, f) == 0 for f in findings)

    _sweep(session)

    for finding in findings:
        assert _assessments(session, finding) == 1
        assert _opened_audits(session, finding) == 1


def test_the_sweep_skips_closed_and_false_positive_findings(session):
    open_finding, resolved, false_positive = _malware_findings(session, 3)
    resolved.state = "resolved"
    false_positive.state = "false_positive"
    session.flush()

    _sweep(session)

    assert _assessments(session, open_finding) == 1
    assert _assessments(session, resolved) == 0
    assert _assessments(session, false_positive) == 0
    assert _opened_audits(session, resolved) == 0
    assert _opened_audits(session, false_positive) == 0


def test_a_second_sweep_opens_nothing_more(session):
    findings = _malware_findings(session, 2)
    _sweep(session)

    _sweep(session)

    for finding in findings:
        assert _assessments(session, finding) == 1
        assert _opened_audits(session, finding) == 1


def test_the_sweep_waits_out_its_interval(session):
    (finding,) = _malware_findings(session, 1)

    scheduler._sweep_compromise_assessments(session, {"compromise-sweep": 10**9}, 10**9 + 1)

    assert _assessments(session, finding) == 0


def test_the_sweep_opens_at_most_one_batch_per_run(session, monkeypatch):
    _malware_findings(session, 3)
    monkeypatch.setattr(scheduler, "COMPROMISE_SWEEP_BATCH", 2)
    before = _opened_audits(session)

    _sweep(session)

    assert _opened_audits(session) - before == 2
