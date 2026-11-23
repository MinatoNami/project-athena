"""What happens around an investigation while the model is still working.

A verdict takes minutes. In that time correlation can close the finding, a person
can move it on, or the advisory can be revised — and the late verdict must not
undo any of that, nor notify anybody about a question that no longer stands. And
when correlation only closes or reopens findings, connected pages must still hear
about it.
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime

import pytest

from athena.db.models import (
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
from athena.investigation.verdict import Verdict

pytestmark = pytest.mark.usefixtures("engine")


@pytest.fixture
def worker_session(session, monkeypatch):
    """Point the workers' own transactions at the test session, and capture what
    they publish and notify."""

    @contextlib.contextmanager
    def scope():
        yield session
        session.flush()

    published: list[tuple[str, str]] = []
    notified: list[str] = []
    import athena.workers.intel_jobs as intel_jobs
    import athena.workers.investigate as investigate

    for module in (investigate, intel_jobs):
        monkeypatch.setattr(module, "session_scope", scope)
        monkeypatch.setattr(
            module,
            "publish",
            lambda _s, *, topic, subject_id: published.append((topic, subject_id)),
        )
    monkeypatch.setattr(
        investigate,
        "_notify_if_worth_it",
        lambda _s, finding, *_a: notified.append(str(finding.id)),
    )
    return session, published, notified


def _finding(session, *, state: str, revision: int = 2) -> Finding:
    vid = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    session.add(Vulnerability(id=vid, content_hash=f"h{vid}", revision=revision, cvss_score=9.8))
    asset = Asset(
        kind="host",
        identity_key=f"h-{uuid.uuid4().hex}",
        display_name="h",
        tier="production",
        exposure="internet",
    )
    component = Component(ecosystem="pypi", name=f"p-{uuid.uuid4().hex[:6]}", version="1.0")
    session.add_all([asset, component])
    session.flush()
    now = datetime.now(UTC)
    finding = Finding(
        group_key=vid,
        vulnerability_id=vid,
        asset_id=asset.id,
        component_id=component.id,
        state=state,
        match_method="purl_exact_range",
        match_confidence=0.95,
        fixed_version="2.0",
        advisory_revision=revision,
        first_seen=now,
        state_changed_at=now,
    )
    session.add(finding)
    session.flush()
    return finding


APPLICABLE = Verdict(signals={}, verdict="applicable", verdict_confidence=0.9, rationale="r")


def _apply(finding: Finding, *, revision: int):
    from athena.workers.investigate import _apply

    return _apply(
        str(finding.id),
        APPLICABLE,
        model="test",
        investigation_id=None,
        tokens=0,
        from_cache=True,
        advisory_revision=revision,
    )


def _events(session, finding: Finding, action: str) -> int:
    return (
        session.query(AuditEvent).filter_by(subject=f"finding:{finding.id}", action=action).count()
    )


def test_a_late_verdict_does_not_reopen_an_unmatched_finding(worker_session):
    session, _, notified = worker_session
    finding = _finding(session, state="unmatched")

    outcome = _apply(finding, revision=2)

    session.refresh(finding)
    assert outcome["discarded"] is True
    assert finding.state == "unmatched"
    assert notified == [], "nobody is told about a question that no longer stands"
    assert _events(session, finding, "INVESTIGATION_DISCARDED") == 1


def test_a_verdict_for_an_older_revision_is_asked_again(worker_session):
    session, published, notified = worker_session
    finding = _finding(session, state="investigating", revision=3)

    outcome = _apply(finding, revision=2)

    session.refresh(finding)
    assert outcome["discarded"] is True
    assert finding.state == "discovered", "back in the queue, for the current revision"
    assert finding.risk_band is None
    assert notified == []
    assert ("findings", str(finding.id)) in published


def test_a_current_verdict_is_applied(worker_session):
    session, _, notified = worker_session
    finding = _finding(session, state="investigating", revision=2)

    outcome = _apply(finding, revision=2)

    session.refresh(finding)
    assert "discarded" not in outcome
    assert finding.state == "confirmed"
    assert notified == [str(finding.id)]


# ── closure-only correlation runs reach connected pages ──────────────────────


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
        "modified": withdrawn or "2026-11-01T00:00:00Z",
    }
    if withdrawn:
        record["withdrawn"] = withdrawn
    return record


def test_closing_and_reopening_findings_publishes_an_update(worker_session):
    from athena.workers.intel_jobs import correlate_one_advisory

    session, published, _ = worker_session
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-aaaa-bbbb"
    upsert_advisory(session, parse(_record(ghsa, cve, package)))

    asset = Asset(kind="host", identity_key=f"h-{uuid.uuid4().hex}", display_name="h")
    component = Component(ecosystem="pypi", name=package, version="1.0")
    session.add_all([asset, component])
    session.flush()
    run = ScanRun(
        asset_id=asset.id, kind="host", tool="t", status="succeeded", finished_at=datetime.now(UTC)
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
    assert correlate_one_advisory({"vulnerability_id": cve})["created"] == 1

    # Only closes: nothing is created, and the page must still hear about it.
    upsert_advisory(session, parse(_record(ghsa, cve, package, withdrawn="2026-11-10T00:00:00Z")))
    published.clear()
    result = correlate_one_advisory({"vulnerability_id": cve})
    assert result["created"] == 0 and result["unmatched"] == 1
    assert published == [("findings", cve)]

    # Only reopens: likewise.
    upsert_advisory(session, parse(_record(f"PYSEC-{uuid.uuid4().hex[:8]}", cve, package)))
    published.clear()
    result = correlate_one_advisory({"vulnerability_id": cve})
    assert result["created"] == 0 and result["reopened"] == 1
    assert published == [("findings", cve)]
    finding = session.query(Finding).filter_by(vulnerability_id=cve).one()
    assert _events(session, finding, "FINDING_REMATCHED") == 1
