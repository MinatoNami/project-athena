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


def test_a_discarded_cached_verdict_is_reported_as_discarded(worker_session, monkeypatch):
    import athena.workers.investigate as investigate

    session, _, notified = worker_session
    finding = _finding(session, state="unmatched")
    monkeypatch.setattr(
        investigate, "_load", lambda _id: {"fingerprint": "f" * 64, "advisory_revision": 2}
    )
    monkeypatch.setattr(investigate, "_lookup_cache", lambda _fp: (APPLICABLE, None, "test"))

    result = investigate.investigate_finding({"finding_id": str(finding.id)})

    assert result["status"] == "discarded"
    assert notified == []


# ── a match the advisory has moved past ──────────────────────────────────────


def test_a_finding_waits_for_correlation_after_a_revision(worker_session):
    """Ingest has revised the advisory; correlation has not re-matched the finding.
    Its facts describe the old range, so neither triage nor investigation reads
    them, and the finding is left as it was."""
    from athena.workers.investigate import _load, _load_for_triage

    session, _, _ = worker_session
    finding = _finding(session, state="discovered", revision=2)
    finding.advisory_revision = 1
    session.flush()

    assert _load(str(finding.id)) is None
    assert _load_for_triage(str(finding.id)) is None
    session.refresh(finding)
    assert finding.state == "discovered"

    finding.advisory_revision = 2  # correlation has caught up
    session.flush()
    context = _load(str(finding.id))
    assert context is not None and context["advisory_revision"] == 2


def test_a_verdict_on_a_match_from_before_the_revision_is_discarded(worker_session):
    session, _, notified = worker_session
    finding = _finding(session, state="investigating", revision=2)
    finding.advisory_revision = 1
    session.flush()

    outcome = _apply(finding, revision=2)

    session.refresh(finding)
    assert outcome["discarded"] is True
    assert finding.state == "discovered"
    assert notified == []


def test_an_investigation_of_an_older_revision_does_not_answer_this_one(worker_session):
    from athena.db.models import InvestigationRecord
    from athena.workers.investigate import _load

    session, _, _ = worker_session
    finding = _finding(session, state="discovered", revision=2)
    earlier = InvestigationRecord(
        fingerprint=uuid.uuid4().hex,
        vulnerability_id=finding.vulnerability_id,
        advisory_revision=1,
        verdict="applicable",
        verdict_confidence=0.9,
        model="m",
        prompt_hash="p",
    )
    session.add(earlier)
    session.flush()
    finding.investigation_id = earlier.id
    session.flush()
    assert _load(str(finding.id)) is not None, "the advisory changed since it was asked"

    earlier.advisory_revision = 2
    finding.state = "discovered"
    session.flush()
    assert _load(str(finding.id)) is None, "already answered for this revision"


def test_a_rematched_finding_is_assessed_again(worker_session):
    """Whatever was concluded answered a match its source retracted. Reopened by a
    range that came back, the finding is a new question and is queued as one."""
    from athena.correlation.engine import correlate_advisory
    from athena.workers.investigate import _load

    session, _, _ = worker_session
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-7777-8888"
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
    correlate_advisory(session, cve)
    finding = session.query(Finding).filter_by(vulnerability_id=cve).one()
    finding.state = "confirmed"
    finding.investigation_id = uuid.uuid4()
    finding.risk_band, finding.risk_score, finding.confidence = "high", 70, 0.9
    finding.triage_disposition = "investigate"
    session.flush()

    upsert_advisory(session, parse(_record(ghsa, cve, package, withdrawn="2026-11-10T00:00:00Z")))
    correlate_advisory(session, cve)
    upsert_advisory(session, parse(_record(f"PYSEC-{uuid.uuid4().hex[:8]}", cve, package)))
    assert correlate_advisory(session, cve)["reopened"] == 1

    session.refresh(finding)
    assert finding.state == "discovered"
    assert finding.investigation_id is None
    assert (finding.risk_band, finding.risk_score, finding.triage_disposition) == (None, None, None)
    assert _load(str(finding.id)) is not None, "eligible to be investigated again"


def _install(session, package: str) -> None:
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


def test_a_match_becoming_undecided_or_decided_again_publishes_an_update(worker_session):
    """Either way the fix a connected page shows has changed — withdrawn, or back —
    though nothing was created, closed or reopened."""
    from athena.workers.intel_jobs import correlate_one_advisory

    session, published, _ = worker_session
    cve = f"CVE-2099-{uuid.uuid4().int % 10**9}"
    package = f"pkg-{uuid.uuid4().hex[:6]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-bbbb-cccc"
    upsert_advisory(session, parse(_record(ghsa, cve, package)))
    _install(session, package)
    assert correlate_one_advisory({"vulnerability_id": cve})["created"] == 1

    # Revised to a bound the installed version cannot be ordered against.
    undecidable = _record(ghsa, cve, package)
    undecidable["affected"][0]["ranges"][0]["events"] = [
        {"introduced": "0"},
        {"fixed": "not a version"},
    ]
    undecidable["modified"] = "2026-11-12T00:00:00Z"
    upsert_advisory(session, parse(undecidable))
    published.clear()
    result = correlate_one_advisory({"vulnerability_id": cve})
    assert result["undecided"] == 1
    assert result["created"] == result["unmatched"] == result["reopened"] == 0
    assert published == [("findings", cve)]

    # Still undecided on the next run: nothing changed, nothing to say.
    published.clear()
    assert correlate_one_advisory({"vulnerability_id": cve})["undecided"] == 0
    assert published == []

    # Corrected: a match again, with its fix back.
    corrected = _record(ghsa, cve, package)
    corrected["modified"] = "2026-11-13T00:00:00Z"
    upsert_advisory(session, parse(corrected))
    published.clear()
    assert correlate_one_advisory({"vulnerability_id": cve})["decided"] == 1
    assert published == [("findings", cve)]
    finding = session.query(Finding).filter_by(vulnerability_id=cve).one()
    assert finding.fixed_version == "2.0"
    assert _events(session, finding, "FINDING_MATCH_DECIDED") == 1
