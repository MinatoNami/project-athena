from __future__ import annotations

import uuid
from contextlib import contextmanager
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
    Notification,
    ScanRun,
)
from athena.intel.ingest import upsert_advisory
from athena.intel.osv import parse
from athena.investigation.compromise import (
    ANSWER_KIND,
    ASSESSMENT_KIND,
    AssessmentError,
    answer_compromise_assessment,
    compromise_assessment_of,
    open_compromise_assessments,
)
from athena.notify.service import URGENT
from athena.workers import intel_jobs

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


def _installed(session, package: str) -> Asset:
    asset = Asset(kind="host", identity_key=f"h-{uuid.uuid4().hex}", display_name="build-01")
    component = Component(ecosystem="npm", name=package, version="1.0.0")
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
    return asset


def _correlate(session, monkeypatch, vulnerability_id: str) -> dict:
    @contextmanager
    def same_session():
        yield session
        session.flush()

    monkeypatch.setattr(intel_jobs, "session_scope", same_session)
    return intel_jobs.correlate_one_advisory({"vulnerability_id": vulnerability_id})


def _finding(session, vulnerability_id: str, asset: Asset) -> Finding:
    return (
        session.query(Finding).filter_by(vulnerability_id=vulnerability_id, asset_id=asset.id).one()
    )


def _assessments(session, finding: Finding) -> list[Evidence]:
    return session.query(Evidence).filter_by(finding_id=finding.id, kind=ASSESSMENT_KIND).all()


def _notifications(session, finding: Finding) -> list[Notification]:
    return (
        session.query(Notification)
        .filter_by(group_key=f"finding.compromise_assessment:{finding.id}")
        .all()
    )


def _audited(session, finding: Finding, action: str) -> list[AuditEvent]:
    return session.query(AuditEvent).filter_by(subject=f"finding:{finding.id}", action=action).all()


def _malware(session) -> tuple[str, Asset]:
    mal_id = f"MAL-2026-{uuid.uuid4().int % 10**8}"
    package = f"stealer-{uuid.uuid4().hex[:8]}"
    upsert_advisory(session, parse(_advisory(mal_id, package)))
    return mal_id, _installed(session, package)


def test_a_malware_match_opens_one_assessment_with_a_top_priority_notification(
    session, monkeypatch
):
    mal_id, asset = _malware(session)

    result = _correlate(session, monkeypatch, mal_id)
    finding = _finding(session, mal_id, asset)

    assert result["created"] == 1
    assert result["compromise_assessments"] == 1
    assert len(_assessments(session, finding)) == 1
    notifications = _notifications(session, finding)
    assert len(notifications) == 1
    assert notifications[0].urgency == URGENT
    assert notifications[0].kind == "finding.compromise_assessment"
    assert len(_audited(session, finding, "COMPROMISE_ASSESSMENT_OPENED")) == 1

    assessment = compromise_assessment_of(session, finding)
    assert assessment["status"] == "open"
    assert assessment["still_open"] == ["code_ran", "credentials", "network_reach"]


def test_the_assessment_is_opened_once_across_rematches(session, monkeypatch):
    mal_id, asset = _malware(session)
    _correlate(session, monkeypatch, mal_id)
    finding = _finding(session, mal_id, asset)

    finding.state = "unmatched"
    session.flush()
    result = _correlate(session, monkeypatch, mal_id)
    assert result["reopened"] == 1
    assert len(_audited(session, finding, "FINDING_REMATCHED")) == 1

    _correlate(session, monkeypatch, mal_id)
    assert open_compromise_assessments(session, vulnerability_id=mal_id) == 0

    assert len(_assessments(session, finding)) == 1
    assert len(_notifications(session, finding)) == 1
    assert _notifications(session, finding)[0].occurrence_count == 1
    assert len(_audited(session, finding, "COMPROMISE_ASSESSMENT_OPENED")) == 1


def test_a_rematch_opens_the_assessment_a_finding_never_had(session):
    mal_id, asset = _malware(session)
    correlate_advisory(session, mal_id)
    finding = _finding(session, mal_id, asset)
    assert _assessments(session, finding) == []

    finding.state = "unmatched"
    session.flush()
    assert open_compromise_assessments(session, vulnerability_id=mal_id) == 0

    assert correlate_advisory(session, mal_id)["reopened"] == 1
    assert open_compromise_assessments(session, vulnerability_id=mal_id) == 1
    assert len(_assessments(session, finding)) == 1


def test_an_ordinary_vulnerability_opens_no_assessment(session, monkeypatch):
    package = f"lib-{uuid.uuid4().hex[:8]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-aaaa-bbbb"
    record = _advisory(ghsa, package)
    record["affected"][0]["ranges"][0]["events"].append({"fixed": "2.0.0"})
    upsert_advisory(session, parse(record))
    asset = _installed(session, package)

    result = _correlate(session, monkeypatch, ghsa)
    finding = _finding(session, ghsa, asset)

    assert result["created"] == 1
    assert "compromise_assessments" not in result
    assert _assessments(session, finding) == []
    assert _notifications(session, finding) == []
    assert compromise_assessment_of(session, finding) is None


def test_answers_become_evidence_and_leave_the_finding_where_it_was(session, monkeypatch):
    mal_id, asset = _malware(session)
    _correlate(session, monkeypatch, mal_id)
    finding = _finding(session, mal_id, asset)
    state, band, score = finding.state, finding.risk_band, finding.risk_score

    assessment = answer_compromise_assessment(
        session, finding, {"code_ran": "installed", "credentials": "yes"}, actor="user:alice"
    )

    assert assessment["still_open"] == ["network_reach"]
    assert assessment["status"] == "open"
    answers = session.query(Evidence).filter_by(finding_id=finding.id, kind=ANSWER_KIND).all()
    assert {a.value["question"]: a.value["answer"] for a in answers} == {
        "code_ran": "installed",
        "credentials": "yes",
    }
    assert all(a.source_ref == "user:alice" for a in answers)
    assert len(_audited(session, finding, "COMPROMISE_ASSESSMENT_ANSWERED")) == 1
    assert (finding.state, finding.risk_band, finding.risk_score) == (state, band, score)

    assessment = answer_compromise_assessment(
        session, finding, {"network_reach": "internet", "credentials": "no"}, actor="user:bob"
    )
    assert assessment["status"] == "answered"
    assert assessment["still_open"] == []
    answers = session.query(Evidence).filter_by(finding_id=finding.id, kind=ANSWER_KIND).all()
    assert len(answers) == 3
    latest = {q["key"]: q["answer"] for q in assessment["questions"]}
    assert latest == {"code_ran": "installed", "credentials": "no", "network_reach": "internet"}
    audit = _audited(session, finding, "COMPROMISE_ASSESSMENT_ANSWERED")
    assert any(e.detail.get("replaced") == {"credentials": "yes"} for e in audit)
    assert finding.state == state


def test_an_answer_outside_the_questions_is_refused(session, monkeypatch):
    mal_id, asset = _malware(session)
    _correlate(session, monkeypatch, mal_id)
    finding = _finding(session, mal_id, asset)

    with pytest.raises(AssessmentError):
        answer_compromise_assessment(session, finding, {"code_ran": "maybe"}, actor="user:a")
    with pytest.raises(AssessmentError):
        answer_compromise_assessment(session, finding, {"mood": "yes"}, actor="user:a")
    with pytest.raises(AssessmentError):
        answer_compromise_assessment(session, finding, {}, actor="user:a")
    assert session.query(Evidence).filter_by(finding_id=finding.id, kind=ANSWER_KIND).count() == 0


def test_a_finding_without_an_assessment_cannot_be_answered(session):
    package = f"lib-{uuid.uuid4().hex[:8]}"
    ghsa = f"GHSA-{uuid.uuid4().hex[:4]}-cccc-dddd"
    record = _advisory(ghsa, package)
    record["affected"][0]["ranges"][0]["events"].append({"fixed": "2.0.0"})
    upsert_advisory(session, parse(record))
    asset = _installed(session, package)
    correlate_advisory(session, ghsa)

    with pytest.raises(AssessmentError):
        answer_compromise_assessment(
            session, _finding(session, ghsa, asset), {"credentials": "no"}, actor="user:a"
        )


def test_the_api_records_answers_and_lists_only_what_is_still_open(session, monkeypatch):
    from fastapi import HTTPException

    from athena.api.routers.findings import CompromiseAnswers, answer_compromise, get_finding

    class Principal:
        actor = "user:carol"

    mal_id, asset = _malware(session)
    _correlate(session, monkeypatch, mal_id)
    finding = _finding(session, mal_id, asset)

    shown = get_finding(str(finding.id), _=Principal(), session=session)
    assert shown["compromise_assessment"]["still_open"] == [
        "code_ran",
        "credentials",
        "network_reach",
    ]

    answered = answer_compromise(
        str(finding.id),
        CompromiseAnswers(answers={"code_ran": "declared_only"}),
        principal=Principal(),
        session=session,
    )
    assert answered["still_open"] == ["credentials", "network_reach"]
    shown = get_finding(str(finding.id), _=Principal(), session=session)
    assert any(
        e["kind"] == ANSWER_KIND and e["source_ref"] == "user:carol" for e in shown["evidence"]
    )

    with pytest.raises(HTTPException) as refused:
        answer_compromise(
            str(finding.id),
            CompromiseAnswers(answers={"code_ran": "perhaps"}),
            principal=Principal(),
            session=session,
        )
    assert refused.value.status_code == 422

    with pytest.raises(HTTPException) as missing:
        answer_compromise(
            str(uuid.uuid4()),
            CompromiseAnswers(answers={"code_ran": "installed"}),
            principal=Principal(),
            session=session,
        )
    assert missing.value.status_code == 404
