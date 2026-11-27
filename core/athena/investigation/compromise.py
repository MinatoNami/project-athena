from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.audit import record
from athena.db.models import Asset, Evidence, Finding, Vulnerability
from athena.notify import emit
from athena.notify.service import URGENT
from athena.queue import publish

ASSESSMENT_KIND = "compromise_assessment"
ANSWER_KIND = "compromise_answer"

NOT_ASSESSED_STATES = ("unmatched", "false_positive")


@dataclass(frozen=True)
class Question:
    key: str
    prompt: str
    options: tuple[tuple[str, str], ...]


QUESTIONS: tuple[Question, ...] = (
    Question(
        key="code_ran",
        prompt=(
            "Did the package's install or startup code run on this asset? Installed "
            "means it ran; declared in a manifest but never installed means it did not."
        ),
        options=(
            ("installed", "Installed, so its install or startup code ran"),
            ("declared_only", "Only declared in a manifest, never installed"),
            ("unknown", "Not known"),
        ),
    ),
    Question(
        key="credentials",
        prompt="Does this asset hold credentials, tokens or CI secrets?",
        options=(
            ("yes", "Yes"),
            ("no", "No"),
            ("unknown", "Not known"),
        ),
    ),
    Question(
        key="network_reach",
        prompt="What network can this asset reach?",
        options=(
            ("internet", "The internet"),
            ("internal", "Internal networks only"),
            ("isolated", "Nothing beyond itself"),
            ("unknown", "Not known"),
        ),
    ),
)

QUESTION_BY_KEY = {q.key: q for q in QUESTIONS}


class AssessmentError(ValueError):
    pass


def _hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _assessment_of(session: Session, finding_id: Any) -> Evidence | None:
    return session.execute(
        select(Evidence)
        .where(Evidence.finding_id == finding_id, Evidence.kind == ASSESSMENT_KIND)
        .order_by(Evidence.observed_at)
        .limit(1)
    ).scalar_one_or_none()


def _answers_of(session: Session, finding_id: Any) -> dict[str, Evidence]:
    rows = (
        session.execute(
            select(Evidence)
            .where(Evidence.finding_id == finding_id, Evidence.kind == ANSWER_KIND)
            .order_by(Evidence.observed_at)
        )
        .scalars()
        .all()
    )
    return {row.value.get("question"): row for row in rows if row.value.get("question")}


def open_compromise_assessments(
    session: Session,
    *,
    vulnerability_id: str | None = None,
    asset_id: Any = None,
    states: tuple[str, ...] | None = None,
    limit: int | None = None,
) -> int:
    candidates = (
        select(Finding.id)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(
            Vulnerability.malicious.is_(True),
            Finding.state.notin_(NOT_ASSESSED_STATES),
            ~select(Evidence.id)
            .where(Evidence.finding_id == Finding.id, Evidence.kind == ASSESSMENT_KIND)
            .exists(),
        )
    )
    if vulnerability_id is not None:
        candidates = candidates.where(Finding.vulnerability_id == vulnerability_id)
    if asset_id is not None:
        candidates = candidates.where(Finding.asset_id == asset_id)
    if states is not None:
        candidates = candidates.where(Finding.state.in_(states))
    if limit is not None:
        candidates = candidates.order_by(Finding.first_seen, Finding.id).limit(limit)

    opened = 0
    for finding_id in session.execute(candidates).scalars().all():
        if _open_one(session, finding_id):
            opened += 1
    return opened


def _open_one(session: Session, finding_id: Any) -> bool:
    finding = session.execute(
        select(Finding).where(Finding.id == finding_id).with_for_update()
    ).scalar_one_or_none()
    if finding is None or finding.state in NOT_ASSESSED_STATES:
        return False
    if _assessment_of(session, finding.id) is not None:
        return False

    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    if vulnerability is None or not vulnerability.malicious:
        return False
    asset = session.get(Asset, finding.asset_id)

    value = {
        "status": "open",
        "vulnerability_id": vulnerability.id,
        "advisory_revision": finding.advisory_revision,
        "questions": [q.key for q in QUESTIONS],
    }
    session.add(
        Evidence(
            finding_id=finding.id,
            kind=ASSESSMENT_KIND,
            claim=(
                "Compromise assessment opened: removing a malicious package does not "
                "undo code that ran at install or startup."
            ),
            value=value,
            source_ref="system:compromise-assessment",
            content_hash=_hash({"finding": str(finding.id), **value}),
        )
    )
    session.flush()

    emit(
        session,
        kind="finding.compromise_assessment",
        group_key=f"finding.compromise_assessment:{finding.id}",
        title=f"Assess possible compromise: {vulnerability.id} on "
        f"{asset.display_name if asset else 'an asset'}",
        body=(
            "A malicious package matched. Say whether its install or startup code ran, "
            "whether the asset holds credentials, tokens or CI secrets, and what network "
            "it can reach."
        ),
        subject=asset.display_name if asset else None,
        urgency=URGENT,
    )
    record(
        session,
        actor="system:compromise-assessment",
        action="COMPROMISE_ASSESSMENT_OPENED",
        subject=f"finding:{finding.id}",
        detail={
            "vulnerability_id": vulnerability.id,
            "advisory_revision": finding.advisory_revision,
            "questions": [q.key for q in QUESTIONS],
        },
    )
    publish(session, topic="findings", subject_id=str(finding.id))
    return True


def answer_compromise_assessment(
    session: Session,
    finding: Finding,
    answers: dict[str, str],
    *,
    actor: str,
) -> dict[str, Any]:
    if _assessment_of(session, finding.id) is None:
        raise AssessmentError("This finding has no compromise assessment.")
    if not answers:
        raise AssessmentError("No answers given.")
    for key, choice in answers.items():
        question = QUESTION_BY_KEY.get(key)
        if question is None:
            raise AssessmentError(f"Unknown question: {key}")
        if choice not in {option for option, _ in question.options}:
            raise AssessmentError(f"Not an answer to {key}: {choice}")

    existing = _answers_of(session, finding.id)
    replaced: dict[str, str] = {}
    for key, choice in answers.items():
        question = QUESTION_BY_KEY[key]
        previous = existing.get(key)
        if previous is not None:
            if previous.value.get("answer") == choice:
                continue
            replaced[key] = previous.value.get("answer")
            session.delete(previous)
        label = dict(question.options)[choice]
        value = {"question": key, "answer": choice, "answered_by": actor}
        session.add(
            Evidence(
                finding_id=finding.id,
                kind=ANSWER_KIND,
                claim=f"{question.prompt} {label}.",
                value=value,
                source_ref=actor,
                content_hash=_hash({"finding": str(finding.id), **value}),
            )
        )
    session.flush()

    record(
        session,
        actor=actor,
        action="COMPROMISE_ASSESSMENT_ANSWERED",
        subject=f"finding:{finding.id}",
        detail={"answers": dict(answers), "replaced": replaced},
    )
    publish(session, topic="findings", subject_id=str(finding.id))
    return compromise_assessment_of(session, finding)


def compromise_assessment_of(session: Session, finding: Finding) -> dict[str, Any] | None:
    opened = _assessment_of(session, finding.id)
    if opened is None:
        return None
    answers = _answers_of(session, finding.id)
    questions = []
    for question in QUESTIONS:
        answered = answers.get(question.key)
        questions.append(
            {
                "key": question.key,
                "prompt": question.prompt,
                "options": [{"value": v, "label": label} for v, label in question.options],
                "answer": answered.value.get("answer") if answered else None,
                "answered_by": answered.value.get("answered_by") if answered else None,
                "answered_at": answered.observed_at if answered else None,
            }
        )
    still_open = [q["key"] for q in questions if q["answer"] is None]
    return {
        "opened_at": opened.observed_at,
        "status": "open" if still_open else "answered",
        "still_open": still_open,
        "questions": questions,
    }
