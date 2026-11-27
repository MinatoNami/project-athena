from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select

from athena.audit import record
from athena.db.base import session_scope
from athena.db.models import (
    Asset,
    AssetComponent,
    AssetEdge,
    Component,
    Evidence,
    Finding,
    InvestigationRecord,
    Vulnerability,
)
from athena.investigation.loop import context_fingerprint, investigate
from athena.investigation.verdict import Signal, Verdict
from athena.queue import publish
from athena.queue.registry import handler
from athena.risk import Signals, component_role, score
from athena.risk.scoring import MATCH_FLOOR

log = structlog.get_logger(__name__)

VERDICT_STATE = {
    "applicable": "confirmed",
    "not_applicable": "false_positive",
    "uncertain": "discovered",
}


def match_is_current(finding: Finding, vulnerability: Vulnerability) -> bool:
    return finding.advisory_revision >= vulnerability.revision


def state_for(verdict: str, *, malicious: bool) -> str:
    if malicious and verdict == "not_applicable":
        return "discovered"
    return VERDICT_STATE.get(verdict, "discovered")


def _is_malware(session: Any, finding: Finding) -> bool:
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    return bool(vulnerability and vulnerability.malicious)


@handler("investigate.finding")
def investigate_finding(payload: dict[str, Any]) -> dict[str, Any]:
    finding_id = payload["finding_id"]
    context = _load(finding_id)
    if context is None:
        return {"status": "skipped"}

    if (cached := _lookup_cache(context["fingerprint"])) is not None:
        verdict, investigation_id, model = cached
        outcome = _apply(
            finding_id, verdict, model=model, investigation_id=investigation_id,
            tokens=0, from_cache=True, advisory_revision=context["advisory_revision"],
        )
        log.info("investigation.cache_hit", finding=finding_id,
                 fingerprint=context["fingerprint"][:12])
        return {
            "status": "discarded" if outcome.get("discarded") else "cached",
            "verdict": verdict.verdict,
        }

    with session_scope() as session:
        result = investigate(
            session,
            asset_id=context["asset_id"],
            component_id=context["component_id"],
            vulnerability_id=context["vulnerability_id"],
            seed_facts=context["seed"],
            established=context["established"],
            advisory_describes_flaw=context["advisory_describes_flaw"],
        )

    if not result.succeeded:
        _reset(finding_id)
        log.warning("investigation.inconclusive", finding=finding_id,
                    reason=result.stopped_because)
        return {"status": "inconclusive", "reason": result.stopped_because}

    investigation_id = _store(context, result)
    outcome = _apply(
        finding_id, result.verdict, model=result.model,
        investigation_id=investigation_id,
        advisory_revision=context["advisory_revision"],
        tokens=result.prompt_tokens + result.completion_tokens,
        from_cache=False,
    )
    return {"status": "discarded" if outcome.get("discarded") else "investigated", **outcome}


def _load(finding_id: str) -> dict[str, Any] | None:
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None or finding.state not in ("discovered", "investigating"):
            return None

        vuln_for_guard = session.get(Vulnerability, finding.vulnerability_id)
        if vuln_for_guard is not None and not match_is_current(finding, vuln_for_guard):
            return None

        if finding.investigation_id is not None and vuln_for_guard is not None:
            answered = session.get(InvestigationRecord, finding.investigation_id)
            if answered is None or answered.advisory_revision >= vuln_for_guard.revision:
                return None

        asset = session.get(Asset, finding.asset_id)
        component = session.get(Component, finding.component_id)
        vulnerability = session.get(Vulnerability, finding.vulnerability_id)
        if not (asset and component and vulnerability):
            return None

        finding.state = "investigating"
        finding.state_changed_at = datetime.now(UTC)

        established: dict[str, Any] = {"component_present": True}
        if finding.match_confidence >= MATCH_FLOOR:
            established["version_in_range"] = True

        return {
            "asset_id": str(asset.id),
            "component_id": str(component.id),
            "vulnerability_id": vulnerability.id,
            "advisory_revision": vulnerability.revision,
            "established": established,
            "advisory_describes_flaw": bool(
                vulnerability.cvss_score is not None
                or vulnerability.severity
                or vulnerability.cwe
                or vulnerability.details
            ),
            "seed": {
                "asset": {
                    "name": asset.display_name, "kind": asset.kind, "tier": asset.tier,
                    "exposure": asset.exposure,
                    "os": asset.attributes.get("os_version"),
                },
                "component": {
                    "name": component.name, "version": component.version,
                    "ecosystem": component.ecosystem,
                },
                "advisory": {
                    "id": vulnerability.id, "summary": vulnerability.summary,
                    "severity": vulnerability.severity, "cvss": vulnerability.cvss_score,
                    "known_exploited": vulnerability.kev,
                    "fixed_in": finding.fixed_version,
                    **({"malicious": True} if vulnerability.malicious else {}),
                },
                "match": {
                    "method": finding.match_method,
                    "confidence": finding.match_confidence,
                },
            },
            "fingerprint": context_fingerprint(
                {
                    "vulnerability": vulnerability.id,
                    "revision": vulnerability.revision,
                    "purl": component.purl,
                    "tier": asset.tier,
                    "exposure": asset.exposure,
                    "release": asset.attributes.get("distro_release"),
                    "fixed_in": finding.fixed_version,
                    "established": sorted(established),
                    "advisory_describes_flaw": bool(
                        vulnerability.cvss_score is not None
                        or vulnerability.severity
                        or vulnerability.cwe
                        or vulnerability.details
                    ),
                }
            ),
        }


def _reset(finding_id: str) -> None:
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is not None and finding.state == "investigating":
            finding.state = "discovered"
            finding.state_changed_at = datetime.now(UTC)


def _lookup_cache(fingerprint: str) -> tuple[Verdict, Any, str] | None:
    with session_scope() as session:
        cached = session.execute(
            select(InvestigationRecord).where(InvestigationRecord.fingerprint == fingerprint)
        ).scalar_one_or_none()
        if cached is None:
            return None
        cached.reused += 1
        return _verdict_of(cached), cached.id, cached.model


def _verdict_of(cached: InvestigationRecord) -> Verdict:
    return Verdict(
        signals={
            name: Signal(
                value=data.get("value", "unknown"),
                confidence=float(data.get("confidence") or 0.0),
                evidence=list(data.get("evidence") or []),
            )
            for name, data in (cached.signals or {}).items()
        },
        verdict=cached.verdict,
        verdict_confidence=cached.verdict_confidence,
        rationale=cached.rationale or "",
        uncertainties=list(cached.uncertainties or []),
        corrections=list(cached.corrections or []),
    )


def _store(context: dict[str, Any], result) -> Any:
    verdict = result.verdict
    with session_scope() as session:
        stored = InvestigationRecord(
            fingerprint=context["fingerprint"],
            vulnerability_id=context["vulnerability_id"],
            advisory_revision=context["advisory_revision"],
            verdict=verdict.verdict,
            verdict_confidence=verdict.verdict_confidence,
            signals={
                name: {"value": s.value, "confidence": s.confidence, "evidence": s.evidence}
                for name, s in verdict.signals.items()
            },
            rationale=verdict.rationale,
            uncertainties=verdict.uncertainties,
            corrections=verdict.corrections,
            model=result.model,
            prompt_hash=result.prompt_hash,
            tool_calls=result.tool_calls,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
            duration_ms=result.duration_ms,
        )
        session.add(stored)
        session.flush()
        return stored.id


def _apply(
    finding_id: str,
    verdict: Verdict,
    *,
    model: str,
    investigation_id: Any,
    tokens: int,
    from_cache: bool,
    advisory_revision: int,
) -> dict[str, Any]:
    with session_scope() as session:
        finding = session.execute(
            select(Finding)
            .where(Finding.id == finding_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if finding is None:
            return {}
        vulnerability = session.get(Vulnerability, finding.vulnerability_id)
        current = vulnerability.revision if vulnerability is not None else None
        revised = current != advisory_revision or finding.advisory_revision != advisory_revision
        if finding.state != "investigating" or revised:
            return _discard(
                session, finding, verdict, model=model,
                revised=revised, advisory_revision=advisory_revision,
            )

        risk = score(signals_for(session, finding, verdict))

        _notify_if_worth_it(session, finding, verdict, risk)

        finding.risk_score = risk.value
        finding.risk_band = str(risk.band)
        finding.confidence = verdict.verdict_confidence
        finding.investigation_id = investigation_id
        finding.state = state_for(verdict.verdict, malicious=_is_malware(session, finding))
        finding.state_changed_at = datetime.now(UTC)
        finding.last_evaluated_at = datetime.now(UTC)

        _attach(session, finding, verdict, risk, model=model)

        record(
            session,
            actor=f"model:{model}",
            action="FINDING_INVESTIGATED",
            subject=f"finding:{finding.id}",
            detail={
                "verdict": verdict.verdict,
                "confidence": round(verdict.verdict_confidence, 3),
                "band": str(risk.band),
                "score": risk.value,
                "corrections": verdict.corrections,
                "tokens": tokens,
                "from_cache": from_cache,
            },
        )
        publish(session, topic="findings", subject_id=str(finding.id))

        return {
            "verdict": verdict.verdict,
            "band": str(risk.band),
            "score": risk.value,
            "corrections": len(verdict.corrections),
        }


def _discard(
    session: Any,
    finding: Finding,
    verdict: Verdict,
    *,
    model: str,
    revised: bool,
    advisory_revision: int,
) -> dict[str, Any]:
    reset = finding.state == "investigating"
    if reset:
        finding.state = "discovered"
        finding.state_changed_at = datetime.now(UTC)
    record(
        session,
        actor=f"model:{model}",
        action="INVESTIGATION_DISCARDED",
        subject=f"finding:{finding.id}",
        detail={
            "verdict": verdict.verdict,
            "reason": "advisory revised" if revised else f"finding is now {finding.state}",
            "investigated_revision": advisory_revision,
            "returned_to_discovered": reset,
        },
    )
    if reset:
        publish(session, topic="findings", subject_id=str(finding.id))
    return {"verdict": verdict.verdict, "discarded": True}


_WORTH_TELLING = {"critical", "high", "medium"}


def _notify_if_worth_it(session, finding: Finding, verdict: Verdict, risk) -> None:
    from athena.db.models import Asset, Vulnerability
    from athena.notify import emit

    band = str(risk.band)
    if band not in _WORTH_TELLING:
        return
    was = finding.risk_band
    if was == band or (was in _WORTH_TELLING and _RANK.get(was, 0) >= _RANK.get(band, 0)):
        return

    asset = session.get(Asset, finding.asset_id)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    urgent = bool(vulnerability and vulnerability.kev) or band == "critical"

    emit(
        session,
        kind="finding.assessed",
        group_key=f"finding.assessed:{finding.vulnerability_id}",
        title=f"{finding.vulnerability_id} scored {band}",
        body=(vulnerability.summary or "")[:400] if vulnerability else "",
        subject=asset.display_name if asset else None,
        urgency="urgent" if urgent else "routine",
    )


_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def _attach(session, finding: Finding, verdict: Verdict, risk, *, model: str) -> None:
    session.query(Evidence).filter(
        Evidence.finding_id == finding.id,
        Evidence.kind.in_(("model_claim", "verdict", "uncertainty",
                           "grounding_correction", "risk")),
    ).delete(synchronize_session=False)

    def add(kind: str, claim: str, value: dict[str, Any]) -> None:
        blob = json.dumps(value, sort_keys=True, default=str)
        session.add(
            Evidence(
                finding_id=finding.id, kind=kind, claim=claim, value=value,
                source_ref=f"model:{model}",
                content_hash=hashlib.sha256(blob.encode()).hexdigest(),
            )
        )

    for name, signal in verdict.signals.items():
        if signal.value == "unknown" and signal.confidence == 0.0 and not signal.evidence:
            continue
        add("model_claim", f"{name.replace('_', ' ')}: {signal.value}",
            {"confidence": signal.confidence, "evidence": signal.evidence})

    add("verdict", verdict.rationale or verdict.verdict,
        {"verdict": verdict.verdict, "confidence": verdict.verdict_confidence})

    for uncertainty in verdict.uncertainties:
        add("uncertainty", uncertainty, {})

    for correction in verdict.corrections:
        add("grounding_correction", correction, {})

    add("risk", f"Scored {risk.value} ({risk.band})", risk.explain())


def signals_for(session, finding: Finding, verdict: Verdict) -> Signals:
    asset = session.get(Asset, finding.asset_id)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    component = session.get(Component, finding.component_id)
    scope = session.execute(
        select(AssetComponent.scope).where(
            AssetComponent.asset_id == finding.asset_id,
            AssetComponent.component_id == finding.component_id,
        )
    ).scalars().first()
    running = _running(verdict)
    if running is not True and component is not None and _listening(
        session, asset_id=finding.asset_id, name=component.name
    ):
        running = True

    return Signals(
        cvss_score=vulnerability.cvss_score if vulnerability else None,
        severity=vulnerability.severity if vulnerability else None,
        kev=bool(vulnerability and vulnerability.kev),
        epss=vulnerability.epss_score if vulnerability else None,
        exploit_public=bool(vulnerability and vulnerability.exploit_public),
        exposure=asset.exposure if asset else "unknown",
        service_running=running,
        component_role=component_role(component.ecosystem if component else None, scope),
        tier=asset.tier if asset else "unknown",
        criticality=asset.criticality if asset else None,
        reachable_in_code=_reach(verdict.signal_value("reachable_in_code")),
        match_confidence=finding.match_confidence,
        verdict_confidence=verdict.verdict_confidence,
        verdict=verdict.verdict,
        fix_available=bool(finding.fixed_version),
        fix_requires_entitlement=(finding.fix_channel or "standard") != "standard",
        malicious=bool(vulnerability and vulnerability.malicious),
    )


def _listening(session, *, asset_id: Any, name: str) -> bool:
    wanted = (name or "").strip().lower()
    if not wanted:
        return False
    services = session.execute(
        select(Asset.display_name, Asset.attributes)
        .join(AssetEdge, AssetEdge.src_id == Asset.id)
        .where(AssetEdge.dst_id == asset_id, Asset.kind == "service")
        .limit(200)
    ).all()
    for display_name, attributes in services:
        process = str((attributes or {}).get("process") or "").strip().lower()
        if wanted in (process, str(display_name or "").strip().lower()):
            return True
    return False


def _running(verdict: Verdict) -> bool | None:
    signal = verdict.signals.get("service_running")
    if signal is None:
        return None
    if signal.value is not False:
        return _tri(signal.value)
    if signal.downgraded or not signal.evidence:
        return None
    return False


def _tri(value: Any) -> bool | None:
    if value is True or value is False:
        return value
    return None


def _reach(value: Any) -> str:
    if isinstance(value, str) and value in {
        "confirmed", "likely", "unknown", "unlikely", "no"
    }:
        return value
    if value is True:
        return "likely"
    if value is False:
        return "unlikely"
    return "unknown"


@handler("triage.finding")
def triage_finding(payload: dict[str, Any]) -> dict[str, Any]:
    from athena.investigation.triage import triage

    finding_id = payload["finding_id"]
    context = _load_for_triage(finding_id)
    if context is None:
        return {"status": "skipped"}

    outcome = triage(context["facts"])

    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            return {"status": "gone"}

        finding.triage_disposition = outcome.disposition
        finding.triage_reason = outcome.reason
        finding.triage_confidence = outcome.confidence
        finding.triaged_at = datetime.now(UTC)

        _add_evidence(
            session, finding,
            kind="triage",
            claim=f"Triaged as {outcome.disposition}: {outcome.reason}",
            value={
                "disposition": outcome.disposition,
                "confidence": outcome.confidence,
                "forced_by_policy": outcome.forced,
                "tokens": outcome.tokens,
            },
            source="triage",
        )

        if outcome.disposition == "investigate":
            from athena.queue import enqueue

            enqueue(
                session,
                kind="investigate.finding",
                key=str(finding.id),
                payload={"finding_id": str(finding.id)},
                priority=5,
            )

        record(
            session,
            actor="system:triage",
            action="FINDING_TRIAGED",
            subject=f"finding:{finding.id}",
            detail={
                "disposition": outcome.disposition,
                "confidence": round(outcome.confidence, 3),
                "forced": outcome.forced,
                "tokens": outcome.tokens,
            },
        )

    return {
        "status": "triaged",
        "disposition": outcome.disposition,
        "confidence": round(outcome.confidence, 3),
        "forced": outcome.forced,
        "tokens": outcome.tokens,
    }


def _load_for_triage(finding_id: str) -> dict[str, Any] | None:
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None or finding.state != "discovered":
            return None
        if finding.triage_disposition is not None:
            return None

        asset = session.get(Asset, finding.asset_id)
        component = session.get(Component, finding.component_id)
        vulnerability = session.get(Vulnerability, finding.vulnerability_id)
        if not (asset and component and vulnerability):
            return None
        if not match_is_current(finding, vulnerability):
            return None

        return {
            "facts": {
                "asset": {
                    "name": asset.display_name, "kind": asset.kind, "tier": asset.tier,
                    "exposure": asset.exposure,
                    "os": asset.attributes.get("os_version"),
                },
                "component": {
                    "name": component.name, "version": component.version,
                    "ecosystem": component.ecosystem,
                },
                "advisory": {
                    "id": vulnerability.id,
                    "summary": (vulnerability.summary or "")[:600],
                    "severity": vulnerability.severity,
                    "cvss": vulnerability.cvss_score,
                    "epss": vulnerability.epss_score,
                    "known_exploited": vulnerability.kev,
                    **({"malicious": True} if vulnerability.malicious else {}),
                },
                "fix": {
                    "fixed_version": finding.fixed_version,
                    "channel": finding.fix_channel,
                },
            }
        }


def _add_evidence(session, finding, *, kind: str, claim: str, value: dict, source: str) -> None:
    blob = json.dumps(value, sort_keys=True, default=str)
    session.query(Evidence).filter(
        Evidence.finding_id == finding.id, Evidence.kind == kind
    ).delete(synchronize_session=False)
    session.add(
        Evidence(
            finding_id=finding.id, kind=kind, claim=claim, value=value,
            source_ref=source,
            content_hash=hashlib.sha256(blob.encode()).hexdigest(),
        )
    )
