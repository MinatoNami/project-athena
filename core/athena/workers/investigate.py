"""Investigation job: candidate finding → evidenced verdict → risk score."""

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

log = structlog.get_logger(__name__)

# Verdict → the state a finding lands in. `uncertain` deliberately returns to
# discovered: an inconclusive investigation has not confirmed anything, and the UI
# must keep presenting it as not yet settled.
VERDICT_STATE = {
    "applicable": "confirmed",
    "not_applicable": "false_positive",
    "uncertain": "discovered",
}


@handler("investigate.finding")
def investigate_finding(payload: dict[str, Any]) -> dict[str, Any]:
    """Investigate one candidate finding.

    A model failure leaves the finding in `discovered` — uninvestigated, and shown as
    such — rather than producing a verdict nobody could justify.
    """
    finding_id = payload["finding_id"]
    context = _load(finding_id)
    if context is None:
        return {"status": "skipped"}

    # Identical relevant facts share an answer. Fourteen matching hosts are one
    # question; without this, investigating a fleet costs a model call per host.
    if (cached := _lookup_cache(context["fingerprint"])) is not None:
        verdict, investigation_id, model = cached
        _apply(finding_id, verdict, model=model, investigation_id=investigation_id,
               tokens=0, from_cache=True)
        log.info("investigation.cache_hit", finding=finding_id,
                 fingerprint=context["fingerprint"][:12])
        return {"status": "cached", "verdict": verdict.verdict}

    with session_scope() as session:
        result = investigate(
            session,
            asset_id=context["asset_id"],
            component_id=context["component_id"],
            vulnerability_id=context["vulnerability_id"],
            seed_facts=context["seed"],
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
        tokens=result.prompt_tokens + result.completion_tokens,
        from_cache=False,
    )
    return {"status": "investigated", **outcome}


# ── context ──────────────────────────────────────────────────────────────────


def _load(finding_id: str) -> dict[str, Any] | None:
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None or finding.state not in ("discovered", "investigating"):
            return None

        # An uncertain verdict returns the finding to `discovered`, which is correct —
        # it has not been settled. But without this guard a sweep would investigate it
        # again on every pass, forever, at 40 seconds a time. Re-investigation happens
        # when the advisory changes, not because the answer was inconclusive.
        vuln_for_guard = session.get(Vulnerability, finding.vulnerability_id)
        if (
            finding.investigation_id is not None
            and vuln_for_guard is not None
            and finding.advisory_revision >= vuln_for_guard.revision
        ):
            return None

        asset = session.get(Asset, finding.asset_id)
        component = session.get(Component, finding.component_id)
        vulnerability = session.get(Vulnerability, finding.vulnerability_id)
        if not (asset and component and vulnerability):
            return None

        finding.state = "investigating"
        finding.state_changed_at = datetime.now(UTC)

        return {
            "asset_id": str(asset.id),
            "component_id": str(component.id),
            "vulnerability_id": vulnerability.id,
            "advisory_revision": vulnerability.revision,
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
                },
                "match": {
                    "method": finding.match_method,
                    "confidence": finding.match_confidence,
                },
            },
            # Only facts that could change the verdict. Anything else would fragment
            # the cache without improving its correctness.
            "fingerprint": context_fingerprint(
                {
                    "vulnerability": vulnerability.id,
                    "revision": vulnerability.revision,
                    "purl": component.purl,
                    "tier": asset.tier,
                    "exposure": asset.exposure,
                    "release": asset.attributes.get("distro_release"),
                    "fixed_in": finding.fixed_version,
                }
            ),
        }


def _reset(finding_id: str) -> None:
    """Return a finding to uninvestigated after an inconclusive attempt."""
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is not None and finding.state == "investigating":
            finding.state = "discovered"
            finding.state_changed_at = datetime.now(UTC)


# ── cache ────────────────────────────────────────────────────────────────────


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
    """Persist the investigation so its conclusion can be replayed."""
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


# ── applying the verdict ─────────────────────────────────────────────────────


def _apply(
    finding_id: str,
    verdict: Verdict,
    *,
    model: str,
    investigation_id: Any,
    tokens: int,
    from_cache: bool,
) -> dict[str, Any]:
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None:
            return {}

        asset = session.get(Asset, finding.asset_id)
        risk = score(signals_for(session, finding, verdict))

        finding.risk_score = risk.value
        finding.risk_band = str(risk.band)
        finding.confidence = verdict.verdict_confidence
        finding.investigation_id = investigation_id
        finding.state = VERDICT_STATE.get(verdict.verdict, "discovered")
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


def _attach(session, finding: Finding, verdict: Verdict, risk, *, model: str) -> None:
    """Persist the reasoning, so the conclusion can be replayed and argued with."""
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

    # Corrections are evidence too: they record where the model asserted something
    # it could not support.
    for correction in verdict.corrections:
        add("grounding_correction", correction, {})

    add("risk", f"Scored {risk.value} ({risk.band})", risk.explain())


def signals_for(session, finding: Finding, verdict: Verdict) -> Signals:
    """Assemble the scoring inputs for one finding.

    The single definition of what the score depends on. Anything that recomputes a
    score — the investigation path, a rescore after the function changes — goes
    through here, because two copies would drift and the drift would be silent:
    both would produce a plausible number and only one would be the number the UI
    says it is.
    """
    asset = session.get(Asset, finding.asset_id)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    component = session.get(Component, finding.component_id)
    scope = session.execute(
        select(AssetComponent.scope).where(
            AssetComponent.asset_id == finding.asset_id,
            AssetComponent.component_id == finding.component_id,
        )
    ).scalars().first()
    # An observation outranks an assertion. The model is asked whether the service is
    # running and sometimes answers "no" while citing the very tool output that shows
    # it listening — grounding cannot catch that, because it checks that evidence was
    # cited, not that the evidence supports the claim. Where inventory records a
    # listening service whose process is this package, running state is a fact we hold
    # and not a question for the model.
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
    )


def _listening(session, *, asset_id: Any, name: str) -> bool:
    """Does inventory show a listening service on this asset that is this package?

    Matched on the process name or the service's own name, exactly and
    case-insensitively. Deliberately narrow: this function only ever raises a
    finding's score, so a loose match here would invent exposure that is not there.
    A package that runs under some other process name simply falls through to
    unknown, which earns no discount either way.
    """
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
    """`service_running`, but a "no" has to be earned.

    This one signal carries a four-fold discount, which makes it the cheapest way
    for an unsupported assertion to bury a real finding. A `False` therefore counts
    only when the model cited tool output for it and grounding did not downgrade the
    claim. Everything else reads as unknown, which earns no discount.
    """
    signal = verdict.signals.get("service_running")
    if signal is None:
        return None
    if signal.value is not False:
        return _tri(signal.value)
    if signal.downgraded or not signal.evidence:
        return None
    return False


def _tri(value: Any) -> bool | None:
    """True, False, or None for unknown. Unknown is never collapsed into False."""
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
    """Decide whether a finding earns a full investigation.

    Triage never closes anything. A deprioritised finding stays `discovered` and
    still reports that it has not been investigated — it is simply not queued for
    the expensive loop.
    """
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
    """The summary triage reasons over. No tools, so this is all it gets."""
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if finding is None or finding.state != "discovered":
            return None
        if finding.triage_disposition is not None:
            return None    # already triaged; re-triage is an explicit action

        asset = session.get(Asset, finding.asset_id)
        component = session.get(Component, finding.component_id)
        vulnerability = session.get(Vulnerability, finding.vulnerability_id)
        if not (asset and component and vulnerability):
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
