from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.audit import record
from athena.db.models import (
    AffectedRange,
    Asset,
    Component,
    Evidence,
    Finding,
    Vulnerability,
)
from athena.intel.ingest import source_health
from athena.queue import enqueue

router = APIRouter(tags=["findings"])


# Rank for ordering. Distribution advisories rarely carry CVSS, so without this the
# list ties at zero and degenerates to alphabetical order by CVE id.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _severity_of(v: Vulnerability) -> str:
    """A coarse label until real risk scoring arrives in M3.

    Deliberately named `provisional_severity` in the API: it is the advisory's own
    view, with no environmental context at all. Presenting it as risk would be a lie.
    """
    if v.cvss_score is not None:
        if v.cvss_score >= 9.0:
            return "critical"
        if v.cvss_score >= 7.0:
            return "high"
        if v.cvss_score >= 4.0:
            return "medium"
        return "low"
    return (v.severity or "unknown").lower()


@router.get("/findings")
def list_findings(
    state: str | None = None,
    asset_id: str | None = None,
    kev_only: bool = False,
    include_no_fix: bool = False,
    limit: int = Query(default=100, le=500),
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Findings, grouped by vulnerability.

    One CVE affecting forty hosts is one row with forty instances, not forty rows.
    """
    # Default view is work that can actually be done. Findings a distribution has
    # published no fix for are real, but they are not action — they are shown on
    # request, and counted separately so they are never silently hidden.
    stmt = (
        select(Finding, Vulnerability, Asset, Component)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Component, Component.id == Finding.component_id)
    )
    if state:
        stmt = stmt.where(Finding.state == state)
    elif not include_no_fix:
        stmt = stmt.where(Finding.state != "no_fix_available")
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if kev_only:
        stmt = stmt.where(Vulnerability.kev.is_(True))

    rows = session.execute(stmt.limit(limit * 20)).all()

    groups: dict[str, dict[str, Any]] = {}
    for finding, vulnerability, asset, component in rows:
        group = groups.setdefault(
            finding.group_key,
            {
                "group_key": finding.group_key,
                "worst_band": None,
                "worst_score": None,
                "investigated_count": 0,
                "vulnerability_id": vulnerability.id,
                "summary": vulnerability.summary,
                "provisional_severity": _severity_of(vulnerability),
                "cvss_score": vulnerability.cvss_score,
                "epss_score": vulnerability.epss_score,
                "kev": vulnerability.kev,
                "kev_ransomware": vulnerability.kev_ransomware,
                "published_at": vulnerability.published_at,
                "instances": [],
            },
        )
        group["instances"].append(
            {
                "finding_id": str(finding.id),
                # An investigated finding has a real band and a confidence behind it.
                # One that has not been looked at has neither, and must not borrow the
                # advisory's severity to look as though it had.
                "investigated": finding.risk_band is not None,
                "risk_band": finding.risk_band,
                "risk_score": finding.risk_score,
                "confidence": finding.confidence,
                "triage_disposition": finding.triage_disposition,
                "triage_reason": finding.triage_reason,
                "asset_id": str(asset.id),
                "asset": asset.display_name,
                "asset_kind": asset.kind,
                "tier": asset.tier,
                "component": f"{component.name} {component.version}",
                "ecosystem": component.ecosystem,
                "fixed_version": finding.fixed_version,
                # A fix only available through Ubuntu Pro is not an upgrade the
                # operator can necessarily perform.
                "fix_channel": finding.fix_channel,
                "state": finding.state,
                "match_method": finding.match_method,
                "match_confidence": finding.match_confidence,
            }
        )

    # Known-exploited first, then severity, then CVSS, then most recent. This is the
    # only ordering defensible before M3: nothing here knows whether a service is
    # running or reachable, so it cannot claim to rank by risk.
    # Roll the per-instance assessment up to the group. Risk is scored per instance,
    # so the group takes the worst of them rather than an average that would hide it.
    band_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    for group in groups.values():
        assessed = [i for i in group["instances"] if i["investigated"]]
        group["investigated_count"] = len(assessed)
        if assessed:
            worst = max(assessed, key=lambda i: band_rank.get(i["risk_band"], -1))
            group["worst_band"] = worst["risk_band"]
            group["worst_score"] = worst["risk_score"]

    ordered = sorted(
        groups.values(),
        key=lambda g: (
            # Assessed findings rank above unassessed ones: a measured band is a
            # stronger claim than an advisory's opinion, in either direction.
            -band_rank.get(g["worst_band"] or "", -1),
            not g["kev"],
            -SEVERITY_RANK.get(g["provisional_severity"], 0),
            -(g["cvss_score"] or 0),
            -(g["epss_score"] or 0),
            g["vulnerability_id"],
        ),
    )[:limit]
    for group in ordered:
        group["instance_count"] = len(group["instances"])

    no_fix_count = session.execute(
        select(func.count(func.distinct(Finding.vulnerability_id)))
        .where(Finding.state == "no_fix_available")
    ).scalar_one()

    total_assets = session.execute(
        select(func.count()).select_from(Asset).where(Asset.tombstoned_at.is_(None))
    ).scalar_one()
    observed = session.execute(
        select(func.count())
        .select_from(Asset)
        .where(Asset.tombstoned_at.is_(None), Asset.last_inventoried_at.isnot(None))
    ).scalar_one()

    return {
        "groups": ordered,
        "group_count": len(groups),
        # Surfaced, never hidden: the operator can see how much is being held back
        # and why.
        "no_fix_available_count": no_fix_count,
        # Findings are only as complete as the inventory behind them.
        "coverage": {"of_assets_observed": observed, "of_assets_total": total_assets},
        # Stated explicitly so nobody reads these as assessed risk.
        "caveat": (
            "These are candidate matches from version comparison only. Nothing here "
            "has been investigated: no check has been made of whether the affected "
            "component is running, reachable, or exploitable in this environment."
        ),
    }


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    row = session.execute(
        select(Finding, Vulnerability, Asset, Component)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Component, Component.id == Finding.component_id)
        .where(Finding.id == finding_id)
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such finding")
    finding, vulnerability, asset, component = row

    evidence = session.execute(
        select(Evidence).where(Evidence.finding_id == finding.id).order_by(Evidence.observed_at)
    ).scalars().all()

    ranges = session.execute(
        select(AffectedRange).where(
            AffectedRange.vulnerability_id == vulnerability.id,
            AffectedRange.ecosystem == component.ecosystem,
            AffectedRange.package == component.name,
        )
    ).scalars().all()

    return {
        "id": str(finding.id),
        "state": finding.state,
        "match_method": finding.match_method,
        "match_confidence": finding.match_confidence,
        "fixed_version": finding.fixed_version,
        "fix_channel": finding.fix_channel,
        "matched_source": finding.matched_source,
        "matched_release": finding.matched_release,
        "advisory_revision": finding.advisory_revision,
        "first_seen": finding.first_seen,
        "last_evaluated_at": finding.last_evaluated_at,
        "vulnerability": {
            "id": vulnerability.id,
            "aliases": vulnerability.aliases,
            "summary": vulnerability.summary,
            "details": vulnerability.details,
            "cvss_vector": vulnerability.cvss_vector,
            "cvss_score": vulnerability.cvss_score,
            "provisional_severity": _severity_of(vulnerability),
            "epss_score": vulnerability.epss_score,
            "kev": vulnerability.kev,
            "kev_ransomware": vulnerability.kev_ransomware,
            "published_at": vulnerability.published_at,
            "references": vulnerability.references_,
            "revision": vulnerability.revision,
        },
        "asset": {
            "id": str(asset.id),
            "display_name": asset.display_name,
            "kind": asset.kind,
            "tier": asset.tier,
            "exposure": asset.exposure,
        },
        "component": {
            "name": component.name,
            "version": component.version,
            "ecosystem": component.ecosystem,
            "purl": component.purl,
        },
        # Every ✓ and ? in the UI traces to one of these rows.
        "evidence": [
            {
                "kind": e.kind,
                "claim": e.claim,
                "value": e.value,
                "source_ref": e.source_ref,
                "observed_at": e.observed_at,
            }
            for e in evidence
        ],
        # Shown so a disagreement between sources is visible rather than resolved
        # behind the scenes.
        "advisory_ranges": [
            {
                "source": r.source,
                "authority": r.authority,
                "introduced": r.introduced,
                "fixed": r.fixed,
                "last_affected": r.last_affected,
                "distro": r.distro,
                "distro_release": r.distro_release,
                "channel": r.channel,
                # Falls back to the denormalised facts: the referenced row is
                # replaced whenever the advisory is revised.
                "used_for_match": (
                    r.id == finding.matched_range_id
                    or (
                        finding.matched_range_id is None
                        and r.source == finding.matched_source
                        and r.distro_release == finding.matched_release
                        and r.fixed == finding.fixed_version
                    )
                ),
            }
            for r in ranges
        ],
        "not_yet_investigated": finding.risk_band is None,
        "risk_band": finding.risk_band,
        "risk_score": finding.risk_score,
        "confidence": finding.confidence,
        "triage": (
            {
                "disposition": finding.triage_disposition,
                "reason": finding.triage_reason,
                "confidence": finding.triage_confidence,
                "at": finding.triaged_at,
            }
            if finding.triage_disposition
            else None
        ),
        "investigation": _investigation_of(session, finding),
    }


def _investigation_of(session: Session, finding: Finding) -> dict[str, Any] | None:
    """The stored investigation, so a verdict can be argued with rather than taken.

    Includes the signals, the corrections applied to them, and how many other
    findings share this answer — a reused verdict is a different claim from one
    reached for this asset alone.
    """
    from athena.db.models import InvestigationRecord

    if finding.investigation_id is None:
        return None
    stored = session.get(InvestigationRecord, finding.investigation_id)
    if stored is None:
        return None

    return {
        "verdict": stored.verdict,
        "confidence": stored.verdict_confidence,
        "rationale": stored.rationale,
        "uncertainties": stored.uncertainties,
        # Where the model asserted something it could not support and code overruled
        # it. Shown, not hidden: it is the clearest signal of how much to trust this.
        "corrections": stored.corrections,
        "signals": stored.signals,
        "model": stored.model,
        "tools_called": sorted({c.get("tool") for c in (stored.tool_calls or []) if c.get("tool")}),
        "tokens": stored.prompt_tokens + stored.completion_tokens,
        "duration_ms": stored.duration_ms,
        "shared_with_findings": stored.reused,
        "at": stored.created_at,
    }


@router.get("/intel/sources")
def intel_sources(
    _: Principal = Depends(current_principal), session: Session = Depends(db)
) -> dict[str, Any]:
    """Feed health. Stale intelligence looks exactly like a quiet week otherwise."""
    sources = source_health(session)
    total = session.execute(select(func.count()).select_from(Vulnerability)).scalar_one()
    kev = session.execute(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.kev.is_(True))
    ).scalar_one()
    return {
        "sources": sources,
        "advisories": total,
        "kev_advisories": kev,
        "any_source_stale": any(
            s["never_succeeded"] or (s["age_seconds"] or 0) > 21600 for s in sources
        )
        if sources
        else True,
    }


@router.get("/ai/status")
def ai_status(
    _: Principal = Depends(current_principal), session: Session = Depends(db)
) -> dict[str, Any]:
    """Whether the model is reachable, and what has left the network.

    On a self-hosted security tool this is the answer to the question that matters
    most, so it is a first-class view rather than something to reconstruct from logs.
    """
    from sqlalchemy import func as sqlfunc

    from athena.db.models import EgressLog
    from athena.llm import health

    totals = session.execute(
        select(
            sqlfunc.count(),
            sqlfunc.count().filter(EgressLog.blocked.is_(True)),
            sqlfunc.count().filter(EgressLog.local.is_(False)),
            sqlfunc.coalesce(sqlfunc.sum(EgressLog.prompt_tokens), 0),
            sqlfunc.coalesce(sqlfunc.sum(EgressLog.completion_tokens), 0),
        ).select_from(EgressLog)
    ).one()

    recent = session.execute(
        select(EgressLog).order_by(EgressLog.at.desc()).limit(20)
    ).scalars().all()

    return {
        "model": health(),
        "egress": {
            "calls": totals[0],
            "blocked": totals[1],
            # The number that matters in local_only mode: it must stay zero.
            "left_the_network": totals[2],
            "prompt_tokens": totals[3],
            "completion_tokens": totals[4],
        },
        "recent": [
            {
                "at": e.at,
                "purpose": e.purpose,
                "endpoint": e.endpoint,
                "model": e.model,
                "local": e.local,
                "data_classes": e.data_classes,
                "blocked": e.blocked,
                "reason": e.reason,
                "tokens": e.prompt_tokens + e.completion_tokens,
                "duration_ms": e.duration_ms,
            }
            for e in recent
        ],
    }


@router.post("/intel/refresh", status_code=status.HTTP_202_ACCEPTED)
def refresh_intel(
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Queue a full intelligence refresh."""
    from athena.intel.feeds import DEFAULT_ECOSYSTEMS

    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M")
    queued = 0
    for ecosystem in DEFAULT_ECOSYSTEMS:
        if enqueue(
            session,
            kind="intel.poll.osv",
            key=f"{ecosystem}:{stamp}",
            payload={"ecosystem": ecosystem},
            priority=4,
        ):
            queued += 1
    for kind in ("intel.poll.kev", "intel.poll.epss"):
        if enqueue(session, kind=kind, key=stamp, payload={}, priority=3):
            queued += 1

    record(
        session,
        actor=principal.actor,
        action="INTEL_REFRESH_REQUESTED",
        subject="intel",
        detail={"jobs": queued},
    )
    return {"queued": queued}
