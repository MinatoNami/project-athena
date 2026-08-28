from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.audit import record
from athena.config import get_settings
from athena.db.models import (
    AffectedRange,
    Asset,
    Component,
    Evidence,
    Finding,
    Vulnerability,
)
from athena.findings import FindingQuery, query_findings
from athena.findings.query import DEFAULT_LIMIT, MAX_LIMIT, SORTS
from athena.intel.ingest import source_health
from athena.investigation.priority import decide
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
    include_suppressed: bool = False,
    include_baseline: bool = False,
    q: str | None = None,
    assessed: bool | None = None,
    exposure: str | None = None,
    tier: str | None = None,
    has_fix: bool | None = None,
    min_band: str | None = None,
    needs_attention: bool = False,
    sort: str = "risk",
    cursor: str | None = None,
    limit: int = Query(default=DEFAULT_LIMIT, le=MAX_LIMIT),
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Findings, grouped by vulnerability.

    One CVE affecting forty hosts is one row with forty instances, not forty rows.

    Filtering, ordering and the page boundary are all decided in SQL. They used to be
    decided in Python over an unordered slice of rows, which silently returned an
    arbitrary subset once the estate outgrew the slice.
    """
    if sort not in SORTS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Unknown sort {sort!r} — expected one of {', '.join(SORTS)}",
        )

    page = query_findings(
        session,
        FindingQuery(
            state=state,
            asset_id=asset_id,
            include_no_fix=include_no_fix,
            include_suppressed=include_suppressed,
            include_baseline=include_baseline,
            q=q,
            assessed=assessed,
            # `kev_only` predates the facet set and is kept so existing callers and
            # bookmarks keep working.
            kev=kev_only,
            exposure=exposure,
            tier=tier,
            has_fix=has_fix,
            min_band=min_band,
            needs_attention=needs_attention,
            sort=sort,
            cursor=cursor,
            limit=limit,
        ),
    )

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
        "groups": page.groups,
        # `group_count` is the whole population and `matching_group_count` is what
        # survives the filters. A single number cannot answer both "what am I looking
        # at" and "what am I excluding", and only ever answering the first is how a
        # filtered view comes to read as a complete one.
        "group_count": page.group_count,
        "matching_group_count": page.matching_group_count,
        "next_cursor": page.next_cursor,
        # Over the whole matching set, not this page: these are the denominator for
        # "how much of what I am looking at has been assessed".
        "instance_count": page.instance_count,
        "assessed_count": page.assessed_count,
        # Each facet carries both numbers for the same reason.
        "facets": page.facets,
        "no_fix_available_count": no_fix_count,
        # Both are held back rather than hidden, and both are one parameter away.
        "suppressed_group_count": page.suppressed_group_count,
        "baseline_group_count": page.baseline_group_count,
        "unbaselined_asset_count": page.unbaselined_asset_count,
        "coverage": {"of_assets_observed": observed, "of_assets_total": total_assets},
        "caveat": (
            f"{page.assessed_count} of {page.instance_count} findings have been "
            "investigated: the component was checked against that asset and the risk "
            "scored on what was found. The rest are version matches only — nothing has "
            "checked whether they run, are reachable, or are exploitable here."
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
        "deferred": _deferred(finding, asset, vulnerability),
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
        "risk_explained": _risk_explained(session, finding),
        "remediation": _remediation(session, finding, asset, component),
    }


def _deferred(finding: Finding, asset: Asset, vulnerability) -> dict[str, Any] | None:
    """Whether the configured floor is why nothing has looked at this.

    Computed here rather than stored, from the same function the scheduler applies, so
    the page cannot claim a finding is waiting its turn when the scheduler will never
    select it — nor go on calling it deferred after the floor has moved.

    None means the floor is not the reason. An already-investigated finding returns
    None too: what the floor would say about it now is of no consequence once the work
    has been done.
    """
    if finding.investigation_id is not None:
        return None
    decision = decide(
        {
            "advisory": {
                "severity": vulnerability.severity,
                "cvss": vulnerability.cvss_score,
                "epss": vulnerability.epss_score,
                "known_exploited": vulnerability.kev,
            },
            "asset": {"tier": asset.tier, "exposure": asset.exposure},
        },
        floor=get_settings().investigation_floor,
    )
    if decision.investigate:
        return None
    return {"reason": decision.reason, "floor": get_settings().investigation_floor}


def _remediation(session: Session, finding: Finding, asset: Asset, component: Component):
    """What kind of fix this needs, and where the change has to be made.

    Derived rather than stored: it is a function of facts already on the finding, so
    computing it here means it can never describe a state the finding has left.
    """
    from athena.db.models import AssetComponent
    from athena.remediation import plan_for, source_for

    scope = session.execute(
        select(AssetComponent.scope).where(
            AssetComponent.asset_id == finding.asset_id,
            AssetComponent.component_id == finding.component_id,
        )
    ).scalars().first()

    return plan_for(
        ecosystem=component.ecosystem,
        package=component.name,
        installed_version=component.version,
        fixed_version=finding.fixed_version,
        asset_kind=asset.kind,
        asset_name=asset.display_name,
        scope=scope,
        fix_channel=finding.fix_channel,
        source=source_for(session, asset),
    ).as_dict()


def _risk_explained(session: Session, finding: Finding) -> dict[str, Any] | None:
    """The arithmetic behind the band, recomputed rather than stored.

    "Why is this critical?" has to be answerable without reading code. Recomputing
    from the stored verdict rather than persisting the breakdown keeps the
    explanation and the scoring function from ever disagreeing — a stored breakdown
    would go stale the first time a weight changed, and would then be a confident
    account of a number nobody would reach again.
    """
    from athena.db.models import InvestigationRecord
    from athena.risk import score
    from athena.workers.investigate import _verdict_of, signals_for

    if finding.investigation_id is None:
        return None
    stored = session.get(InvestigationRecord, finding.investigation_id)
    if stored is None:
        return None
    computed = score(signals_for(session, finding, _verdict_of(stored)))
    explained = computed.explain()
    # A recomputation that disagrees with what is stored means the scoring function
    # moved and this finding has not been rescored. Say so rather than quietly
    # showing an explanation for a different number than the one on the page.
    explained["stored_score"] = finding.risk_score
    explained["stale"] = (
        finding.risk_score is not None and computed.value != finding.risk_score
    )
    return explained


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
