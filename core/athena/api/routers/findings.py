from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, can_operate, can_read, db
from athena.api.routers.exports import is_uuid
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


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _severity_of(v: Vulnerability) -> str:
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
    malicious: bool = False,
    include_no_fix: bool = False,
    include_suppressed: bool = False,
    include_baseline: bool = False,
    q: str | None = None,
    assessed: bool | None = None,
    fully_assessed: bool | None = None,
    exposure: str | None = None,
    tier: str | None = None,
    has_fix: bool | None = None,
    min_band: str | None = None,
    needs_attention: bool | None = None,
    sort: str = "risk",
    cursor: str | None = None,
    limit: int = Query(default=DEFAULT_LIMIT, le=MAX_LIMIT),
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict[str, Any]:
    if sort not in SORTS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Unknown sort {sort!r} — expected one of {', '.join(SORTS)}",
        )
    if asset_id is not None and not is_uuid(asset_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")

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
            fully_assessed=fully_assessed,
            kev=kev_only,
            malicious=malicious,
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

    no_fix = (
        select(func.count(func.distinct(Finding.vulnerability_id)))
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(Finding.state == "no_fix_available", Vulnerability.withdrawn_at.is_(None))
    )
    if asset_id:
        no_fix = no_fix.where(Finding.asset_id == asset_id)
    no_fix_count = session.execute(no_fix).scalar_one()
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
        "group_count": page.group_count,
        "matching_group_count": page.matching_group_count,
        "next_cursor": page.next_cursor,
        "instance_count": page.instance_count,
        "assessed_count": page.assessed_count,
        "facets": page.facets,
        "no_fix_available_count": no_fix_count,
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
    _: Principal = Depends(can_read),
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
            "malicious": vulnerability.malicious,
            "withdrawn_at": vulnerability.withdrawn_at,
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
        "prioritization": _prioritization(vulnerability, asset, finding),
        "risk_explained": _risk_explained(session, finding),
        "remediation": _remediation(session, finding, asset, component),
    }


def _prioritization(
    vulnerability: Vulnerability, asset: Asset, finding: Finding
) -> dict[str, Any]:
    from athena.intel import cvss
    from athena.risk import deadline, ssvc

    vector = vulnerability.cvss_vector
    scoring = vulnerability.cvss_scoring_vector
    if scoring is None and vulnerability.cvss_score is not None:
        if cvss.base_score(vector) == vulnerability.cvss_score:
            scoring = vector
    shown = scoring or vector
    try:
        version = cvss.parse(shown).version
    except cvss.VectorError:
        version = None
    today = datetime.now(UTC).date()
    due = vulnerability.kev_due_date
    return {
        "ssvc": ssvc.decide(
            kev=vulnerability.kev,
            exploit_public=vulnerability.exploit_public,
            vector=vector,
            tier=asset.tier,
            criticality=asset.criticality,
            malicious=vulnerability.malicious,
            cisa=vulnerability.ssvc_cisa,
        ).as_dict(),
        "cisa_ssvc": {
            "published": vulnerability.ssvc_cisa is not None,
            "checked_at": vulnerability.ssvc_checked_at,
        },
        "deadline": None if vulnerability.malicious else deadline.deadline(
            exposure=asset.exposure,
            kev=vulnerability.kev,
            kev_date_added=vulnerability.kev_date_added,
            vector=vector,
            cisa_ssvc=vulnerability.ssvc_cisa,
            first_seen=finding.first_seen.date(),
        ).as_dict(today=today),
        "epss": {
            "score": vulnerability.epss_score,
            "percentile": vulnerability.epss_percentile,
            "updated_at": vulnerability.epss_updated_at,
            "scored": vulnerability.epss_score is not None,
        },
        "kev": {
            "listed": vulnerability.kev,
            "date_added": vulnerability.kev_date_added,
            "due_date": due,
            "days_to_due": (due - today).days if due else None,
            "ransomware": vulnerability.kev_ransomware,
            "forensic_triage": vulnerability.kev_forensic_triage,
        },
        "cvss": {
            "vector": shown,
            "version": version,
            "score": vulnerability.cvss_score,
            "computed_from_vector": scoring is not None,
            "published_vector": vector if scoring and vector != scoring else None,
            "scored": vulnerability.cvss_score is not None,
        },
        "malicious": vulnerability.malicious,
    }


def _deferred(finding: Finding, asset: Asset, vulnerability) -> dict[str, Any] | None:
    if finding.investigation_id is not None:
        return None
    decision = decide(
        {
            "advisory": {
                "severity": vulnerability.severity,
                "cvss": vulnerability.cvss_score,
                "epss": vulnerability.epss_score,
                "known_exploited": vulnerability.kev,
                "malicious": vulnerability.malicious,
            },
            "asset": {"tier": asset.tier, "exposure": asset.exposure},
        },
        floor=get_settings().investigation_floor,
    )
    if decision.investigate:
        return None
    return {"reason": decision.reason, "floor": get_settings().investigation_floor}


def _remediation(session: Session, finding: Finding, asset: Asset, component: Component):
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
        malicious=bool(session.get(Vulnerability, finding.vulnerability_id).malicious),
    ).as_dict()


def _risk_explained(session: Session, finding: Finding) -> dict[str, Any] | None:
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
    explained["stored_score"] = finding.risk_score
    explained["stale"] = (
        finding.risk_score is not None and computed.value != finding.risk_score
    )
    return explained


def _investigation_of(session: Session, finding: Finding) -> dict[str, Any] | None:
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
    _: Principal = Depends(can_read), session: Session = Depends(db)
) -> dict[str, Any]:
    sources = source_health(session)
    total = session.execute(select(func.count()).select_from(Vulnerability)).scalar_one()
    kev = session.execute(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.kev.is_(True))
    ).scalar_one()
    malicious = session.execute(
        select(func.count()).select_from(Vulnerability).where(
            Vulnerability.malicious.is_(True), Vulnerability.withdrawn_at.is_(None)
        )
    ).scalar_one()
    from athena.intel.enrichment import eligible

    relevant_cves, ssvc_checked, ssvc_published = session.execute(
        select(
            func.count(),
            func.count().filter(Vulnerability.ssvc_checked_at.is_not(None)),
            func.count().filter(func.jsonb_typeof(Vulnerability.ssvc_cisa) == "object"),
        )
        .select_from(Vulnerability)
        .where(*eligible())
    ).one()
    return {
        "sources": sources,
        "advisories": total,
        "kev_advisories": kev,
        "malicious_advisories": malicious,
        "cisa_ssvc": {
            "cves_with_open_findings": relevant_cves,
            "checked": ssvc_checked,
            "published": ssvc_published,
        },
        "any_source_stale": any(s["stale"] for s in sources) if sources else True,
    }


@router.get("/ai/status")
def ai_status(
    _: Principal = Depends(can_read), session: Session = Depends(db)
) -> dict[str, Any]:
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
    principal: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
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
    for kind in ("intel.poll.kev", "intel.poll.epss", "intel.enrich.vulnrichment"):
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
