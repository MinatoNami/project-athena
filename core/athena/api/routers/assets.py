from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.audit import record
from athena.db.models import Asset, AssetComponent, Component, MergeCandidate, ScanRun
from athena.inventory.identity import AssetKind, IdentityError, identity_for
from athena.inventory.service import coverage, is_stale, register_asset
from athena.queue import enqueue

router = APIRouter(tags=["inventory"])

TIERS = {"production", "staging", "development", "personal", "unknown"}
EXPOSURES = {"internet", "internal", "isolated", "unknown"}


class RegisterRepository(BaseModel):
    url: str = Field(min_length=1, max_length=2000)
    display_name: str | None = None
    default_branch: str | None = None
    tier: str = "unknown"
    owner: str | None = None


class UpdateAsset(BaseModel):
    tier: str | None = None
    exposure: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    owner: str | None = None


def _serialise(asset: Asset, *, component_count: int | None = None) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "kind": asset.kind,
        "identity_key": asset.identity_key,
        "display_name": asset.display_name,
        "tier": asset.tier,
        "exposure": asset.exposure,
        # Explicitly null rather than 0 — nobody has set it, which is not the same as
        # "unimportant". The UI surfaces this as a configuration gap.
        "criticality": asset.criticality,
        "owner": asset.owner,
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "last_inventoried_at": asset.last_inventoried_at,
        "never_inventoried": asset.last_inventoried_at is None,
        "stale": is_stale(asset),
        "component_count": component_count,
        "attributes": asset.attributes,
    }


@router.get("/assets")
def list_assets(
    kind: str | None = None,
    limit: int = Query(default=100, le=500),
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    stmt = select(Asset).where(Asset.tombstoned_at.is_(None)).order_by(Asset.display_name)
    if kind:
        stmt = stmt.where(Asset.kind == kind)
    assets = session.execute(stmt.limit(limit)).scalars().all()

    counts = dict(
        session.execute(
            select(AssetComponent.asset_id, func.count())
            .where(AssetComponent.asset_id.in_([a.id for a in assets] or [None]))
            .group_by(AssetComponent.asset_id)
        ).all()
    )
    return {
        "assets": [_serialise(a, component_count=counts.get(a.id, 0)) for a in assets],
        "coverage": coverage(session),
    }


@router.post("/assets/repositories", status_code=status.HTTP_201_CREATED)
def register_repository(
    body: RegisterRepository,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Register a repository and queue its first scan."""
    try:
        key = identity_for(AssetKind.REPOSITORY, url=body.url)
    except IdentityError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if body.tier not in TIERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown tier {body.tier!r}")

    asset, created = register_asset(
        session,
        kind=AssetKind.REPOSITORY,
        identity_key=key,
        display_name=body.display_name or key,
        attributes={"clone_url": body.url, "default_branch": body.default_branch},
        tier=body.tier,
        owner=body.owner,
    )
    record(
        session,
        actor=principal.actor,
        action="ASSET_REGISTERED" if created else "ASSET_UPDATED",
        subject=f"asset:{asset.id}",
        detail={"kind": "repository", "identity_key": key},
    )
    enqueue(
        session,
        kind="scan.repository",
        key=f"{asset.id}:initial" if created else f"{asset.id}:rescan",
        payload={"asset_id": str(asset.id)},
        priority=3,
    )
    return {"created": created, **_serialise(asset)}


@router.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")

    components = session.execute(
        select(Component, AssetComponent.scope, AssetComponent.observed_at)
        .join(AssetComponent, AssetComponent.component_id == Component.id)
        .where(AssetComponent.asset_id == asset.id)
        .order_by(Component.ecosystem, Component.name)
        .limit(1000)
    ).all()

    runs = session.execute(
        select(ScanRun)
        .where(ScanRun.asset_id == asset.id)
        .order_by(ScanRun.started_at.desc())
        .limit(10)
    ).scalars().all()

    merges = session.execute(
        select(MergeCandidate).where(
            (MergeCandidate.asset_id == asset.id) | (MergeCandidate.other_asset_id == asset.id),
            MergeCandidate.resolved_at.is_(None),
        )
    ).scalars().all()

    return {
        **_serialise(asset, component_count=len(components)),
        "components": [
            {
                "id": str(c.id),
                "purl": c.purl,
                "ecosystem": c.ecosystem,
                "name": c.name,
                "version": c.version,
                "scope": scope,
                "observed_at": observed_at,
            }
            for c, scope, observed_at in components
        ],
        # Every scan attempt, including the ones that failed. An asset whose scans keep
        # failing must look uncovered here, not clean.
        "scan_runs": [
            {
                "id": str(r.id),
                "kind": r.kind,
                "tool": r.tool,
                "tool_version": r.tool_version,
                "status": r.status,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "error": r.error,
                "stats": r.stats,
            }
            for r in runs
        ],
        "merge_candidates": [
            {"id": str(m.id), "reason": m.reason, "confidence": m.confidence} for m in merges
        ],
    }


@router.patch("/assets/{asset_id}")
def update_asset(
    asset_id: str,
    body: UpdateAsset,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")

    if body.tier is not None:
        if body.tier not in TIERS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown tier {body.tier!r}")
        asset.tier = body.tier
    if body.exposure is not None:
        if body.exposure not in EXPOSURES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown exposure {body.exposure!r}"
            )
        asset.exposure = body.exposure
    if body.criticality is not None:
        asset.criticality = body.criticality
    if body.owner is not None:
        asset.owner = body.owner

    record(
        session,
        actor=principal.actor,
        action="ASSET_CLASSIFIED",
        subject=f"asset:{asset.id}",
        detail=body.model_dump(exclude_none=True),
    )
    return _serialise(asset)


@router.post("/assets/{asset_id}/scan", status_code=status.HTTP_202_ACCEPTED)
def rescan(
    asset_id: str,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")
    if asset.kind != AssetKind.REPOSITORY:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Scanning {asset.kind} assets is not implemented yet",
        )

    from datetime import UTC, datetime

    job = enqueue(
        session,
        kind="scan.repository",
        key=f"{asset.id}:{datetime.now(UTC).isoformat(timespec='seconds')}",
        payload={"asset_id": str(asset.id)},
        priority=3,
    )
    record(
        session,
        actor=principal.actor,
        action="SCAN_REQUESTED",
        subject=f"asset:{asset.id}",
        detail={"job_id": job.id if job else None},
    )
    return {"queued": job is not None, "job_id": job.id if job else None}


@router.get("/coverage")
def get_coverage(
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """The honest view: what has been inventoried, what is stale, what was never seen."""
    return coverage(session)
