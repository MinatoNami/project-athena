from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.audit import record
from athena.remediation import link_built_images
from athena.db.models import (
    Asset,
    AssetComponent,
    Component,
    Finding,
    MergeCandidate,
    ScanRun,
    Vulnerability,
)
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
    # The images this repository builds, named the way the runtime reports them
    # (`lumaindex-frontend`, no tag). Nothing in an image records the source that
    # produced it, so this is the only way the two are ever connected — and it is
    # what turns an image finding from "upgrade this somewhere" into a file to edit.
    builds: list[str] = Field(default_factory=list, max_length=200)


class ClassifyGroup(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=1000)
    tier: str | None = None
    exposure: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)


class ClassifyRequest(BaseModel):
    groups: list[ClassifyGroup] = Field(min_length=1, max_length=100)


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
        attributes={
            "clone_url": body.url,
            "default_branch": body.default_branch,
            "builds": [n.strip() for n in body.builds if n.strip()],
        },
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
    # Reported rather than left silent. Matching is exact on the image name, so a
    # name that does not match the runtime's spelling links nothing — and the only
    # moment anybody can correct that is now, while they are looking at what they
    # typed. A zero here against a non-empty `builds` is the whole signal.
    linked = link_built_images(session, asset)
    enqueue(
        session,
        kind="scan.repository",
        key=f"{asset.id}:initial" if created else f"{asset.id}:rescan",
        payload={"asset_id": str(asset.id)},
        priority=3,
    )
    return {"created": created, "images_linked": linked, **_serialise(asset)}


# ── classification ───────────────────────────────────────────────────────────


def _family(asset: Asset) -> tuple[str, str]:
    """Which classification group an asset belongs to, and what to call it.

    Eight tags of one image are one decision, not eight. Grouping is what turns
    "classify 308 assets" into something a person will actually finish, so it is
    computed here rather than left to the browser — the client should not have to
    fetch every asset to work out that they are the same thing.
    """
    if asset.kind == "image":
        # `repo:tag` and `repo@sha256:…` both reduce to the repository.
        name = asset.display_name
        for sep in ("@", ":"):
            if sep in name:
                name = name.rsplit(sep, 1)[0]
        return f"image:{name}", name
    if asset.kind in ("service", "container"):
        # Individually numerous and individually uninteresting; they inherit their
        # host's consequence far more often than they have their own.
        return f"kind:{asset.kind}", f"All {asset.kind}s"
    # Keyed on identity_key rather than id: identity is what the inventory assigned,
    # and it exists before the row does. Keying on the primary key made the group of
    # an unflushed asset "asset:None", which is only ever wrong.
    return f"asset:{asset.identity_key}", asset.display_name


@router.get("/assets/unclassified")
def unclassified(
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Assets with no tier or exposure set, grouped into decisions.

    Unknown is scored as middling rather than harmless, so nothing is hidden by this
    gap — but importance is a placeholder in every score until it is filled in, and
    that is worth showing as a number.
    """
    assets = session.execute(
        select(Asset).where(
            Asset.tombstoned_at.is_(None),
            (Asset.tier == "unknown") | (Asset.exposure == "unknown"),
        )
    ).scalars().all()

    finding_counts = dict(
        session.execute(
            select(Finding.asset_id, func.count()).group_by(Finding.asset_id)
        ).all()
    )

    groups: dict[str, dict[str, Any]] = {}
    for asset in assets:
        key, label = _family(asset)
        group = groups.setdefault(
            key,
            {
                "key": key,
                "label": label,
                "kind": asset.kind,
                "asset_ids": [],
                "asset_count": 0,
                "finding_count": 0,
                "tier": asset.tier,
                "exposure": asset.exposure,
                "mixed": False,
            },
        )
        group["asset_ids"].append(str(asset.id))
        group["asset_count"] += 1
        group["finding_count"] += finding_counts.get(asset.id, 0)
        # A group whose members already disagree must say so rather than show one
        # member's value as if it spoke for the rest.
        if group["tier"] != asset.tier or group["exposure"] != asset.exposure:
            group["mixed"] = True

    ordered = sorted(
        groups.values(), key=lambda g: (-g["finding_count"], -g["asset_count"], g["label"])
    )
    return {
        "groups": ordered,
        "asset_count": len(assets),
        "group_count": len(ordered),
        "findings_affected": sum(g["finding_count"] for g in ordered),
    }


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


@router.post("/assets/classify")
def classify(
    body: ClassifyRequest,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Set tier and exposure across many assets, then rescore what it changed.

    Rescoring is enqueued here rather than left to the operator. Tier and exposure are
    scoring inputs, but the re-investigation guard declines to re-ask a model about an
    advisory that has not moved — so without this the classification would land and
    every score would sit unchanged, which reads as the feature not working.
    """
    for group in body.groups:
        if group.tier is not None and group.tier not in TIERS:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown tier {group.tier!r}"
            )
        if group.exposure is not None and group.exposure not in EXPOSURES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown exposure {group.exposure!r}"
            )

    changed = 0
    for group in body.groups:
        assets = session.execute(
            select(Asset).where(Asset.id.in_(group.asset_ids))
        ).scalars().all()
        for asset in assets:
            before = (asset.tier, asset.exposure, asset.criticality)
            if group.tier is not None:
                asset.tier = group.tier
            if group.exposure is not None:
                asset.exposure = group.exposure
            if group.criticality is not None:
                asset.criticality = group.criticality
            after = (asset.tier, asset.exposure, asset.criticality)
            if before == after:
                continue
            changed += 1
            # Per asset, not per batch: "who decided this host was production" is a
            # question the audit trail should be able to answer on its own.
            record(
                session,
                actor=principal.actor,
                action="ASSET_CLASSIFIED",
                subject=f"asset:{asset.id}",
                detail={
                    "from": {"tier": before[0], "exposure": before[1], "criticality": before[2]},
                    "to": {"tier": after[0], "exposure": after[1], "criticality": after[2]},
                },
            )

    job = None
    if changed:
        job = enqueue(
            session,
            kind="rescore.findings",
            key=f"classify:{principal.actor}",
            payload={},
            priority=2,
        )
    return {"assets_changed": changed, "rescore_queued": job is not None}


# ── baselines ────────────────────────────────────────────────────────────────


class BaselineRequest(BaseModel):
    asset_id: str | None = None
    # Refuses by default when a line has already been drawn: moving a baseline
    # forward accepts everything found since, which is a different decision from
    # drawing one for the first time and should be asked for on purpose.
    move_existing: bool = False


def _baseline_preview(session: Session, asset_id: str | None) -> dict[str, Any]:
    """What a baseline would accept, counted before it is drawn."""
    from athena.findings.query import _is_new

    stmt = (
        select(func.count(func.distinct(Finding.group_key)), func.count())
        .select_from(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(Asset.tombstoned_at.is_(None), _is_new())
    )
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    groups, findings = session.execute(stmt).one()

    assets = select(func.count()).select_from(Asset).where(
        Asset.tombstoned_at.is_(None), Asset.baseline_at.is_(None)
    )
    if asset_id:
        assets = assets.where(Asset.id == asset_id)
    # What a person is actually deciding about is what leaves their screen. The
    # totals above count every finding a baseline would mark, including ones already
    # held back for having no published fix — true, but not the number being weighed.
    from athena.findings import FindingQuery, query_findings

    before = query_findings(
        session, FindingQuery(limit=1, asset_id=asset_id)
    ).matching_group_count
    return {
        "vulnerabilities": groups,
        "findings": findings,
        "assets_without_baseline": session.execute(assets).scalar_one(),
        "default_view_now": before,
        # Everything currently visible that is not exempt by the escape clause.
        "would_leave_default_view": max(0, before - _exempt_count(session, asset_id)),
        "stays_visible": _exempt_count(session, asset_id),
    }


def _exempt_count(session: Session, asset_id: str | None) -> int:
    """Groups the escape clause keeps in view whatever the baseline says.

    Known-exploited, or measured at high or above. Reported alongside the preview so
    the offer is not read as "this makes everything go away".
    """
    from athena.findings.query import _BAND_RANK

    stmt = (
        select(func.count(func.distinct(Finding.group_key)))
        .select_from(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(
            Asset.tombstoned_at.is_(None),
            Finding.state != "no_fix_available",
            (Vulnerability.kev.is_(True)) | (_BAND_RANK >= 3),
        )
    )
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    return session.execute(stmt).scalar_one()


@router.get("/baseline")
def baseline_status(
    asset_id: str | None = None,
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """What is currently baselined, and what drawing one now would accept."""
    baselined = session.execute(
        select(func.count())
        .select_from(Asset)
        .where(Asset.tombstoned_at.is_(None), Asset.baseline_at.is_not(None))
    ).scalar_one()
    total = session.execute(
        select(func.count()).select_from(Asset).where(Asset.tombstoned_at.is_(None))
    ).scalar_one()
    return {
        "assets_baselined": baselined,
        "assets_total": total,
        "would_accept": _baseline_preview(session, asset_id),
    }


@router.post("/baseline")
def capture_baseline(
    body: BaselineRequest,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Draw a line under what is already here.

    Nothing is hidden or deleted: pre-existing findings stay listed, counted, and one
    filter away. Known-exploited findings and anything measured at high or above stay
    in the default view regardless — a baseline that swallowed those would be doing
    the wall of red's job quietly.
    """
    stmt = select(Asset).where(Asset.tombstoned_at.is_(None))
    if body.asset_id:
        stmt = stmt.where(Asset.id == body.asset_id)
    assets = session.execute(stmt).scalars().all()
    if body.asset_id and not assets:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")

    already = [a for a in assets if a.baseline_at is not None]
    if already and not body.move_existing:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{len(already)} of these assets already have a baseline. Moving it forward "
            "accepts everything found since, which is a different decision from drawing "
            "one for the first time — re-send with move_existing to do that.",
        )

    accepted = _baseline_preview(session, body.asset_id)
    now = datetime.now(UTC)
    for asset in assets:
        asset.baseline_at = now
        asset.baseline_by = principal.actor

    record(
        session,
        actor=principal.actor,
        action="BASELINE_CAPTURED",
        subject=f"asset:{body.asset_id}" if body.asset_id else "estate",
        detail={
            "assets": len(assets),
            "moved_existing": len(already),
            "accepted": accepted,
        },
    )
    return {"assets_baselined": len(assets), "accepted": accepted, "at": now}


@router.delete("/baseline")
def clear_baseline(
    asset_id: str | None = None,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Undo it. Everything previously set aside as pre-existing comes back."""
    stmt = select(Asset).where(Asset.tombstoned_at.is_(None), Asset.baseline_at.is_not(None))
    if asset_id:
        stmt = stmt.where(Asset.id == asset_id)
    assets = session.execute(stmt).scalars().all()
    for asset in assets:
        asset.baseline_at = None
        asset.baseline_by = None
    record(
        session,
        actor=principal.actor,
        action="BASELINE_CLEARED",
        subject=f"asset:{asset_id}" if asset_id else "estate",
        detail={"assets": len(assets)},
    )
    return {"assets_cleared": len(assets)}
