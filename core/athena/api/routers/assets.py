from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, NamedTuple

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, can_operate, can_read, db
from athena.audit import record
from athena.db.models import (
    Asset,
    AssetComponent,
    AssetEdge,
    Component,
    Finding,
    MergeCandidate,
    Node,
    ScanRun,
    Vulnerability,
)
from athena.inventory.classify import mark_operator
from athena.inventory.identity import AssetKind, IdentityError, identity_for
from athena.inventory.service import coverage, is_stale, register_asset
from athena.nodes.dispatch import enqueue_collection
from athena.queue import enqueue
from athena.remediation import link_built_images

router = APIRouter(tags=["inventory"])

COMPONENT_LIST_LIMIT = 1000

_LISTED = (Vulnerability.withdrawn_at.is_(None), Finding.state != "unmatched")

TIERS = {"production", "staging", "development", "personal", "unknown"}
EXPOSURES = {"internet", "internal", "isolated", "unknown"}


class RegisterRepository(BaseModel):
    url: str = Field(min_length=1, max_length=2000)
    display_name: str | None = None
    default_branch: str | None = None
    tier: str = "unknown"
    owner: str | None = None
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
        "classification": asset.attributes.get("classification") or {},
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
    _: Principal = Depends(can_read),
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
    principal: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
    try:
        key = identity_for(AssetKind.REPOSITORY, url=body.url)
    except IdentityError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    if body.tier not in TIERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown tier {body.tier!r}")

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
    linked = link_built_images(session, asset)
    enqueue(
        session,
        kind="scan.repository",
        key=f"{asset.id}:initial" if created else f"{asset.id}:rescan",
        payload={"asset_id": str(asset.id)},
        priority=3,
    )
    return {"created": created, "images_linked": linked, **_serialise(asset)}


def _family(asset: Asset) -> tuple[str, str]:
    if asset.kind == "image":
        name = asset.display_name
        for sep in ("@", ":"):
            if sep in name:
                name = name.rsplit(sep, 1)[0]
        return f"image:{name}", name
    if asset.kind in ("service", "container"):
        return f"kind:{asset.kind}", f"All {asset.kind}s"
    return f"asset:{asset.identity_key}", asset.display_name


@router.get("/assets/unclassified")
def unclassified(
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict[str, Any]:
    assets = session.execute(
        select(Asset).where(
            Asset.tombstoned_at.is_(None),
            (Asset.tier == "unknown") | (Asset.exposure == "unknown"),
        )
    ).scalars().all()

    finding_counts = dict(
        session.execute(
            select(Finding.asset_id, func.count())
            .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
            .where(*_LISTED)
            .group_by(Finding.asset_id)
        ).all()
    )

    evidence = _exposure_evidence(session, assets)

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
                "classification": asset.attributes.get("classification") or {},
                "evidence": [],
                "mixed": False,
            },
        )
        for line in evidence.get(asset.id, []):
            if line not in group["evidence"]:
                group["evidence"].append(line)
        group["asset_ids"].append(str(asset.id))
        group["asset_count"] += 1
        group["finding_count"] += finding_counts.get(asset.id, 0)
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


def _exposure_evidence(session: Session, assets: list[Asset]) -> dict[Any, list[str]]:
    ids = {a.id for a in assets}
    if not ids:
        return {}
    out: dict[Any, list[str]] = {}

    runs = session.execute(
        select(AssetEdge.src_id, Asset.display_name)
        .join(Asset, Asset.id == AssetEdge.dst_id)
        .where(AssetEdge.relation == "runs_on", Asset.kind == "host")
    ).all()
    host_of = dict(runs)

    rows = session.execute(
        select(AssetEdge.dst_id, Asset)
        .join(Asset, Asset.id == AssetEdge.src_id)
        .where(
            AssetEdge.dst_id.in_(ids),
            AssetEdge.relation == "built_from",
            Asset.tombstoned_at.is_(None),
        )
        .order_by(Asset.last_seen)
    ).all()
    latest: dict[tuple[Any, str], str] = {}
    for image_id, container in rows:
        where = f" on {host_of[container.id]}" if container.id in host_of else ""
        ports = container.attributes.get("published_ports")
        if ports is None:
            how = "ports not reported by this host's agent"
        elif not ports.strip():
            how = "publishing no ports"
        else:
            how = f"publishing {ports}"
        latest[(image_id, container.display_name)] = f"{container.display_name}{where}, {how}"
    for (image_id, _), line in latest.items():
        out.setdefault(image_id, []).append(line)

    for host in (a for a in assets if a.kind == "host"):
        seen = session.execute(
            select(Asset.display_name, Asset.exposure)
            .join(AssetEdge, AssetEdge.src_id == Asset.id)
            .where(
                AssetEdge.dst_id == host.id,
                AssetEdge.relation == "runs_on",
                Asset.kind == "service",
                Asset.tombstoned_at.is_(None),
            )
        ).all()
        if not seen:
            continue
        reachable = [n for n, e in seen if e != "isolated"]
        detail = f" — e.g. {', '.join(reachable[:3])}" if reachable else ""
        out.setdefault(host.id, []).append(
            f"{len(reachable)} of {len(seen)} listening services accept connections "
            f"from off-host{detail}"
        )
    return out


@router.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,
    _: Principal = Depends(can_read),
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
        .limit(COMPONENT_LIST_LIMIT)
    ).all()
    by_ecosystem = session.execute(
        select(Component.ecosystem, func.count())
        .join(AssetComponent, AssetComponent.component_id == Component.id)
        .where(AssetComponent.asset_id == asset.id)
        .group_by(Component.ecosystem)
        .order_by(func.count().desc(), Component.ecosystem)
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
        **_serialise(asset, component_count=sum(n for _, n in by_ecosystem)),
        "ecosystems": [{"ecosystem": e or "unknown", "count": n} for e, n in by_ecosystem],
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
        "scan": _scan_offer(session, asset).as_json(),
    }


@router.patch("/assets/{asset_id}")
def update_asset(
    asset_id: str,
    body: UpdateAsset,
    principal: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")

    if body.tier is not None:
        if body.tier not in TIERS:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown tier {body.tier!r}"
            )
        asset.tier = body.tier
    if body.exposure is not None:
        if body.exposure not in EXPOSURES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown exposure {body.exposure!r}"
            )
        asset.exposure = body.exposure
    if body.criticality is not None:
        asset.criticality = body.criticality
    if body.owner is not None:
        asset.owner = body.owner
    mark_operator(
        asset,
        *[f for f in ("tier", "exposure") if getattr(body, f) is not None],
    )

    record(
        session,
        actor=principal.actor,
        action="ASSET_CLASSIFIED",
        subject=f"asset:{asset.id}",
        detail=body.model_dump(exclude_none=True),
    )
    return _serialise(asset)


SCAN_JOBS = {
    AssetKind.REPOSITORY: "scan.repository",
    AssetKind.IMAGE: "scan.image",
}

COLLECT = "collect"

NOT_SCANNED_DIRECTLY = {
    AssetKind.CONTAINER: (
        "A container's packages come from the image it was built from — scan that image instead."
    ),
    AssetKind.SERVICE: "A service is observed by the node on its host, not scanned on its own.",
    AssetKind.NETWORK_HOST: (
        "A network host is only ever seen from the outside, so there is nothing here "
        "to look inside."
    ),
}

NO_NODE = "No node is enrolled for this host, so there is nothing to collect from."

UNREFERENCABLE_IMAGE = (
    "This image has no repository name and no usable tag or digest, so the scanner "
    "cannot locate it. Scan the image it was tagged as, or the container's image."
)


def _image_is_referencable(asset: Asset) -> bool:
    attrs = asset.attributes or {}
    repository, tag, digest = attrs.get("repository"), attrs.get("tag"), attrs.get("digest")
    if not repository or repository == "<none>":
        return False
    return bool((tag and tag != "<none>") or (digest and str(digest).startswith("sha256:")))


class ScanOffer(NamedTuple):
    action: str | None
    reason: str | None = None
    node: Node | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "supported": self.action is not None,
            "action": self.action,
            "reason": self.reason,
        }


def _scan_offer(session: Session, asset: Asset) -> ScanOffer:
    if asset.kind == AssetKind.HOST:
        node = session.execute(
            select(Node).where(Node.asset_id == asset.id, Node.revoked_at.is_(None))
        ).scalars().first()
        return ScanOffer(COLLECT, node=node) if node is not None else ScanOffer(None, NO_NODE)
    if asset.kind == AssetKind.IMAGE and not _image_is_referencable(asset):
        return ScanOffer(None, UNREFERENCABLE_IMAGE)
    if (job_kind := SCAN_JOBS.get(asset.kind)) is not None:
        return ScanOffer(job_kind)
    return ScanOffer(
        None, NOT_SCANNED_DIRECTLY.get(asset.kind, f"A {asset.kind} asset is not scanned.")
    )


def scan_job_key(asset: Asset) -> str:
    return f"{asset.id}:{datetime.now(UTC).isoformat(timespec='seconds')}"


@router.post("/assets/{asset_id}/scan", status_code=status.HTTP_202_ACCEPTED)
def rescan(
    asset_id: str,
    principal: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")

    offer = _scan_offer(session, asset)
    if offer.action is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, offer.reason)

    if offer.action == COLLECT:
        return _collect_from_host(session, asset, offer.node, principal)

    job = enqueue(
        session,
        kind=offer.action,
        key=scan_job_key(asset),
        payload={"asset_id": str(asset.id)},
        priority=3,
    )
    record(
        session,
        actor=principal.actor,
        action="SCAN_REQUESTED",
        subject=f"asset:{asset.id}",
        detail={"job_id": job.id if job else None, "kind": offer.action},
    )
    return {
        "queued": job is not None,
        "job_id": job.id if job else None,
        "message": "Scan queued." if job else "A scan is already queued for this asset.",
    }


def _collect_from_host(
    session: Session, asset: Asset, node: Node, principal: Principal
) -> dict[str, Any]:
    created = enqueue_collection(session, node)
    record(
        session,
        actor=principal.actor,
        action="SCAN_REQUESTED",
        subject=f"asset:{asset.id}",
        detail={"node_id": str(node.id), "tasks": created},
    )
    return {
        "queued": created > 0,
        "tasks": created,
        "message": (
            f"Collection queued: {created} task(s) for {node.display_name}."
            if created
            else "A collection sweep is already in flight for this host."
        ),
    }


@router.get("/coverage")
def get_coverage(
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict[str, Any]:
    return coverage(session)


@router.post("/assets/classify")
def classify(
    body: ClassifyRequest,
    principal: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
    for group in body.groups:
        if group.tier is not None and group.tier not in TIERS:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown tier {group.tier!r}"
            )
        if group.exposure is not None and group.exposure not in EXPOSURES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown exposure {group.exposure!r}"
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
            mark_operator(
                asset,
                *[
                    f for f in ("tier", "exposure")
                    if getattr(group, f) is not None
                ],
            )
            after = (asset.tier, asset.exposure, asset.criticality)
            if before == after:
                continue
            changed += 1
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


class BaselineRequest(BaseModel):
    asset_id: str | None = None
    move_existing: bool = False


def _baseline_preview(session: Session, asset_id: str | None) -> dict[str, Any]:
    from athena.findings.query import _is_new

    stmt = (
        select(func.count(func.distinct(Finding.group_key)), func.count())
        .select_from(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(Asset.tombstoned_at.is_(None), _is_new(), *_LISTED)
    )
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    groups, findings = session.execute(stmt).one()

    assets = select(func.count()).select_from(Asset).where(
        Asset.tombstoned_at.is_(None), Asset.baseline_at.is_(None)
    )
    if asset_id:
        assets = assets.where(Asset.id == asset_id)
    from athena.findings import FindingQuery, query_findings

    before = query_findings(
        session, FindingQuery(limit=1, asset_id=asset_id)
    ).matching_group_count
    return {
        "vulnerabilities": groups,
        "findings": findings,
        "assets_without_baseline": session.execute(assets).scalar_one(),
        "default_view_now": before,
        "would_leave_default_view": max(0, before - _exempt_count(session, asset_id)),
        "stays_visible": _exempt_count(session, asset_id),
    }


def _exempt_count(session: Session, asset_id: str | None) -> int:
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
            *_LISTED,
        )
    )
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    return session.execute(stmt).scalar_one()


@router.get("/baseline")
def baseline_status(
    asset_id: str | None = None,
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict[str, Any]:
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
    principal: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
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
    principal: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict[str, Any]:
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
