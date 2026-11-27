from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.db.models import Asset, AssetEdge
from athena.inventory.identity import AssetKind

log = structlog.get_logger(__name__)

OPERATOR = "operator"

TIER_ORDER = {"unknown": 0, "personal": 1, "development": 2, "staging": 3, "production": 4}
EXPOSURE_ORDER = {"unknown": 0, "isolated": 1, "internal": 2, "internet": 3}


def _strongest(values: list[str], order: dict[str, int]) -> str | None:
    known = [v for v in values if order.get(v, 0) > 0]
    return max(known, key=lambda v: order[v]) if known else None


def _source(asset: Asset, field: str) -> str | None:
    return (asset.attributes.get("classification") or {}).get(field)


def _set(asset: Asset, field: str, value: str, *, why: str) -> bool:
    if _source(asset, field) == OPERATOR:
        return False
    if getattr(asset, field) == value and _source(asset, field) == why:
        return False
    setattr(asset, field, value)
    marks = dict(asset.attributes.get("classification") or {})
    marks[field] = why
    asset.attributes = {**asset.attributes, "classification": marks}
    return True


def mark_operator(asset: Asset, *fields: str) -> None:
    marks = dict(asset.attributes.get("classification") or {})
    for field in fields:
        marks[field] = OPERATOR
    asset.attributes = {**asset.attributes, "classification": marks}


def derive(session: Session) -> dict[str, int]:
    live = session.execute(
        select(Asset).where(Asset.tombstoned_at.is_(None))
    ).scalars().all()
    by_id = {a.id: a for a in live}

    edges = session.execute(
        select(AssetEdge.src_id, AssetEdge.dst_id, AssetEdge.relation)
    ).all()
    runs_on: dict[Any, list[Any]] = {}
    built_from: dict[Any, list[Any]] = {}
    for src, dst, relation in edges:
        if relation == "runs_on":
            runs_on.setdefault(dst, []).append(src)
        elif relation == "built_from":
            built_from.setdefault(dst, []).append(src)

    counts = {"host_exposure": 0, "container_tier": 0, "image_tier": 0}

    for host in (a for a in live if a.kind == AssetKind.HOST):
        services = [
            by_id[sid] for sid in runs_on.get(host.id, [])
            if sid in by_id and by_id[sid].kind == AssetKind.SERVICE
        ]
        strongest = _strongest([s.exposure for s in services], EXPOSURE_ORDER)
        if strongest is None:
            continue
        reachable = sum(1 for s in services if s.exposure != "isolated")
        why = (
            f"observed: {reachable} of {len(services)} listening services accept "
            "connections from off-host"
            if reachable
            else f"observed: all {len(services)} listening services are loopback-only"
        )
        counts["host_exposure"] += _set(host, "exposure", strongest, why=why)

    for container in (a for a in live if a.kind == AssetKind.CONTAINER):
        hosts = [
            by_id[h] for h in _dsts(edges, container.id, "runs_on")
            if h in by_id and by_id[h].kind == AssetKind.HOST
        ]
        strongest = _strongest([h.tier for h in hosts], TIER_ORDER)
        if strongest is None:
            continue
        counts["container_tier"] += _set(
            container, "tier", strongest,
            why=f"inherited from {hosts[0].display_name}, the host it runs on",
        )

    for image in (a for a in live if a.kind == AssetKind.IMAGE):
        containers = [
            by_id[c] for c in built_from.get(image.id, []) if c in by_id
        ]
        strongest = _strongest([c.tier for c in containers], TIER_ORDER)
        if strongest is None:
            continue
        counts["image_tier"] += _set(
            image, "tier", strongest,
            why=(
                f"inherited from {len(containers)} container(s) running it, the "
                f"most consequential of which is {strongest}"
            ),
        )

    log.info("classify.derived", **counts)
    return counts


def _dsts(edges: list, src_id: Any, relation: str) -> list[Any]:
    return [d for s, d, r in edges if s == src_id and r == relation]
