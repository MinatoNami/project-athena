"""Deriving what can be derived, so a person only decides what needs deciding.

165 of this estate's 192 live assets carry neither a tier nor an exposure, and every
finding on them is scored against an unknown — deliberately pessimistically, since not
knowing is not the same as being safe. The cost is that nothing discriminates: 528
findings awaiting investigation sit on assets whose tier and exposure are both unset,
so the strongest prioritisation signal there is has nothing to say.

Most of that is not a judgement anybody needs to make. A container running on a
production host is production; that is an ownership fact, not a security opinion, and
asking a person to confirm it 73 times is how a classification queue stops being
used. What genuinely needs a person is exposure on things that could be reached
through something else — and that is left alone here rather than guessed at.

Three rules, and the reason each is safe:

Tier flows from where a thing runs. Containers take the tier of their host, and an
image takes the strongest tier of the containers running it, because the consequence
of a flaw in an image is the consequence of the worst place it runs.

A host's exposure comes from its own listening sockets, which is direct evidence
rather than inference — the agent observed them. This is the one derivation that can
*lower* a score, since an unknown exposure is weighted above an internal one on
purpose. Lowering is correct here: unknown is pessimistic precisely because the asset
might be internet-facing, and evidence that it is not is exactly what should relieve
that.

Nothing is derived from absence. An image with no running containers stays unknown
rather than becoming isolated, and a host with no observed services stays unknown
rather than becoming safe.

An operator's decision is never overwritten. Provenance is recorded per field, so a
later pass can tell what it set from what a person set, and the page can say which.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.db.models import Asset, AssetEdge
from athena.inventory.identity import AssetKind

log = structlog.get_logger(__name__)

OPERATOR = "operator"

# Ordered for "the strongest of these". Unknown sits at the bottom so it can never
# win a comparison — an unclassified sibling must not drag a classified one down.
TIER_ORDER = {"unknown": 0, "personal": 1, "development": 2, "staging": 3, "production": 4}
EXPOSURE_ORDER = {"unknown": 0, "isolated": 1, "internal": 2, "internet": 3}


def _strongest(values: list[str], order: dict[str, int]) -> str | None:
    """The most consequential of several, or None if none of them said anything."""
    known = [v for v in values if order.get(v, 0) > 0]
    return max(known, key=lambda v: order[v]) if known else None


def _source(asset: Asset, field: str) -> str | None:
    return (asset.attributes.get("classification") or {}).get(field)


def _set(asset: Asset, field: str, value: str, *, why: str) -> bool:
    """Write a derived value unless a person set this field. Returns whether it moved.

    The provenance string is the explanation shown to an operator, not a code — it has
    to answer "why does Athena think this container is production" on its own.
    """
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
    """Record that a person decided these, so no later pass may overwrite them."""
    marks = dict(asset.attributes.get("classification") or {})
    for field in fields:
        marks[field] = OPERATOR
    asset.attributes = {**asset.attributes, "classification": marks}


def derive(session: Session) -> dict[str, int]:
    """One pass over the graph. Safe to run repeatedly; it converges."""
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

    # 1. A host's exposure, from the sockets the agent actually saw it listening on.
    for host in (a for a in live if a.kind == AssetKind.HOST):
        services = [
            by_id[sid] for sid in runs_on.get(host.id, [])
            if sid in by_id and by_id[sid].kind == AssetKind.SERVICE
        ]
        strongest = _strongest([s.exposure for s in services], EXPOSURE_ORDER)
        if strongest is None:
            continue        # no observed services is not evidence of safety
        reachable = sum(1 for s in services if s.exposure != "isolated")
        why = (
            f"observed: {reachable} of {len(services)} listening services accept "
            "connections from off-host"
            if reachable
            else f"observed: all {len(services)} listening services are loopback-only"
        )
        counts["host_exposure"] += _set(host, "exposure", strongest, why=why)

    # 2. A container's tier, from the host it runs on. Not a security judgement — a
    #    container on the production server is part of production.
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

    # 3. An image's tier, from the containers running it. The consequence of a flaw in
    #    an image is the consequence of the worst place that image runs.
    for image in (a for a in live if a.kind == AssetKind.IMAGE):
        containers = [
            by_id[c] for c in built_from.get(image.id, []) if c in by_id
        ]
        strongest = _strongest([c.tier for c in containers], TIER_ORDER)
        if strongest is None:
            continue        # an image nothing runs stays unknown
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
