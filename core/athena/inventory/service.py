from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, aliased

from athena.db.models import Asset, AssetEdge, Component, ScanRun
from athena.inventory.identity import AssetKind
from athena.inventory.purl import build_purl, normalise_name

STALENESS: dict[str, timedelta] = {
    AssetKind.HOST: timedelta(hours=24),
    AssetKind.REPOSITORY: timedelta(days=7),
    AssetKind.IMAGE: timedelta(days=7),
    AssetKind.CONTAINER: timedelta(hours=24),
    AssetKind.SERVICE: timedelta(hours=24),
    AssetKind.NETWORK_HOST: timedelta(days=7),
}
DEFAULT_STALENESS = timedelta(hours=24)

CONCLUSIVE = {"succeeded"}


@dataclass(frozen=True)
class ObservedComponent:
    ecosystem: str
    name: str
    version: str
    scope: str = "unknown"
    purl: str | None = None
    cpe: str | None = None
    install_path: str | None = None
    is_running: bool | None = None


def register_asset(
    session: Session,
    *,
    kind: AssetKind | str,
    identity_key: str,
    display_name: str,
    attributes: dict[str, Any] | None = None,
    tier: str | None = None,
    owner: str | None = None,
) -> tuple[Asset, bool]:
    kind = str(AssetKind(kind))
    existing = session.execute(
        select(Asset).where(Asset.kind == kind, Asset.identity_key == identity_key)
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    if existing is not None:
        existing.last_seen = now
        existing.tombstoned_at = None
        existing.display_name = display_name or existing.display_name
        if attributes:
            existing.attributes = {**existing.attributes, **attributes}
        if tier:
            existing.tier = tier
        if owner:
            existing.owner = owner
        return existing, False

    asset = Asset(
        kind=kind,
        identity_key=identity_key,
        display_name=display_name,
        attributes=attributes or {},
        tier=tier or "unknown",
        owner=owner,
        first_seen=now,
        last_seen=now,
    )
    session.add(asset)
    session.flush()
    return asset, True


def link(
    session: Session,
    *,
    src: Asset,
    dst: Asset,
    relation: str,
    confidence: float = 1.0,
) -> None:
    session.execute(
        text(
            """
            INSERT INTO asset_edge (src_id, dst_id, relation, observed_at, confidence)
            VALUES (:src, :dst, :rel, now(), :conf)
            ON CONFLICT (src_id, dst_id, relation)
            DO UPDATE SET observed_at = now(), confidence = EXCLUDED.confidence
            """
        ),
        {"src": src.id, "dst": dst.id, "rel": relation, "conf": confidence},
    )


def flag_merge_candidate(
    session: Session, *, asset: Asset, other: Asset, reason: str, confidence: float
) -> None:
    if asset.id == other.id:
        return
    a, b = sorted([asset.id, other.id], key=str)
    session.execute(
        text(
            """
            INSERT INTO merge_candidate (id, asset_id, other_asset_id, reason, confidence)
            VALUES (:id, :a, :b, :reason, :conf)
            ON CONFLICT (asset_id, other_asset_id) DO NOTHING
            """
        ),
        {"id": uuid.uuid4(), "a": a, "b": b, "reason": reason, "conf": confidence},
    )


def tombstone_asset(session: Session, asset: Asset) -> None:
    asset.tombstoned_at = datetime.now(UTC)


def start_scan(
    session: Session, *, asset: Asset | None, kind: str, tool: str, tool_version: str | None = None
) -> ScanRun:
    run = ScanRun(
        asset_id=asset.id if asset else None,
        kind=kind,
        tool=tool,
        tool_version=tool_version,
        status="running",
    )
    session.add(run)
    session.flush()
    return run


def finish_scan(
    session: Session,
    run: ScanRun,
    *,
    status: str,
    stats: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    if status not in {"succeeded", "partial", "failed", "timeout"}:
        raise ValueError(f"Unknown scan status {status!r}")

    run.status = status
    run.finished_at = datetime.now(UTC)
    run.stats = stats or {}
    run.error = error

    if status in CONCLUSIVE and run.asset_id is not None:
        asset = session.get(Asset, run.asset_id)
        if asset is not None:
            asset.last_inventoried_at = run.finished_at
            asset.last_seen = run.finished_at


def upsert_component(session: Session, observed: ObservedComponent) -> Component:
    name = normalise_name(observed.ecosystem, observed.name)
    version = observed.version.strip()
    purl = observed.purl or build_purl(observed.ecosystem, name, version)

    row = session.execute(
        text(
            """
            INSERT INTO component (id, purl, cpe, ecosystem, name, version)
            VALUES (:id, :purl, :cpe, :eco, :name, :version)
            ON CONFLICT (ecosystem, name, version)
            DO UPDATE SET purl = COALESCE(component.purl, EXCLUDED.purl),
                          cpe  = COALESCE(component.cpe,  EXCLUDED.cpe)
            RETURNING id
            """
        ),
        {
            "id": uuid.uuid4(),
            "purl": purl,
            "cpe": observed.cpe,
            "eco": observed.ecosystem.lower(),
            "name": name,
            "version": version,
        },
    ).one()
    return session.get(Component, row.id)


def record_components(
    session: Session,
    *,
    asset: Asset,
    run: ScanRun,
    components: list[ObservedComponent],
    replace: bool = True,
) -> int:
    seen: set[tuple[uuid.UUID, str]] = set()
    for observed in components:
        component = upsert_component(session, observed)
        session.execute(
            text(
                """
                INSERT INTO asset_component
                    (asset_id, component_id, scope, install_path, is_running,
                     observed_at, scan_run_id)
                VALUES (:asset, :component, :scope, :path, :running, now(), :run)
                ON CONFLICT (asset_id, component_id, scope)
                DO UPDATE SET observed_at = now(),
                              scan_run_id = EXCLUDED.scan_run_id,
                              install_path = EXCLUDED.install_path,
                              is_running   = EXCLUDED.is_running
                """
            ),
            {
                "asset": asset.id,
                "component": component.id,
                "scope": observed.scope,
                "path": observed.install_path,
                "running": observed.is_running,
                "run": run.id,
            },
        )
        seen.add((component.id, observed.scope))

    if replace:
        session.execute(
            text(
                "DELETE FROM asset_component "
                " WHERE asset_id = :asset AND scan_run_id <> :run"
            ),
            {"asset": asset.id, "run": run.id},
        )
    return len(seen)


def is_stale(asset: Asset, *, now: datetime | None = None) -> bool:
    if asset.last_inventoried_at is None:
        return True
    now = now or datetime.now(UTC)
    return asset.last_inventoried_at < now - STALENESS.get(asset.kind, DEFAULT_STALENESS)


def _inherited_inventory(session: Session) -> dict[Any, datetime]:
    container = aliased(Asset)
    image = aliased(Asset)
    rows = session.execute(
        select(container.id, image.last_inventoried_at)
        .select_from(AssetEdge)
        .join(container, container.id == AssetEdge.src_id)
        .join(image, image.id == AssetEdge.dst_id)
        .where(
            AssetEdge.relation == "built_from",
            container.kind == AssetKind.CONTAINER,
            image.last_inventoried_at.is_not(None),
        )
    ).all()
    return {asset_id: at for asset_id, at in rows}


def coverage(session: Session) -> dict[str, Any]:
    now = datetime.now(UTC)
    rows = session.execute(
        select(Asset.kind, Asset.id, Asset.display_name, Asset.last_inventoried_at).where(
            Asset.tombstoned_at.is_(None)
        )
    ).all()

    inherited_at = _inherited_inventory(session)
    total = len(rows)
    never: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    inherited = 0

    for kind, asset_id, name, inventoried in rows:
        window_kind = kind
        if inventoried is None and asset_id in inherited_at:
            inventoried = inherited_at[asset_id]
            inherited += 1
            window_kind = AssetKind.IMAGE

        if inventoried is None:
            never.append({"id": str(asset_id), "kind": kind, "display_name": name})
        elif inventoried < now - STALENESS.get(window_kind, DEFAULT_STALENESS):
            stale.append(
                {
                    "id": str(asset_id),
                    "kind": kind,
                    "display_name": name,
                    "last_inventoried_at": inventoried,
                }
            )

    fresh = total - len(never) - len(stale)
    failed_scans = session.execute(
        select(func.count())
        .select_from(ScanRun)
        .where(ScanRun.status.in_(("failed", "partial", "timeout")))
        .where(ScanRun.finished_at > now - timedelta(days=1))
    ).scalar_one()

    return {
        "assets_total": total,
        "assets_fresh": fresh,
        "assets_stale": len(stale),
        "assets_never_scanned": len(never),
        "coverage_ratio": round(fresh / total, 4) if total else None,
        "inconclusive_scans_24h": failed_scans,
        "assets_inherited": inherited,
        "never_scanned": never[:50],
        "stale": stale[:50],
    }
