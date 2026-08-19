"""Inventory operations.

Two rules govern everything here:

  1. An observation is never recorded without its provenance (which scan run, which
     tool, at what time).
  2. Nothing is ever marked inventoried unless the scan that produced it actually
     succeeded. A partial scan leaves the asset stale, not clean.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from athena.db.models import Asset, Component, ScanRun
from athena.inventory.identity import AssetKind
from athena.inventory.purl import build_purl, normalise_name

# How long before an asset's inventory is considered stale. Deliberately per-kind:
# a repository changes when someone pushes, a host drifts continuously.
STALENESS: dict[str, timedelta] = {
    AssetKind.HOST: timedelta(hours=24),
    AssetKind.REPOSITORY: timedelta(days=7),
    AssetKind.IMAGE: timedelta(days=7),
    AssetKind.CONTAINER: timedelta(hours=24),
    AssetKind.SERVICE: timedelta(hours=24),
    AssetKind.NETWORK_HOST: timedelta(days=7),
}
DEFAULT_STALENESS = timedelta(hours=24)

# Scan outcomes that justify calling an asset inventoried.
CONCLUSIVE = {"succeeded"}


@dataclass(frozen=True)
class ObservedComponent:
    ecosystem: str
    name: str
    version: str
    scope: str = "unknown"         # direct | transitive | os | runtime | unknown
    purl: str | None = None
    cpe: str | None = None
    install_path: str | None = None
    is_running: bool | None = None


# ─── assets ──────────────────────────────────────────────────────────────────


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
    """Find or create an asset by identity. Returns (asset, created)."""
    kind = str(AssetKind(kind))
    existing = session.execute(
        select(Asset).where(Asset.kind == kind, Asset.identity_key == identity_key)
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    if existing is not None:
        existing.last_seen = now
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
    """Record a relationship. Re-observing refreshes it rather than duplicating it."""
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
    """Record that two assets might be the same, for a human to confirm.

    Never merges. A wrong merge corrupts history irreversibly; a wrong split is untidy.
    """
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
    """Retire an asset without deleting it, so its history stays auditable."""
    asset.tombstoned_at = datetime.now(UTC)


# ─── scan runs ───────────────────────────────────────────────────────────────


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
    """Close a scan run and, only on a conclusive result, mark the asset inventoried.

    This is the single place that sets `last_inventoried_at`. A partial, failed, or
    timed-out scan deliberately leaves the asset looking stale, because that is the
    truth: we do not know its current state.
    """
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


# ─── components ──────────────────────────────────────────────────────────────


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
    """Attach observed components to an asset, tagged with the run that saw them.

    `replace` drops rows this scan did not re-observe, so a removed dependency
    disappears — but only ever within a run that completed, never a partial one.
    """
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


# ─── coverage ────────────────────────────────────────────────────────────────


def is_stale(asset: Asset, *, now: datetime | None = None) -> bool:
    if asset.last_inventoried_at is None:
        return True
    now = now or datetime.now(UTC)
    return asset.last_inventoried_at < now - STALENESS.get(asset.kind, DEFAULT_STALENESS)


def coverage(session: Session) -> dict[str, Any]:
    """The honest answer to "is everything being watched?".

    `never_scanned` is the number that matters: those assets are unknown, and no
    aggregate elsewhere may present them as clean.
    """
    now = datetime.now(UTC)
    rows = session.execute(
        select(Asset.kind, Asset.id, Asset.display_name, Asset.last_inventoried_at).where(
            Asset.tombstoned_at.is_(None)
        )
    ).all()

    total = len(rows)
    never: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []

    for kind, asset_id, name, inventoried in rows:
        if inventoried is None:
            never.append({"id": str(asset_id), "kind": kind, "display_name": name})
        elif inventoried < now - STALENESS.get(kind, DEFAULT_STALENESS):
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
        # Explicitly not a percentage of "assets we know about and looked at" — the
        # denominator is every registered asset, so a gap cannot hide in the ratio.
        "coverage_ratio": round(fresh / total, 4) if total else None,
        "inconclusive_scans_24h": failed_scans,
        "never_scanned": never[:50],
        "stale": stale[:50],
    }
