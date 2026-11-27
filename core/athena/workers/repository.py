from __future__ import annotations

import pathlib
from typing import Any

import structlog

from athena.audit import record
from athena.codefindings import record_code_scan
from athena.config import get_settings
from athena.db.base import session_scope
from athena.db.models import Asset
from athena.inventory.service import (
    finish_scan,
    record_components,
    start_scan,
)
from athena.queue import enqueue, publish
from athena.queue.registry import handler
from athena.scanners import manifests, misconfig, secrets, startup_hooks, syft
from athena.scanners.git import CheckoutError, clone, remove_checkout
from athena.scanners.sandbox import SandboxError

log = structlog.get_logger(__name__)


@handler("scan.repository")
def scan_repository(payload: dict[str, Any]) -> dict[str, Any]:
    asset_id = payload["asset_id"]
    work_volume = get_settings().work_volume

    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise LookupError(f"No such asset {asset_id}")
        url = asset.attributes.get("clone_url") or asset.attributes.get("url")
        ref = asset.attributes.get("default_branch")
        display = asset.display_name
        if not url:
            run = start_scan(session, asset=asset, kind="repository", tool="syft")
            finish_scan(session, run, status="failed", error="No clone URL configured")
            return {"status": "failed", "reason": "no clone URL"}

    checkout: str | None = None
    try:
        checkout, commit = clone(url, work_volume=work_volume, ref=ref)
        if get_settings().code_scans_enabled:
            try:
                _scan_code(asset_id, checkout, work_volume=work_volume, commit=commit)
            except Exception as exc:  # noqa: BLE001
                log.warning("repository.code_scan_aborted", asset=asset_id, error=str(exc))
        result, tool_version = syft.scan_directory(checkout, work_volume=work_volume)

        if not result.ok:
            reason = result.diagnosis
            _record_failure(asset_id, tool_version, f"syft failed: {reason}",
                            status="timeout" if result.timed_out else "failed",
                            detail=result.stderr[:400])
            return {"status": "failed", "reason": reason}

        components, warnings, notes = syft.parse(result.json())

        declared = manifests.declarations(pathlib.Path(get_settings().work_dir) / checkout)
        manifest_gaps = manifests.gaps(declared, {c.ecosystem for c in components})
        warnings = manifest_gaps + warnings

    except CheckoutError as exc:
        _record_failure(asset_id, None, str(exc), status="failed")
        return {"status": "failed", "reason": "clone failed"}
    except SandboxError as exc:
        _record_failure(asset_id, None, str(exc), status="failed")
        return {"status": "failed", "reason": "sandbox unavailable"}
    finally:
        if checkout:
            remove_checkout(checkout, work_volume=work_volume)

    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        run = start_scan(
            session, asset=asset, kind="repository", tool="syft", tool_version=tool_version
        )
        count = record_components(session, asset=asset, run=run, components=components)

        status = "partial" if warnings else "succeeded"
        finish_scan(
            session,
            run,
            status=status,
            stats={
                "components": count,
                "commit": commit,
                "manifests": [
                    {"path": d.path, "ecosystem": d.ecosystem, "declared": d.declared}
                    for d in declared
                ],
                "warnings": len(warnings),
                "warning_sample": warnings[:10],
                "notes": sorted(set(notes))[:10],
            },
            error=_gap_summary(warnings, gap_count=len(manifest_gaps)),
        )
        asset.attributes = {**asset.attributes, "last_commit": commit}

        record(
            session,
            actor="system:worker",
            action="REPOSITORY_SCANNED",
            subject=f"asset:{asset_id}",
            detail={"components": count, "status": status, "commit": commit[:12]},
        )
        publish(session, topic="assets", subject_id=str(asset_id))
        enqueue(
            session,
            kind="correlate.asset",
            key=f"{asset_id}:repository-scan",
            payload={"asset_id": str(asset_id)},
            priority=4,
        )

    log.info(
        "repository.scanned", asset=display, components=count, status=status,
        warnings=len(warnings), notes=len(set(notes)),
    )
    return {
        "status": status,
        "components": count,
        "warnings": len(warnings),
        "notes": len(set(notes)),
    }


def _image_version(image: str) -> str | None:
    reference = image.split("@", 1)[0]
    tail = reference.rsplit("/", 1)[-1]
    return tail.split(":", 1)[1] if ":" in tail else None


def _scan_code(asset_id: str, checkout: str, *, work_volume: str, commit: str) -> None:
    settings = get_settings()
    scanners = (
        ("secrets", "gitleaks", settings.gitleaks_image),
        ("misconfiguration", "trivy", settings.trivy_image),
    )
    for scan_kind, tool, image in scanners:
        observations = None
        stats: dict[str, Any] = {"commit": commit[:12]}
        version = _image_version(image)
        error = None
        try:
            if scan_kind == "secrets":
                result = secrets.scan(checkout, work_volume=work_volume)
            else:
                result = misconfig.scan(checkout, work_volume=work_volume)
            if not result.ok:
                status = "timeout" if result.timed_out else "failed"
                error = f"{tool} failed: {result.diagnosis}: {result.stderr.strip()[-300:]}"
            elif scan_kind == "secrets":
                observations = secrets.parse(result.stdout, checkout=checkout)
                status = "succeeded"
                stats["scope"] = "working tree only; history not searched"
            else:
                observations, summary = misconfig.parse(result.stdout)
                version = misconfig.version_of(result.stdout) or version
                status = "succeeded"
                stats.update(summary)
        except (SandboxError, ValueError) as exc:
            status, error = "failed", f"{tool}: {exc}"[:500]
        except Exception as exc:  # noqa: BLE001
            status, error = "failed", f"{tool}: {type(exc).__name__}: {exc}"[:500]
            observations = None

        kind = "secret" if scan_kind == "secrets" else "misconfiguration"
        try:
            with session_scope() as session:
                asset = session.get(Asset, asset_id)
                if asset is None:
                    return
                counts = record_code_scan(
                    session, asset=asset, kind=kind, tool=tool, tool_version=version,
                    status=status, observations=observations, error=error, stats=stats,
                )
                publish(session, topic="assets", subject_id=str(asset_id))
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            with session_scope() as session:
                asset = session.get(Asset, asset_id)
                if asset is None:
                    return
                counts = record_code_scan(
                    session, asset=asset, kind=kind, tool=tool, tool_version=version,
                    status=status, stats=stats,
                    error=f"{tool}: results not recorded: {type(exc).__name__}"[:500],
                )
        log.info("repository.code_scanned", asset=asset_id, tool=tool, status=status,
                 **counts)
    _scan_startup_hooks(asset_id, checkout, commit=commit)


def _scan_startup_hooks(asset_id: str, checkout: str, *, commit: str) -> None:
    stats: dict[str, Any] = {"commit": commit[:12]}
    observations = None
    error = None
    try:
        found = startup_hooks.scan_tree(pathlib.Path(get_settings().work_dir) / checkout)
        observations = found.observations
        stats.update(
            pth_files=found.files,
            allowlisted=found.allowlisted[:20],
            unread=found.unread[:20],
            truncated=found.truncated,
        )
        if found.unread or found.truncated:
            status = "partial"
            error = f"{len(found.unread)} .pth file(s) not read" + (
                "; file limit reached" if found.truncated else ""
            )
        else:
            status = "succeeded"
    except Exception as exc:  # noqa: BLE001
        status, error = "failed", f"{startup_hooks.TOOL}: {type(exc).__name__}: {exc}"[:500]
        observations = None
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            return
        counts = record_code_scan(
            session, asset=asset, kind=startup_hooks.KIND, tool=startup_hooks.TOOL,
            tool_version=startup_hooks.TOOL_VERSION, status=status,
            observations=observations, error=error, stats=stats,
        )
        publish(session, topic="assets", subject_id=str(asset_id))
    log.info("repository.code_scanned", asset=asset_id, tool=startup_hooks.TOOL,
             status=status, **counts)


def _gap_summary(warnings: list[str], *, gap_count: int) -> str | None:
    if not warnings:
        return None
    unresolved = len(warnings) - gap_count
    parts = []
    if gap_count:
        parts.append(f"{gap_count} declared ecosystem(s) produced no components")
    if unresolved > 0:
        parts.append(f"{unresolved} component(s) could not be fully resolved")
    return "; ".join(parts)


def _record_failure(
    asset_id: str, tool_version: str | None, error: str, *, status: str, detail: str | None = None
) -> None:
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        run = start_scan(
            session, asset=asset, kind="repository", tool="syft", tool_version=tool_version
        )
        finish_scan(
            session, run, status=status, error=error, stats={"detail": detail} if detail else {}
        )
        record(
            session,
            actor="system:worker",
            action="REPOSITORY_SCAN_FAILED",
            subject=f"asset:{asset_id}",
            detail={"error": error[:500], "status": status},
        )
    log.warning("repository.scan_failed", asset=asset_id, error=error, status=status)
