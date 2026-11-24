"""Repository patrol.

Clone → SBOM → components, with the outcome recorded honestly at every exit. The
handler is written so that no failure path can leave an asset looking inventoried.
"""

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
from athena.queue import publish
from athena.queue.registry import handler
from athena.scanners import manifests, misconfig, secrets, syft
from athena.scanners.git import CheckoutError, clone, remove_checkout
from athena.scanners.sandbox import SandboxError

log = structlog.get_logger(__name__)


@handler("scan.repository")
def scan_repository(payload: dict[str, Any]) -> dict[str, Any]:
    """Inventory one repository.

    Every outcome is written to the scan run: succeeded, partial (we saw something but
    not everything), or failed. Only `succeeded` marks the asset inventoried.
    """
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
        # Before the SBOM, and recorded independently of it: a repository whose
        # Syft run keeps failing still deserves to know it has a key committed.
        if get_settings().code_scans_enabled:
            # A code scan must never cost the SBOM. `_scan_code` records its own
            # failures; this is for what it could not record.
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

        # The one check the SBOM cannot perform on itself. Syft reported 754 npm
        # packages for this repository and nothing else, and every downstream check
        # asked whether what it found was sound — none could ask whether it had
        # looked at `core/pyproject.toml` at all. Reading the tree answers that.
        declared = manifests.declarations(pathlib.Path(get_settings().work_dir) / checkout)
        manifest_gaps = manifests.gaps(declared, {c.ecosystem for c in components})
        # First, not appended. A whole ecosystem being invisible outranks any
        # number of individually unresolved artifacts, and the sample kept on the
        # run is capped at ten.
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

        # Only a genuine gap downgrades the scan. An ecosystem Athena cannot map is a
        # known limitation recorded as a note — treating it as an incomplete scan
        # would leave such repositories permanently stale and make coverage useless.
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
    """`ghcr.io/x/gitleaks:v8.30.1@sha256:…` → `v8.30.1`."""
    reference = image.split("@", 1)[0]
    tail = reference.rsplit("/", 1)[-1]
    return tail.split(":", 1)[1] if ":" in tail else None


def _scan_code(asset_id: str, checkout: str, *, work_volume: str, commit: str) -> None:
    """Secrets (Gitleaks) and misconfigurations (Trivy) over the same checkout.

    Each scanner's outcome is its own scan run in its own transaction. One failing —
    an image that cannot be pulled on an air-gapped host, a timeout on a huge tree —
    is recorded as that scanner's inconclusive run and leaves the other, and the
    SBOM, untouched.
    """
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
                # Said on every run, because it is the scan's honest edge: the
                # checkout is shallow, so history is not searched.
                stats["scope"] = "working tree only; history not searched"
            else:
                observations, summary = misconfig.parse(result.stdout)
                version = misconfig.version_of(result.stdout) or version
                status = "succeeded"
                stats.update(summary)
        except (SandboxError, ValueError) as exc:
            status, error = "failed", f"{tool}: {exc}"[:500]
        except Exception as exc:  # noqa: BLE001 - e.g. a `docker pull` that hung past its timeout
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
        except Exception as exc:  # noqa: BLE001 - e.g. a concurrent patrol's identical row
            # The results could not be stored, so the run is recorded as failed — an
            # unrecorded scan would leave the last success standing as current.
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


def _gap_summary(warnings: list[str], *, gap_count: int) -> str | None:
    """One line saying what kind of incompleteness this was.

    An ecosystem nothing was found for and an artifact whose version would not resolve
    are both gaps, but only the first means a part of the repository was never read —
    so the summary leads with it rather than reporting a single count for both.
    """
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
    """Record an inconclusive scan in its own transaction.

    The job may still be retried, but the fact that this attempt failed must survive
    regardless — an asset whose scans keep failing has to look uncovered, not clean.
    """
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
