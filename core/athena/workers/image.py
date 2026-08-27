"""Container image patrol.

Images are where a modern estate's dependency surface actually lives: a host with
3,252 OS packages may run twenty containers carrying their own trees entirely.

Scanned by digest rather than tag, because a tag is a moving pointer — scanning
"latest" tells you about whatever it points at today, not about what is running.
"""

from __future__ import annotations

from typing import Any

import structlog

from athena.audit import record
from athena.db.base import session_scope
from athena.db.models import Asset
from athena.inventory.service import finish_scan, record_components, start_scan
from athena.queue import publish
from athena.queue.registry import handler
from athena.scanners import syft
from athena.scanners.sandbox import SandboxError

log = structlog.get_logger(__name__)


@handler("scan.image")
def scan_image(payload: dict[str, Any]) -> dict[str, Any]:
    """Inventory one container image."""
    asset_id = payload["asset_id"]

    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise LookupError(f"No such asset {asset_id}")
        digest = asset.attributes.get("digest")
        repository = asset.attributes.get("repository")
        tag = asset.attributes.get("tag")
        display = asset.display_name

    if not repository or repository == "<none>":
        _fail(asset_id, "Image has no repository reference, so it cannot be located")
        return {"status": "failed", "reason": "unreferencable image"}

    # A locally built image has no resolvable repository digest, so `repo@sha256:…`
    # does not name anything the daemon can find. Scan by tag when there is one and
    # record which reference was used, because a tag is a moving pointer and the
    # precision of the result depends on which was possible.
    if tag and tag != "<none>":
        reference, by_digest = f"{repository}:{tag}", False
    elif digest and digest.startswith("sha256:"):
        reference, by_digest = f"{repository}@{digest}", True
    else:
        _fail(asset_id, "Image has neither a usable tag nor a repository digest")
        return {"status": "failed", "reason": "unreferencable image"}

    try:
        result, tool_version = syft.scan_image(reference)
    except SandboxError as exc:
        _fail(asset_id, str(exc))
        return {"status": "failed", "reason": "sandbox unavailable"}

    if not result.ok:
        reason = result.diagnosis
        _fail(
            asset_id,
            f"syft failed ({reason}): {result.stderr.strip()[-300:]}",
            status="timeout" if result.timed_out else "failed",
            tool_version=tool_version,
        )
        return {"status": "failed", "reason": reason}

    components, warnings, notes = syft.parse(result.json())

    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        run = start_scan(
            session, asset=asset, kind="image", tool="syft", tool_version=tool_version
        )
        count = record_components(session, asset=asset, run=run, components=components)
        status = "partial" if warnings else "succeeded"
        finish_scan(
            session,
            run,
            status=status,
            stats={
                "components": count,
                "reference": reference,
                "by_digest": by_digest,
                "warnings": len(warnings),
                "notes": sorted(set(notes))[:10],
            },
            error=(
                f"{len(warnings)} component(s) could not be fully resolved"
                if warnings
                else None
            ),
        )
        record(
            session,
            actor="system:worker",
            action="IMAGE_SCANNED",
            subject=f"asset:{asset_id}",
            detail={"components": count, "status": status, "by_digest": by_digest},
        )
        publish(session, topic="assets", subject_id=str(asset_id))

        from athena.queue import enqueue

        enqueue(
            session,
            kind="correlate.asset",
            key=f"{asset_id}:image-scan",
            payload={"asset_id": str(asset_id)},
            priority=4,
        )

    log.info("image.scanned", image=display, components=count, status=status)
    return {"status": status, "components": count}


def _fail(
    asset_id: str, error: str, *, status: str = "failed", tool_version: str | None = None
) -> None:
    """Record an inconclusive scan so the image looks uncovered, never clean."""
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        run = start_scan(
            session, asset=asset, kind="image", tool="syft", tool_version=tool_version
        )
        finish_scan(session, run, status=status, error=error)
    log.warning("image.scan_failed", asset=asset_id, error=error)
