from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.audit import record
from athena.codefindings.model import CodeObservation
from athena.db.models import Asset, CodeFinding, ScanRun

GUIDANCE = {
    "secret": {
        "summary": (
            "Rotate the credential first, then remove it. Deleting it from the file "
            "does not revoke it, and it remains in the repository's history and in "
            "every clone already made."
        ),
        "steps": [
            "Revoke or rotate the credential with whoever issued it",
            "Check the issuer's logs for use since the commit that added it",
            "Move it to a secret store and reference it at runtime",
            "Remove it from the tree; rewrite history only if the repository is public",
        ],
    },
    "misconfiguration": {
        "summary": (
            "Change the configuration as the check's resolution describes. Nothing is "
            "exposed until it is deployed, so this is fixed in the repository, before "
            "the next build."
        ),
        "steps": [],
    },
}


def record_code_scan(
    session: Session,
    *,
    asset: Asset,
    kind: str,
    tool: str,
    tool_version: str | None,
    status: str,
    observations: list[CodeObservation] | None = None,
    error: str | None = None,
    stats: dict[str, Any] | None = None,
) -> dict[str, int]:
    if status not in {"succeeded", "partial", "failed", "timeout"}:
        raise ValueError(f"Unknown scan status {status!r}")
    now = datetime.now(UTC)
    run = ScanRun(
        asset_id=asset.id,
        kind=kind,
        tool=tool,
        tool_version=tool_version,
        status=status,
        finished_at=now,
        error=error,
    )
    session.add(run)
    session.flush()

    counts = {"new": 0, "seen": 0, "resolved": 0, "reopened": 0, "held": 0}
    seen: set[str] = set()
    present_groups: set[str] = set()
    for obs in observations or []:
        if obs.kind != kind or obs.fingerprint in seen:
            continue
        seen.add(obs.fingerprint)
        if group := obs.detail.get("identity_group"):
            present_groups.add(group)
        existing = session.execute(
            select(CodeFinding).where(
                CodeFinding.asset_id == asset.id, CodeFinding.fingerprint == obs.fingerprint
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                CodeFinding(
                    asset_id=asset.id,
                    kind=obs.kind,
                    tool=tool,
                    tool_version=tool_version,
                    rule_id=obs.rule_id,
                    title=obs.title,
                    severity=obs.severity,
                    path=obs.path,
                    line=obs.line,
                    fingerprint=obs.fingerprint,
                    detail=obs.detail,
                    scan_run_id=run.id,
                    first_seen=now,
                    last_seen=now,
                )
            )
            counts["new"] += 1
            continue
        if existing.resolved_at is not None:
            existing.resolved_at = None
            counts["reopened"] += 1
        counts["seen"] += 1
        existing.last_seen = now
        existing.scan_run_id = run.id
        existing.line = obs.line
        existing.title = obs.title
        existing.severity = obs.severity
        existing.detail = obs.detail
        existing.tool_version = tool_version

    if status == "succeeded":
        stale = (
            session.execute(
                select(CodeFinding).where(
                    CodeFinding.asset_id == asset.id,
                    CodeFinding.kind == kind,
                    CodeFinding.tool == tool,
                    CodeFinding.resolved_at.is_(None),
                    CodeFinding.fingerprint.notin_(seen or {""}),
                )
            )
            .scalars()
            .all()
        )
        for finding in stale:
            if (finding.detail or {}).get("identity_group") in present_groups:
                counts["held"] += 1
                continue
            finding.resolved_at = now
            counts["resolved"] += 1

    run.stats = {**(stats or {}), "findings": len(seen), **counts}
    session.flush()

    if counts["new"] or counts["reopened"] or counts["resolved"] or status != "succeeded":
        record(
            session,
            actor="system:worker",
            action="CODE_SCANNED" if status == "succeeded" else "CODE_SCAN_INCONCLUSIVE",
            subject=f"asset:{asset.id}",
            detail={"kind": kind, "tool": tool, "status": status, **counts},
        )
    return counts
