from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.api.routers.exports import is_uuid
from athena.codefindings import GUIDANCE
from athena.db.models import Asset, CodeFinding, ScanRun

router = APIRouter(tags=["code"])

KINDS = ("secret", "misconfiguration", "startup-hook")
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _serialise(finding: CodeFinding, asset: Asset) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "kind": finding.kind,
        "tool": finding.tool,
        "tool_version": finding.tool_version,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "path": finding.path,
        "line": finding.line,
        "detail": finding.detail,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "resolved_at": finding.resolved_at,
        "asset": {
            "id": str(asset.id),
            "display_name": asset.display_name,
            "tier": asset.tier,
            "exposure": asset.exposure,
        },
    }


def _coverage(session: Session, asset_id: str | None) -> dict[str, Any]:
    repos = select(Asset.id).where(Asset.kind == "repository", Asset.tombstoned_at.is_(None))
    if asset_id:
        repos = repos.where(Asset.id == asset_id)
    total = session.execute(select(func.count()).select_from(repos.subquery())).scalar_one()
    out: dict[str, Any] = {"repositories": total}
    for kind in KINDS:
        latest = (
            select(ScanRun.asset_id, func.max(ScanRun.finished_at).label("at"))
            .where(ScanRun.kind == kind, ScanRun.status == "succeeded", ScanRun.asset_id.in_(repos))
            .group_by(ScanRun.asset_id)
            .subquery()
        )
        scanned, oldest, newest = session.execute(
            select(func.count(), func.min(latest.c.at), func.max(latest.c.at)).select_from(latest)
        ).one()
        last_attempt = (
            select(
                ScanRun.status,
                func.row_number()
                .over(
                    partition_by=ScanRun.asset_id,
                    order_by=(ScanRun.finished_at.desc().nulls_last(), ScanRun.id.desc()),
                )
                .label("n"),
            )
            .where(ScanRun.kind == kind, ScanRun.asset_id.in_(repos))
            .subquery()
        )
        failing = session.execute(
            select(func.count())
            .select_from(last_attempt)
            .where(last_attempt.c.n == 1, last_attempt.c.status != "succeeded")
        ).scalar_one()
        out[kind] = {
            "scanned": scanned,
            "never_succeeded": total - scanned,
            "failing": failing,
            "oldest_success": oldest,
            "latest_success": newest,
        }
    return out


@router.get("/code-findings")
def list_code_findings(
    asset_id: str | None = None,
    kind: str | None = None,
    include_resolved: bool = False,
    limit: int = Query(default=200, le=1000),
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    if asset_id is not None and not is_uuid(asset_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such asset")
    if kind is not None and kind not in KINDS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"kind must be one of {', '.join(KINDS)}"
        )
    stmt = (
        select(CodeFinding, Asset)
        .join(Asset, Asset.id == CodeFinding.asset_id)
        .where(Asset.tombstoned_at.is_(None))
    )
    if asset_id:
        stmt = stmt.where(CodeFinding.asset_id == asset_id)
    if kind:
        stmt = stmt.where(CodeFinding.kind == kind)
    if not include_resolved:
        stmt = stmt.where(CodeFinding.resolved_at.is_(None))
    rows = session.execute(stmt).all()
    rows.sort(
        key=lambda r: (
            r[0].resolved_at is not None,
            r[0].kind != "secret",
            _SEVERITY_RANK.get(r[0].severity, 5),
            r[1].display_name,
            r[0].path,
            r[0].line or 0,
        )
    )

    counts: dict[str, dict[str, int]] = {k: {} for k in KINDS}
    open_rows = (
        select(CodeFinding.kind, CodeFinding.severity, func.count())
        .join(Asset, Asset.id == CodeFinding.asset_id)
        .where(Asset.tombstoned_at.is_(None), CodeFinding.resolved_at.is_(None))
        .group_by(CodeFinding.kind, CodeFinding.severity)
    )
    if asset_id:
        open_rows = open_rows.where(CodeFinding.asset_id == asset_id)
    for finding_kind, severity, n in session.execute(open_rows).all():
        counts.setdefault(finding_kind, {})[severity] = n

    return {
        "findings": [_serialise(f, a) for f, a in rows[:limit]],
        "total": len(rows),
        "open_counts": counts,
        "coverage": _coverage(session, asset_id),
        "guidance": GUIDANCE,
    }
