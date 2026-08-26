"""Suppressing findings, and undoing it.

Every route here is a decision somebody is accountable for, so each writes an audit
event and none of them delete anything: a revoked suppression stays, because "who
decided to stop showing this, and who changed their mind" is exactly the question a
trail exists to answer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.db.models import Asset, Finding, Suppression, Vulnerability
from athena.suppression import (
    REASON_CODES,
    SuppressionError,
    active_predicate,
    create_suppression,
    revoke_suppression,
)

router = APIRouter(tags=["suppressions"])


class SuppressRequest(BaseModel):
    reason_code: str
    reason: str = Field(min_length=8, max_length=2000)
    scope: str = "finding"
    expires_at: datetime | None = None


def _serialise(session: Session, s: Suppression) -> dict[str, Any]:
    asset = session.get(Asset, s.asset_id) if s.asset_id else None
    now = datetime.now(UTC)
    expired = s.expires_at is not None and s.expires_at <= now
    return {
        "id": str(s.id),
        "vulnerability_id": s.vulnerability_id,
        "asset_id": str(s.asset_id) if s.asset_id else None,
        "asset": asset.display_name if asset else None,
        "component_id": str(s.component_id) if s.component_id else None,
        "scope": "finding" if s.component_id else ("asset" if s.asset_id else "everywhere"),
        "reason_code": s.reason_code,
        "reason": s.reason,
        "reason_label": REASON_CODES.get(s.reason_code, s.reason_code),
        # What the decision rested on, kept so it can be argued with later.
        "premise": s.premise,
        "created_by": s.created_by,
        "created_at": s.created_at,
        "expires_at": s.expires_at,
        "revoked_at": s.revoked_at,
        "revoked_by": s.revoked_by,
        "invalidated_at": s.invalidated_at,
        # Why the finding came back, in the words shown on the finding itself.
        "invalidated_reason": s.invalidated_reason,
        "expired": expired,
        "active": s.revoked_at is None and s.invalidated_at is None and not expired,
    }


@router.get("/suppressions")
def list_suppressions(
    active_only: bool = True,
    limit: int = Query(default=100, le=500),
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    stmt = select(Suppression).order_by(Suppression.created_at.desc()).limit(limit)
    if active_only:
        stmt = stmt.where(active_predicate())
    rows = session.execute(stmt).scalars().all()
    return {
        "suppressions": [_serialise(session, s) for s in rows],
        "reason_codes": REASON_CODES,
    }


@router.post("/findings/{finding_id}/suppress", status_code=status.HTTP_201_CREATED)
def suppress(
    finding_id: str,
    body: SuppressRequest,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Stop showing a finding, and record what that decision rested on."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such finding")

    try:
        suppression = create_suppression(
            session,
            finding=finding,
            reason_code=body.reason_code,
            reason=body.reason,
            scope=body.scope,
            expires_at=body.expires_at,
            actor=principal.actor,
        )
    except SuppressionError as exc:
        # The message is written for the operator, so it is passed through rather
        # than replaced with a generic rejection.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    return _serialise(session, suppression)


@router.post("/suppressions/{suppression_id}/revoke")
def revoke(
    suppression_id: str,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Put the findings back. The suppression is kept, marked revoked."""
    suppression = session.get(Suppression, suppression_id)
    if suppression is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such suppression")
    try:
        revoke_suppression(session, suppression=suppression, actor=principal.actor)
    except SuppressionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _serialise(session, suppression)


@router.get("/findings/{finding_id}/suppression")
def suppression_for_finding(
    finding_id: str,
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """The live suppression covering this finding, if any.

    Also returns the most recent dead one, so a finding that came back can say why
    rather than simply reappearing.
    """
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such finding")

    from athena.suppression.service import scope_matches_finding

    base = (
        select(Suppression)
        .join(Finding, scope_matches_finding())
        .where(Finding.id == finding.id)
    )
    live = session.execute(base.where(active_predicate())).scalars().first()
    lapsed = session.execute(
        base.where(~active_predicate()).order_by(Suppression.created_at.desc())
    ).scalars().first()
    return {
        "active": _serialise(session, live) if live else None,
        "lapsed": _serialise(session, lapsed) if lapsed else None,
    }
