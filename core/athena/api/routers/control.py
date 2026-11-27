from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from athena.api.deps import Principal, administer_with_step_up, can_read, db, operate_with_step_up
from athena.audit import record
from athena.control import (
    cancel_investigation,
    halt_state,
    is_investigation_paused,
    pause_investigation,
    resume_investigation,
    set_halt,
)
from athena.db.models import Finding

router = APIRouter(tags=["control"])


class HaltRequest(BaseModel):
    reason: str = Field(min_length=4, max_length=2000)


@router.get("/control")
def read_control(
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict[str, Any]:
    return halt_state(session).as_dict()


@router.post("/control/halt")
def halt(
    body: HaltRequest,
    principal: Principal = Depends(administer_with_step_up),
    session: Session = Depends(db),
) -> dict[str, Any]:
    state = set_halt(session, halted=True, reason=body.reason, actor=principal.actor)
    record(
        session,
        actor=principal.actor,
        action="ATHENA_HALTED",
        subject="control",
        detail={"reason": body.reason},
    )
    return state.as_dict()


@router.post("/control/resume")
def resume(
    principal: Principal = Depends(administer_with_step_up),
    session: Session = Depends(db),
) -> dict[str, Any]:
    previous = halt_state(session)
    state = set_halt(session, halted=False, reason=None, actor=principal.actor)
    record(
        session,
        actor=principal.actor,
        action="ATHENA_RESUMED",
        subject="control",
        detail={"was_halted": previous.halted, "halt_reason": previous.reason},
    )
    return state.as_dict()


def _finding(session: Session, finding_id: uuid.UUID) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return finding


@router.post("/findings/{finding_id}/investigation/pause")
def pause(
    finding_id: uuid.UUID,
    principal: Principal = Depends(operate_with_step_up),
    session: Session = Depends(db),
) -> dict[str, Any]:
    _finding(session, finding_id)
    changed = pause_investigation(session, finding_id, actor=principal.actor)
    record(
        session,
        actor=principal.actor,
        action="INVESTIGATION_PAUSED",
        subject=f"finding:{finding_id}",
        detail={"already_paused": not changed},
    )
    return {"finding_id": str(finding_id), "paused": True}


@router.post("/findings/{finding_id}/investigation/unpause")
def unpause(
    finding_id: uuid.UUID,
    principal: Principal = Depends(operate_with_step_up),
    session: Session = Depends(db),
) -> dict[str, Any]:
    _finding(session, finding_id)
    changed = resume_investigation(session, finding_id)
    record(
        session,
        actor=principal.actor,
        action="INVESTIGATION_UNPAUSED",
        subject=f"finding:{finding_id}",
        detail={"was_paused": changed},
    )
    return {"finding_id": str(finding_id), "paused": is_investigation_paused(session, finding_id)}


@router.post("/findings/{finding_id}/investigation/cancel")
def cancel(
    finding_id: uuid.UUID,
    principal: Principal = Depends(operate_with_step_up),
    session: Session = Depends(db),
) -> dict[str, Any]:
    _finding(session, finding_id)
    removed = cancel_investigation(session, finding_id)
    record(
        session,
        actor=principal.actor,
        action="INVESTIGATION_CANCELLED",
        subject=f"finding:{finding_id}",
        detail={"removed_jobs": [str(job_id) for job_id in removed]},
    )
    return {"finding_id": str(finding_id), "removed_jobs": len(removed)}
