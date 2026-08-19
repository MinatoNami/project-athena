from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.audit import record
from athena.db.models import Job
from athena.queue import (
    enqueue,
    handlers,  # noqa: F401  (registers handlers so kinds resolve)
    known_kinds,
)
from athena.workers import repository  # noqa: F401  (registers scan.repository)

router = APIRouter(prefix="/jobs", tags=["jobs"])


class EnqueueRequest(BaseModel):
    kind: str
    key: str = Field(min_length=1, max_length=200)
    payload: dict = Field(default_factory=dict)
    priority: int = Field(default=5, ge=0, le=9)


def _serialise(j: Job) -> dict:
    return {
        "id": j.id,
        "kind": j.kind,
        "key": j.key,
        "priority": j.priority,
        "attempts": j.attempts,
        "started_at": j.started_at,
        "finished_at": j.finished_at,
        "succeeded": j.succeeded,
        "last_error": j.last_error,
        "result": j.result,
    }


@router.get("")
def list_jobs(
    limit: int = Query(default=50, le=200),
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict:
    rows = session.execute(select(Job).order_by(Job.id.desc()).limit(limit)).scalars().all()
    return {"jobs": [_serialise(j) for j in rows], "known_kinds": known_kinds()}


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def create_job(
    body: EnqueueRequest,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict:
    if body.kind not in known_kinds():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown job kind {body.kind!r}")

    job = enqueue(
        session, kind=body.kind, key=body.key, payload=body.payload, priority=body.priority
    )
    if job is None:
        return {"deduplicated": True, "kind": body.kind, "key": body.key}

    record(
        session,
        actor=principal.actor,
        action="JOB_ENQUEUED",
        subject=f"job:{job.id}",
        detail={"kind": job.kind, "key": job.key},
    )
    return {"deduplicated": False, **_serialise(job)}


@router.get("/{job_id}")
def get_job(
    job_id: int,
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict:
    job = session.get(Job, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such job")
    return _serialise(job)
