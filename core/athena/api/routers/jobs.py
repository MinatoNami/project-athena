from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.api.deps import OPERATE_ROLES, Principal, can_operate, can_read, db
from athena.api.routers.assets import SCAN_JOBS, _scan_offer, scan_job_key
from athena.audit import record, record_isolated
from athena.db.models import Asset, Job
from athena.queue import (
    enqueue,
    handlers,  # noqa: F401
    known_kinds,
)
from athena.workers import (
    image,  # noqa: F401
    intel_jobs,  # noqa: F401
    investigate,  # noqa: F401
    node_ingest,  # noqa: F401
    notify_jobs,  # noqa: F401
    repository,  # noqa: F401
    rescore,  # noqa: F401
    suppression_jobs,  # noqa: F401
)

router = APIRouter(prefix="/jobs", tags=["jobs"])


class AssetScanPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: UUID


@dataclass(frozen=True)
class Enqueueable:
    payload: type[BaseModel]
    roles: tuple[str, ...]


USER_ENQUEUEABLE: dict[str, Enqueueable] = {
    kind: Enqueueable(payload=AssetScanPayload, roles=OPERATE_ROLES)
    for kind in sorted(SCAN_JOBS.values())
}


class EnqueueRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=100)
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


def _refuse(principal: Principal, kind: str, reason: str, code: int, detail) -> HTTPException:
    record_isolated(
        actor=principal.actor,
        action="JOB_REFUSED",
        subject=f"job_kind:{kind}",
        detail={"kind": kind, "reason": reason},
    )
    return HTTPException(code, detail)


@router.get("")
def list_jobs(
    limit: int = Query(default=50, le=200),
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict:
    rows = session.execute(select(Job).order_by(Job.id.desc()).limit(limit)).scalars().all()
    return {
        "jobs": [_serialise(j) for j in rows],
        "known_kinds": known_kinds(),
        "enqueueable_kinds": sorted(USER_ENQUEUEABLE),
    }


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def create_job(
    body: EnqueueRequest,
    principal: Principal = Depends(can_operate),
    session: Session = Depends(db),
) -> dict:
    allowed = USER_ENQUEUEABLE.get(body.kind)
    if allowed is None:
        raise _refuse(
            principal,
            body.kind,
            "not user-enqueueable",
            status.HTTP_403_FORBIDDEN,
            f"Job kind {body.kind!r} cannot be enqueued through the API",
        )
    if principal.user.role not in allowed.roles:
        raise _refuse(
            principal,
            body.kind,
            "insufficient role",
            status.HTTP_403_FORBIDDEN,
            "Insufficient role",
        )
    try:
        payload = allowed.payload.model_validate(body.payload)
    except ValidationError as exc:
        raise _refuse(
            principal,
            body.kind,
            "invalid payload",
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            exc.errors(include_url=False, include_context=False, include_input=False),
        ) from None

    asset = session.get(Asset, payload.asset_id)
    if asset is None:
        raise _refuse(
            principal, body.kind, "no such asset", status.HTTP_404_NOT_FOUND, "No such asset"
        )
    if asset.tombstoned_at is not None:
        raise _refuse(
            principal,
            body.kind,
            "asset tombstoned",
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "This asset is tombstoned, so it is not scanned",
        )
    offer = _scan_offer(session, asset)
    if offer.action != body.kind:
        raise _refuse(
            principal,
            body.kind,
            "kind does not fit the asset",
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            offer.reason or f"Job kind {body.kind!r} does not scan a {asset.kind} asset",
        )

    key = scan_job_key(asset)
    job = enqueue(
        session,
        kind=body.kind,
        key=key,
        payload=payload.model_dump(mode="json"),
        priority=body.priority,
    )
    if job is None:
        return {"deduplicated": True, "kind": body.kind, "key": key}

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
    _: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict:
    job = session.get(Job, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such job")
    return _serialise(job)
