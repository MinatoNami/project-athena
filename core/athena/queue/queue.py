"""Postgres-backed job queue.

`SELECT ... FOR UPDATE SKIP LOCKED` with a lease, so a worker that dies releases its
job when the lease elapses rather than wedging it. `UNIQUE (kind, key)` makes
enqueueing idempotent: the same scan requested twice is one job.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from athena.config import get_settings
from athena.db.models import Job, Outbox


def enqueue(
    session: Session,
    *,
    kind: str,
    key: str,
    payload: dict[str, Any] | None = None,
    priority: int = 5,
    run_after: datetime | None = None,
    max_attempts: int = 5,
) -> Job | None:
    """Enqueue idempotently. Returns None when an identical job is already pending."""
    row = session.execute(
        text(
            """
            INSERT INTO job (kind, key, payload, priority, run_after, max_attempts)
            VALUES (:kind, :key, CAST(:payload AS jsonb), :priority,
                    COALESCE(:run_after, now()), :max_attempts)
            ON CONFLICT (kind, key) DO NOTHING
            RETURNING id
            """
        ),
        {
            "kind": kind,
            "key": key,
            "payload": _json(payload or {}),
            "priority": priority,
            "run_after": run_after,
            "max_attempts": max_attempts,
        },
    ).first()
    if row is None:
        return None
    return session.get(Job, row.id)


# Two complete literals rather than an interpolated fragment: nothing is built from
# a variable, so there is no injection surface to reason about. Values are always
# bound parameters.
_CLAIM_SQL = """
    WITH candidate AS (
        SELECT id FROM job
         WHERE finished_at IS NULL
           AND run_after <= now()
           AND (lease_until IS NULL OR lease_until < now())
           {kind_clause}
         ORDER BY priority, run_after
         FOR UPDATE SKIP LOCKED
         LIMIT 1
    )
    UPDATE job SET
        started_at  = COALESCE(started_at, now()),
        attempts    = attempts + 1,
        lease_until = now() + make_interval(secs => :lease)
     WHERE id IN (SELECT id FROM candidate)
    RETURNING id
"""
CLAIM_ANY = _CLAIM_SQL.format(kind_clause="")
CLAIM_OF_KIND = _CLAIM_SQL.format(kind_clause="AND kind = ANY(:kinds)")


def claim(session: Session, *, kinds: list[str] | None = None) -> Job | None:
    """Claim one runnable job, or None. The caller owns it until the lease expires."""
    lease = get_settings().job_lease_seconds
    sql, params = (
        (CLAIM_OF_KIND, {"lease": lease, "kinds": kinds})
        if kinds
        else (CLAIM_ANY, {"lease": lease})
    )
    row = session.execute(text(sql), params).first()
    if row is None:
        return None
    return session.get(Job, row.id)


def finish(
    session: Session,
    job: Job,
    *,
    succeeded: bool,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    """Complete a job, or release it for retry with backoff if attempts remain."""
    if succeeded or job.attempts >= job.max_attempts:
        job.finished_at = datetime.now(UTC)
        job.succeeded = succeeded
        job.result = result
        job.last_error = error
        job.lease_until = None
    else:
        backoff = min(300, 2**job.attempts)
        job.run_after = datetime.now(UTC) + timedelta(seconds=backoff)
        job.lease_until = None
        job.last_error = error
    session.flush()


def publish(session: Session, *, topic: str, subject_id: str, version: int = 1) -> None:
    """Emit a domain event. Identity only — subscribers refetch through the API."""
    session.add(Outbox(topic=topic, subject_id=str(subject_id), version=version))


def _json(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, separators=(",", ":"), default=str)
