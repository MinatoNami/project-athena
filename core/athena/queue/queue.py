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
    """Enqueue idempotently. Returns None when an identical job is already pending.

    Deduplication covers pending work only. A finished job must not reserve its key
    forever: the scheduler buckets keys by interval, so a completed or failed poll
    would otherwise block every later poll with the same key.
    """
    row = session.execute(
        text(
            """
            INSERT INTO job (kind, key, payload, priority, run_after, max_attempts)
            VALUES (:kind, :key, CAST(:payload AS jsonb), :priority,
                    COALESCE(:run_after, now()), :max_attempts)
            ON CONFLICT (kind, key) WHERE finished_at IS NULL DO NOTHING
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
#
# The `inflight` term is a fairness cap. Without it a large backfill occupies every
# worker slot and starves everything else indefinitely — on the deployed host 805
# queued correlation jobs held all four slots while image scans waited behind them.
# Capping each kind below the pool size guarantees at least one slot is always
# reachable by some other kind, whatever the queue looks like.
_CLAIM_SQL = """
    WITH inflight AS (
        SELECT kind, count(*) AS running
          FROM job
         WHERE finished_at IS NULL AND lease_until > now()
         GROUP BY kind
    ), candidate AS (
        SELECT j.id FROM job j
         LEFT JOIN inflight i ON i.kind = j.kind
         WHERE j.finished_at IS NULL
           AND j.run_after <= now()
           AND (j.lease_until IS NULL OR j.lease_until < now())
           AND COALESCE(i.running, 0) < :kind_cap
           {kind_clause}
         ORDER BY j.priority, j.run_after
         FOR UPDATE OF j SKIP LOCKED
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
CLAIM_OF_KIND = _CLAIM_SQL.format(kind_clause="AND j.kind = ANY(:kinds)")


def claim(session: Session, *, kinds: list[str] | None = None) -> Job | None:
    """Claim one runnable job, or None. The caller owns it until the lease expires."""
    settings = get_settings()
    lease = settings.job_lease_seconds
    # At least one slot stays reachable by another kind, however deep the queue.
    kind_cap = max(1, settings.worker_concurrency - 1)

    base = {"lease": lease, "kind_cap": kind_cap}
    sql, params = (
        (CLAIM_OF_KIND, {**base, "kinds": kinds}) if kinds else (CLAIM_ANY, base)
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
