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
           AND NOT (
               j.kind LIKE 'investigate.%'
               AND (
                   EXISTS (SELECT 1 FROM control_state c WHERE c.halted)
                   OR EXISTS (
                       SELECT 1 FROM investigation_hold h
                        WHERE h.finding_id::text = j.payload->>'finding_id'
                   )
               )
           )
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
    settings = get_settings()
    lease = settings.job_lease_seconds
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
    session.add(Outbox(topic=topic, subject_id=str(subject_id), version=version))


def _json(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, separators=(",", ":"), default=str)
