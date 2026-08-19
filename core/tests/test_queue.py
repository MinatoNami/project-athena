from __future__ import annotations

import uuid

from athena.queue import claim, enqueue, finish


def test_enqueue_is_idempotent_on_kind_and_key(session):
    first = enqueue(session, kind="system.echo", key="dedup-probe", payload={"n": 1})
    session.flush()
    second = enqueue(session, kind="system.echo", key="dedup-probe", payload={"n": 2})

    assert first is not None
    assert second is None, "the same kind+key must not enqueue twice"


def test_claim_returns_a_job_then_leases_it(session):
    enqueue(session, kind="system.echo", key="claim-probe", payload={})
    session.commit()

    job = claim(session, kinds=["system.echo"])
    assert job is not None
    assert job.attempts == 1
    assert job.lease_until is not None


def test_failed_job_retries_until_attempts_are_exhausted(session):
    """A job with attempts remaining is rescheduled; an exhausted one terminates.

    Asserts on the enqueued row by id rather than on whatever `claim` happens to
    return, so a concurrent worker cannot make this pass or fail by coincidence.
    """
    from athena.db.models import Job

    created = enqueue(
        session, kind="system.fail", key=f"retry-probe-{uuid.uuid4()}", max_attempts=2
    )
    assert created is not None
    job_id = created.id
    session.commit()

    job = session.get(Job, job_id)
    job.attempts = 1
    finish(session, job, succeeded=False, error="first failure")
    assert job.finished_at is None, "a job with attempts remaining must be rescheduled"
    assert job.run_after is not None, "a retry must be delayed by backoff"

    job.attempts = 2
    finish(session, job, succeeded=False, error="second failure")
    assert job.finished_at is not None, "exhausted attempts must terminate the job"
    assert job.succeeded is False
    assert job.last_error == "second failure"
