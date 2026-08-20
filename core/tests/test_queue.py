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


def test_a_finished_job_does_not_reserve_its_key_forever(session):
    """Deduplication is about not queueing outstanding work twice. Covering finished
    rows meant the scheduler — which buckets keys by interval — could never re-enqueue
    a task after one run, so all scheduled work silently stopped."""
    key = f"hourly-poll-{uuid.uuid4()}"

    first = enqueue(session, kind="system.echo", key=key)
    assert first is not None
    session.commit()

    assert enqueue(session, kind="system.echo", key=key) is None, "still pending"

    job = session.get(type(first), first.id)
    finish(session, job, succeeded=True, result={})
    session.commit()

    again = enqueue(session, kind="system.echo", key=key)
    assert again is not None, "a completed job must free its key for the next cycle"
    assert again.id != first.id


def test_a_failed_job_also_frees_its_key_once_exhausted(session):
    """A failure must not suppress the task for the rest of the bucket."""
    key = f"failing-poll-{uuid.uuid4()}"

    first = enqueue(session, kind="system.fail", key=key, max_attempts=1)
    assert first is not None
    session.commit()

    job = session.get(type(first), first.id)
    job.attempts = 1
    finish(session, job, succeeded=False, error="boom")
    session.commit()

    assert enqueue(session, kind="system.fail", key=key) is not None
