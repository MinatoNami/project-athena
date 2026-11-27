from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text

from athena.control import (
    Halted,
    cancel_investigation,
    halt_state,
    pause_investigation,
    resume_investigation,
    set_halt,
)
from athena.queue import claim, enqueue


@pytest.fixture
def unhalted(session):
    set_halt(session, halted=False, reason=None, actor="test")
    session.commit()
    yield
    session.rollback()
    set_halt(session, halted=False, reason=None, actor="test")
    session.commit()


def _make_finding(session):
    from athena.db.models import Asset, Component, Finding, Vulnerability

    cve = f"CVE-2099-{uuid.uuid4().int % 100000:05d}"
    asset = Asset(
        kind="host",
        identity_key=f"k:{uuid.uuid4()}",
        display_name=f"host-{cve}",
        tier="production",
        exposure="internet",
        last_inventoried_at=datetime.now(UTC),
    )
    component = Component(ecosystem="deb", name=f"lib-{uuid.uuid4().hex[:8]}", version="1.0.0")
    vulnerability = Vulnerability(
        id=cve,
        summary=f"summary for {cve}",
        kev=False,
        content_hash=f"h-{cve}",
        published_at=datetime.now(UTC),
    )
    session.add_all([asset, component, vulnerability])
    session.flush()
    now = datetime.now(UTC)
    finding = Finding(
        group_key=cve,
        vulnerability_id=cve,
        asset_id=asset.id,
        component_id=component.id,
        state="discovered",
        match_method="distro_advisory",
        match_confidence=0.95,
        fixed_version="1.0.1",
        fix_channel="standard",
        advisory_revision=1,
        first_seen=now,
        state_changed_at=now,
    )
    session.add(finding)
    session.flush()
    return finding, asset, component, vulnerability


@pytest.fixture
def finding(session, unhalted):
    from sqlalchemy import delete

    from athena.db.models import Asset, Component, Finding, Vulnerability

    made, asset, component, vulnerability = _make_finding(session)
    session.commit()
    yield made
    session.rollback()
    cancel_investigation(session, made.id)
    session.execute(delete(Finding).where(Finding.id == made.id))
    session.execute(delete(Asset).where(Asset.id == asset.id))
    session.execute(delete(Component).where(Component.id == component.id))
    session.execute(delete(Vulnerability).where(Vulnerability.id == vulnerability.id))
    session.commit()


def _investigation(session, finding_id):
    job = enqueue(
        session,
        kind="investigate.finding",
        key=str(finding_id),
        payload={"finding_id": str(finding_id)},
        priority=0,
    )
    assert job is not None
    return job.id


def _pending(session, job_id) -> bool:
    from athena.db.models import Job

    session.expire_all()
    job = session.get(Job, job_id)
    return job is not None and job.finished_at is None and job.lease_until is None


def test_halt_withholds_investigations_but_other_kinds_still_run(session, finding):
    investigation = _investigation(session, finding.id)
    echo = enqueue(session, kind="system.echo", key=f"halt-{uuid.uuid4()}", priority=0)
    session.commit()

    set_halt(session, halted=True, reason="incident drill", actor="user:test")
    session.commit()

    assert claim(session, kinds=["investigate.finding"]) is None
    assert _pending(session, investigation)
    other = claim(session, kinds=["system.echo"])
    assert other is not None and other.id == echo.id
    session.commit()

    set_halt(session, halted=False, reason=None, actor="user:test")
    session.commit()
    resumed = claim(session, kinds=["investigate.finding"])
    assert resumed is not None and resumed.id == investigation
    session.rollback()
    cancel_investigation(session, finding.id)
    session.commit()


def test_halt_state_records_who_and_why(session, unhalted):
    state = set_halt(session, halted=True, reason="model misbehaving", actor="user:alice")
    assert state.halted is True
    assert state.reason == "model misbehaving"
    assert state.set_by == "user:alice"
    assert state.set_at is not None
    session.commit()
    assert halt_state(session).halted is True


def test_the_gateway_refuses_while_halted_and_logs_the_refusal(session, unhalted, monkeypatch):
    import httpx

    from athena.db.models import EgressLog
    from athena.llm import gateway

    def never(*_args, **_kwargs):
        raise AssertionError("a halted gateway must not reach the model")

    monkeypatch.setattr(httpx.Client, "post", never)
    set_halt(session, halted=True, reason="kill switch test", actor="user:test")
    session.commit()

    marker = f"halt-probe-{uuid.uuid4()}"
    with pytest.raises(Halted):
        gateway.complete(prompt=marker, purpose="investigation")

    digest = gateway._digest(marker)
    session.expire_all()
    rows = (
        session.execute(select(EgressLog).where(EgressLog.payload_hash == digest)).scalars().all()
    )
    assert len(rows) == 1
    assert rows[0].blocked is True
    assert "halted" in rows[0].reason


def test_a_paused_investigation_is_not_claimed_until_unpaused(session, finding):
    investigation = _investigation(session, finding.id)
    assert pause_investigation(session, finding.id, actor="user:test") is True
    assert pause_investigation(session, finding.id, actor="user:test") is False
    session.commit()

    assert claim(session, kinds=["investigate.finding"]) is None
    assert _pending(session, investigation)

    assert resume_investigation(session, finding.id) is True
    session.commit()
    resumed = claim(session, kinds=["investigate.finding"])
    assert resumed is not None and resumed.id == investigation
    session.rollback()
    cancel_investigation(session, finding.id)
    session.commit()


def test_cancel_removes_only_the_pending_investigation(session, finding):
    from athena.db.models import Job

    investigation = _investigation(session, finding.id)
    session.commit()

    removed = cancel_investigation(session, finding.id)
    session.commit()

    assert removed == [investigation]
    assert session.get(Job, investigation) is None
    assert cancel_investigation(session, finding.id) == []


def test_migration_0022_round_trips(engine):
    from alembic import command
    from alembic.config import Config

    from tests.conftest import INTEGRATION_DSN

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", INTEGRATION_DSN)

    def tables() -> set[str]:
        with engine.connect() as conn:
            return set(
                conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables"
                        " WHERE table_name IN ('control_state', 'investigation_hold')"
                    )
                ).scalars()
            )

    command.downgrade(cfg, "0021")
    assert tables() == set()
    command.upgrade(cfg, "head")
    assert tables() == {"control_state", "investigation_hold"}
    with engine.connect() as conn:
        assert conn.execute(text("SELECT halted FROM control_state")).scalars().all() == [False]


@pytest.fixture
def operator(session):
    import secrets
    from datetime import timedelta

    from sqlalchemy import delete

    from athena.api.auth import hash_token
    from athena.db.models import Session_, User

    user = User(
        email=f"operator-{uuid.uuid4().hex[:8]}@example.test",
        password_hash=secrets.token_hex(16),
        role="operator",
    )
    session.add(user)
    session.flush()
    token = secrets.token_urlsafe(32)
    session.add(
        Session_(
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            step_up_at=datetime.now(UTC),
        )
    )
    session.commit()
    yield user.id, token
    session.rollback()
    session.execute(delete(User).where(User.id == user.id))
    session.commit()


def _operator_client(token: str):
    from fastapi.testclient import TestClient

    from athena.api.app import create_app
    from athena.api.auth import SESSION_COOKIE

    return TestClient(create_app(), cookies={SESSION_COOKIE: token})


def _actions(session, subject: str) -> list[str]:
    from athena.db.models import AuditEvent

    session.expire_all()
    return list(
        session.execute(
            select(AuditEvent.action).where(AuditEvent.subject == subject).order_by(AuditEvent.seq)
        ).scalars()
    )


def test_an_operator_pauses_and_cancels_through_the_api(session, finding, operator):
    from athena.control import is_investigation_paused
    from athena.db.models import Job

    _, token = operator
    client = _operator_client(token)
    base = f"/api/v1/findings/{finding.id}/investigation"

    assert client.post(f"{base}/pause").json()["paused"] is True
    assert is_investigation_paused(session, finding.id)
    assert client.post(f"{base}/unpause").json()["paused"] is False
    assert not is_investigation_paused(session, finding.id)

    investigation = _investigation(session, finding.id)
    session.commit()
    cancelled = client.post(f"{base}/cancel")
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["removed_jobs"] == 1
    session.expire_all()
    assert session.get(Job, investigation) is None
    assert is_investigation_paused(session, finding.id)

    assert _actions(session, f"finding:{finding.id}") == [
        "INVESTIGATION_PAUSED",
        "INVESTIGATION_UNPAUSED",
        "INVESTIGATION_CANCELLED",
    ]


def test_an_operator_cannot_halt(operator):
    _, token = operator
    response = _operator_client(token).post("/api/v1/control/halt", json={"reason": "not mine"})
    assert response.status_code == 403
