from __future__ import annotations

import base64
import os
import uuid

import pytest
from sqlalchemy import func, select, text

from athena.api import auth as A
from athena.api.idempotency import IDEMPOTENCY_HEADER, REPLAYED_HEADER, sweep_idempotency_keys
from athena.config import get_settings
from athena.db.models import AuditEvent, User

PASSWORD = "correct-horse-battery"  # noqa: S105


@pytest.fixture
def app(engine, monkeypatch):
    from athena.api.app import create_app

    key = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(get_settings(), "master_key", key, raising=False)
    return create_app()


def _make_user(session, role):
    user = User(
        email=f"{role}-{uuid.uuid4().hex[:12]}@example.com",
        password_hash=A.hash_password(PASSWORD),
        role=role,
    )
    session.add(user)
    session.commit()
    return user


def _signed_in(app, user):
    from fastapi.testclient import TestClient

    client = TestClient(app, base_url="https://testserver")
    body = {"email": user.email, "password": PASSWORD}
    assert client.post("/api/v1/auth/login", json=body).status_code == 200
    assert client.post("/api/v1/auth/step-up", json=body).status_code == 200
    return client


def _role_changes(session, target_id):
    session.expire_all()
    return session.execute(
        select(func.count())
        .select_from(AuditEvent)
        .where(AuditEvent.subject == f"user:{target_id}")
        .where(AuditEvent.action == "USER_ROLE_CHANGED")
    ).scalar_one()


def test_replay_returns_stored_response_without_running_handler(app, session):
    admin = _make_user(session, "admin")
    target = _make_user(session, "viewer")
    client = _signed_in(app, admin)
    key = str(uuid.uuid4())
    path = f"/api/v1/users/{target.id}/role"

    first = client.post(path, json={"role": "operator"}, headers={IDEMPOTENCY_HEADER: key})
    assert first.status_code == 200
    assert REPLAYED_HEADER not in first.headers
    assert _role_changes(session, target.id) == 1

    second = client.post(path, json={"role": "operator"}, headers={IDEMPOTENCY_HEADER: key})
    assert second.status_code == 200
    assert second.headers[REPLAYED_HEADER] == "true"
    assert second.json() == first.json()
    assert _role_changes(session, target.id) == 1


def test_client_error_is_stored_and_replayed(app, session):
    admin = _make_user(session, "admin")
    client = _signed_in(app, admin)
    key = str(uuid.uuid4())
    path = f"/api/v1/users/{uuid.uuid4()}/role"

    first = client.post(path, json={"role": "operator"}, headers={IDEMPOTENCY_HEADER: key})
    assert 400 <= first.status_code < 500
    second = client.post(path, json={"role": "operator"}, headers={IDEMPOTENCY_HEADER: key})
    assert second.status_code == first.status_code
    assert second.headers[REPLAYED_HEADER] == "true"
    assert second.json() == first.json()


def test_mismatched_reuse_is_rejected(app, session):
    admin = _make_user(session, "admin")
    target = _make_user(session, "viewer")
    client = _signed_in(app, admin)
    key = str(uuid.uuid4())
    path = f"/api/v1/users/{target.id}/role"

    assert (
        client.post(path, json={"role": "operator"}, headers={IDEMPOTENCY_HEADER: key}).status_code
        == 200
    )
    different_body = client.post(path, json={"role": "auditor"}, headers={IDEMPOTENCY_HEADER: key})
    assert different_body.status_code == 422
    different_path = client.post(
        f"/api/v1/users/{target.id}/disable", headers={IDEMPOTENCY_HEADER: key}
    )
    assert different_path.status_code == 422
    assert _role_changes(session, target.id) == 1


def test_requests_without_the_header_are_unchanged(app, session):
    admin = _make_user(session, "admin")
    target = _make_user(session, "viewer")
    client = _signed_in(app, admin)
    path = f"/api/v1/users/{target.id}/role"

    for role in ("operator", "operator"):
        response = client.post(path, json={"role": role})
        assert response.status_code == 200
        assert REPLAYED_HEADER not in response.headers
    assert _role_changes(session, target.id) == 2
    stored = session.execute(
        text("SELECT count(*) FROM idempotency_key WHERE user_id = :u"), {"u": admin.id}
    ).scalar_one()
    assert stored == 0


def test_same_key_for_a_different_user_is_independent(app, session):
    first_admin = _make_user(session, "admin")
    second_admin = _make_user(session, "admin")
    target = _make_user(session, "viewer")
    key = str(uuid.uuid4())
    path = f"/api/v1/users/{target.id}/role"

    one = _signed_in(app, first_admin).post(
        path, json={"role": "operator"}, headers={IDEMPOTENCY_HEADER: key}
    )
    two = _signed_in(app, second_admin).post(
        path, json={"role": "auditor"}, headers={IDEMPOTENCY_HEADER: key}
    )
    assert one.status_code == 200
    assert two.status_code == 200
    assert REPLAYED_HEADER not in two.headers
    assert two.json()["role"] == "auditor"
    assert _role_changes(session, target.id) == 2


def test_oversized_key_is_rejected(app, session):
    admin = _make_user(session, "admin")
    target = _make_user(session, "viewer")
    client = _signed_in(app, admin)
    response = client.post(
        f"/api/v1/users/{target.id}/role",
        json={"role": "operator"},
        headers={IDEMPOTENCY_HEADER: "k" * 129},
    )
    assert response.status_code == 422
    assert _role_changes(session, target.id) == 0


def test_sweep_removes_only_expired_keys(app, session):
    admin = _make_user(session, "admin")
    target = _make_user(session, "viewer")
    client = _signed_in(app, admin)
    path = f"/api/v1/users/{target.id}/role"
    expired_key = f"expired-{uuid.uuid4()}"
    fresh_key = f"fresh-{uuid.uuid4()}"
    for key in (expired_key, fresh_key):
        assert (
            client.post(
                path, json={"role": "operator"}, headers={IDEMPOTENCY_HEADER: key}
            ).status_code
            == 200
        )
    session.execute(
        text(
            "UPDATE idempotency_key SET created_at = now() - interval '25 hours'"
            " WHERE user_id = :u AND key = :k"
        ),
        {"u": admin.id, "k": expired_key},
    )
    session.commit()

    replay_after_expiry = client.post(
        path, json={"role": "operator"}, headers={IDEMPOTENCY_HEADER: expired_key}
    )
    assert REPLAYED_HEADER not in replay_after_expiry.headers
    session.execute(
        text(
            "UPDATE idempotency_key SET created_at = now() - interval '25 hours'"
            " WHERE user_id = :u AND key = :k"
        ),
        {"u": admin.id, "k": expired_key},
    )
    session.commit()

    assert sweep_idempotency_keys(session) >= 1
    session.commit()
    remaining = (
        session.execute(text("SELECT key FROM idempotency_key WHERE user_id = :u"), {"u": admin.id})
        .scalars()
        .all()
    )
    assert remaining == [fresh_key]


def test_server_error_is_not_stored(app, session):
    from fastapi import Depends
    from fastapi.responses import JSONResponse

    from athena.api.deps import can_read

    @app.post("/api/v1/unavailable", dependencies=[Depends(can_read)])
    def unavailable():
        return JSONResponse(status_code=503, content={"title": "unavailable"})

    admin = _make_user(session, "admin")
    client = _signed_in(app, admin)
    key = str(uuid.uuid4())
    first = client.post("/api/v1/unavailable", headers={IDEMPOTENCY_HEADER: key})
    second = client.post("/api/v1/unavailable", headers={IDEMPOTENCY_HEADER: key})
    assert first.status_code == second.status_code == 503
    assert REPLAYED_HEADER not in second.headers
    stored = session.execute(
        text("SELECT count(*) FROM idempotency_key WHERE user_id = :u"), {"u": admin.id}
    ).scalar_one()
    assert stored == 0


def test_migration_round_trips(engine):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", os.environ["ATHENA_TEST_DB_URL"])
    command.downgrade(cfg, "0022")
    assert "idempotency_key" not in inspect(engine).get_table_names()
    command.upgrade(cfg, "head")
    assert "idempotency_key" in inspect(engine).get_table_names()
