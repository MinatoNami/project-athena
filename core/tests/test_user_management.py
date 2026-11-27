from __future__ import annotations

import base64
import os
import uuid

import pytest
from sqlalchemy import select

from athena.api import auth as A
from athena.api import totp
from athena.config import get_settings
from athena.db.models import AuditEvent, User

PASSWORD = "correct-horse-battery"  # noqa: S105
NEW_PASSWORD = "a-brand-new-passphrase"  # noqa: S105


@pytest.fixture
def app(engine, monkeypatch):
    from athena.api.app import create_app

    key = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(get_settings(), "master_key", key, raising=False)
    return create_app()


def _client(app):
    from fastapi.testclient import TestClient

    return TestClient(app, base_url="https://testserver")


def _make_user(session, role):
    user = User(
        email=f"{role}-{uuid.uuid4().hex[:12]}@example.com",
        password_hash=A.hash_password(PASSWORD),
        role=role,
    )
    session.add(user)
    session.commit()
    return user


def _signed_in(app, user, *, step_up=True):
    client = _client(app)
    body = {"email": user.email, "password": PASSWORD}
    assert client.post("/api/v1/auth/login", json=body).status_code == 200
    if step_up:
        assert client.post("/api/v1/auth/step-up", json=body).status_code == 200
    return client


def _actions(session, user_id):
    session.expire_all()
    return (
        session.execute(
            select(AuditEvent.action)
            .where(AuditEvent.subject == f"user:{user_id}")
            .order_by(AuditEvent.seq)
        )
        .scalars()
        .all()
    )


def _mutations(target_id):
    return [
        (
            "post",
            "/api/v1/users/invite",
            {"email": f"x-{uuid.uuid4().hex[:8]}@example.com", "role": "viewer"},
        ),
        ("post", f"/api/v1/users/{target_id}/role", {"role": "viewer"}),
        ("post", f"/api/v1/users/{target_id}/disable", None),
        ("post", f"/api/v1/users/{target_id}/mfa/reset", None),
    ]


def test_every_user_route_carries_the_admin_role_dependency(app):
    from athena.api.deps import ADMIN, ROLE_CHECK_ATTR
    from athena.api.routers.users import router

    def calls(dependant):
        for dep in dependant.dependencies:
            yield dep.call
            yield from calls(dep)

    for route in router.routes:
        required = [getattr(c, ROLE_CHECK_ATTR, None) for c in calls(route.dependant)]
        assert (ADMIN,) in required, route.path


@pytest.mark.parametrize("role", ["viewer", "operator", "approver", "auditor"])
def test_non_admins_are_forbidden(app, session, role):
    target = _make_user(session, "viewer")
    client = _signed_in(app, _make_user(session, role))
    assert client.get("/api/v1/users").status_code == 403
    for method, path, body in _mutations(target.id):
        assert getattr(client, method)(path, json=body).status_code == 403, path


def test_anonymous_callers_are_refused(app, session):
    target = _make_user(session, "viewer")
    client = _client(app)
    assert client.get("/api/v1/users").status_code == 401
    for method, path, body in _mutations(target.id):
        assert getattr(client, method)(path, json=body).status_code == 401, path


def test_admins_need_a_fresh_step_up(app, session):
    target = _make_user(session, "viewer")
    client = _signed_in(app, _make_user(session, "admin"), step_up=False)
    assert client.get("/api/v1/users").status_code == 200
    for method, path, body in _mutations(target.id):
        response = getattr(client, method)(path, json=body)
        assert response.status_code == 403, path
        assert response.json()["detail"] == "step_up_required"


def test_admins_cannot_change_their_own_account(app, session):
    admin = _make_user(session, "admin")
    client = _signed_in(app, admin)
    for _, path, body in _mutations(admin.id)[1:]:
        assert client.post(path, json=body).status_code == 409, path


def test_invite_issues_a_single_use_credential(app, session):
    admin = _make_user(session, "admin")
    client = _signed_in(app, admin)
    email = f"invitee-{uuid.uuid4().hex[:8]}@example.com"

    invited = client.post("/api/v1/users/invite", json={"email": email, "role": "operator"})
    assert invited.status_code == 201
    credential = invited.json()["invite_credential"]
    invitee_id = invited.json()["id"]
    assert (
        client.post("/api/v1/users/invite", json={"email": email, "role": "viewer"}).status_code
        == 409
    )

    invitee = _client(app)
    first = {"email": email, "password": credential}
    refused = invitee.post("/api/v1/auth/login", json=first)
    assert refused.status_code == 403
    assert refused.json()["detail"] == "Password change required"
    weak = invitee.post("/api/v1/auth/login", json={**first, "new_password": "short"})
    assert weak.status_code == 422

    changed = invitee.post("/api/v1/auth/login", json={**first, "new_password": NEW_PASSWORD})
    assert changed.status_code == 200
    assert changed.json()["role"] == "operator"

    invitee.cookies.clear()
    assert invitee.post("/api/v1/auth/login", json=first).status_code == 401
    again = {"email": email, "password": NEW_PASSWORD}
    assert invitee.post("/api/v1/auth/login", json=again).status_code == 200

    actions = _actions(session, invitee_id)
    assert actions[0] == "USER_INVITED"
    assert "PASSWORD_CHANGED" in actions


def test_set_role_disable_and_reset_mfa_are_applied_and_audited(app, session):
    admin = _make_user(session, "admin")
    target = _make_user(session, "viewer")
    client = _signed_in(app, admin)
    victim = _signed_in(app, target, step_up=False)

    secret = totp.generate_secret()
    row = session.get(User, target.id)
    row.mfa_secret = totp.seal_secret(row.id, secret)
    row.mfa_enabled = True
    row.mfa_last_counter = 7
    session.commit()

    assert client.post(f"/api/v1/users/{target.id}/role", json={"role": "bogus"}).status_code == 422
    promoted = client.post(f"/api/v1/users/{target.id}/role", json={"role": "operator"})
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "operator"

    reset = client.post(f"/api/v1/users/{target.id}/mfa/reset")
    assert reset.status_code == 200
    assert reset.json()["mfa_enabled"] is False
    session.expire_all()
    row = session.get(User, target.id)
    assert row.mfa_secret is None
    assert row.mfa_last_counter is None
    assert victim.get("/api/v1/auth/me").status_code == 401

    disabled = client.post(f"/api/v1/users/{target.id}/disable")
    assert disabled.status_code == 200
    assert disabled.json()["disabled"] is True
    body = {"email": target.email, "password": PASSWORD}
    assert _client(app).post("/api/v1/auth/login", json=body).status_code == 401

    actions = _actions(session, target.id)
    assert "USER_ROLE_CHANGED" in actions
    assert "MFA_RESET" in actions
    assert actions[-1] == "USER_DISABLED"
    session.expire_all()
    reset_event = session.execute(
        select(AuditEvent).where(
            AuditEvent.subject == f"user:{target.id}", AuditEvent.action == "MFA_RESET"
        )
    ).scalar_one()
    assert reset_event.actor == f"user:{admin.id}"
    assert reset_event.detail["was_active"] is True
