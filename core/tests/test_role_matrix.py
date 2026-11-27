from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import get_args

import pytest

from athena.api.app import create_app
from athena.api.deps import (
    ADMIN,
    ADMIN_ROLES,
    OPERATE_ROLES,
    ROLES,
    STEP_UP_HEADER,
    STEP_UP_REQUIRED,
)
from athena.api.routers.users import AssignableRole

READ_ROUTE = ("GET", "/api/v1/assets")
OPERATE_ROUTE = ("POST", f"/api/v1/notifications/{uuid.uuid4()}/read")
ADMIN_ROUTE = ("GET", "/api/v1/users")
OPERATE_STEP_UP_ROUTE = ("POST", f"/api/v1/suppressions/{uuid.uuid4()}/revoke")
ADMIN_STEP_UP_ROUTE = ("DELETE", f"/api/v1/nodes/{uuid.uuid4()}")

USER_ROUTES = [
    ("GET", "/api/v1/users", None),
    ("POST", "/api/v1/users/invite", {"email": "new@example.test", "role": "viewer"}),
    ("POST", f"/api/v1/users/{uuid.uuid4()}/role", {"role": "viewer"}),
    ("POST", f"/api/v1/users/{uuid.uuid4()}/disable", None),
    ("POST", f"/api/v1/users/{uuid.uuid4()}/mfa/reset", None),
]

NON_ADMIN_ROLES = [role for role in ROLES if role != ADMIN]


@pytest.fixture
def staff(engine):
    from sqlalchemy import delete
    from sqlalchemy.orm import Session

    from athena.api.auth import hash_token
    from athena.db.models import Session_, User

    created: dict[str, tuple[uuid.UUID, uuid.UUID, str]] = {}
    with Session(engine) as s:
        for role in ROLES:
            user = User(
                email=f"{role}-{uuid.uuid4().hex[:8]}@example.test",
                password_hash=secrets.token_hex(16),
                role=role,
            )
            s.add(user)
            s.flush()
            token = secrets.token_urlsafe(32)
            row = Session_(
                user_id=user.id,
                token_hash=hash_token(token),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
            s.add(row)
            s.flush()
            created[role] = (user.id, row.id, token)
        s.commit()

    yield created

    with Session(engine) as s:
        s.execute(delete(User).where(User.id.in_([u for u, _, _ in created.values()])))
        s.commit()


def _client(token: str):
    from fastapi.testclient import TestClient

    from athena.api.auth import SESSION_COOKIE

    return TestClient(create_app(), cookies={SESSION_COOKIE: token})


def _set_step_up(engine, session_id: uuid.UUID, when: datetime | None) -> None:
    from sqlalchemy import update
    from sqlalchemy.orm import Session

    from athena.db.models import Session_

    with Session(engine) as s:
        s.execute(update(Session_).where(Session_.id == session_id).values(step_up_at=when))
        s.commit()


def _audited(engine, user_id: uuid.UUID, action: str) -> list[dict]:
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from athena.db.models import AuditEvent

    with Session(engine) as s:
        return list(
            s.execute(
                select(AuditEvent.detail).where(
                    AuditEvent.actor == f"user:{user_id}", AuditEvent.action == action
                )
            ).scalars()
        )


def _assert_role_denied(engine, user_id, response, path: str) -> None:
    assert response.status_code == 403, response.text
    assert response.json()["detail"] != STEP_UP_REQUIRED
    denials = [d for d in _audited(engine, user_id, "ROLE_DENIED") if d["path"] == path]
    assert len(denials) == 1


def _call(engine, staff, role: str, route: tuple, step_up: bool = False, body=None):
    user_id, session_id, token = staff[role]
    _set_step_up(engine, session_id, datetime.now(UTC) if step_up else None)
    method, path = route
    return user_id, _client(token).request(method, path, json=body)


@pytest.mark.parametrize("role", ROLES)
def test_every_role_may_read(engine, staff, role):
    _, response = _call(engine, staff, role, READ_ROUTE)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("role", ROLES)
def test_only_operators_and_admins_may_operate(engine, staff, role):
    user_id, response = _call(engine, staff, role, OPERATE_ROUTE)
    if role in OPERATE_ROLES:
        assert response.status_code == 404, response.text
    else:
        _assert_role_denied(engine, user_id, response, OPERATE_ROUTE[1])


@pytest.mark.parametrize("role", ROLES)
def test_only_admins_may_administer(engine, staff, role):
    user_id, response = _call(engine, staff, role, ADMIN_ROUTE)
    if role in ADMIN_ROLES:
        assert response.status_code == 200, response.text
    else:
        _assert_role_denied(engine, user_id, response, ADMIN_ROUTE[1])


@pytest.mark.parametrize(
    "route,allowed",
    [(OPERATE_STEP_UP_ROUTE, OPERATE_ROLES), (ADMIN_STEP_UP_ROUTE, ADMIN_ROLES)],
)
@pytest.mark.parametrize("role", ROLES)
def test_a_step_up_route_needs_the_role_and_a_fresh_step_up(engine, staff, role, route, allowed):
    user_id, stale = _call(engine, staff, role, route, step_up=False)
    if role not in allowed:
        _assert_role_denied(engine, user_id, stale, route[1])
        _, fresh = _call(engine, staff, role, route, step_up=True)
        assert fresh.status_code == 403
        assert fresh.json()["detail"] != STEP_UP_REQUIRED
        return

    assert stale.status_code == 403
    assert stale.json()["detail"] == STEP_UP_REQUIRED
    assert stale.headers[STEP_UP_HEADER] == "required"
    refusals = [d for d in _audited(engine, user_id, "STEP_UP_REFUSED") if d["path"] == route[1]]
    assert len(refusals) == 1

    _, fresh = _call(engine, staff, role, route, step_up=True)
    assert fresh.status_code == 404, fresh.text


@pytest.mark.parametrize("method,path,body", USER_ROUTES)
@pytest.mark.parametrize("role", NON_ADMIN_ROLES)
def test_a_non_admin_cannot_reach_user_management(engine, staff, role, method, path, body):
    user_id, response = _call(engine, staff, role, (method, path), step_up=True, body=body)
    _assert_role_denied(engine, user_id, response, path)


def test_the_assignable_roles_are_exactly_the_known_roles():
    assert set(get_args(AssignableRole)) == set(ROLES)


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("POST", "/api/v1/users/invite", {"email": "new@example.test", "role": "superuser"}),
        ("POST", f"/api/v1/users/{uuid.uuid4()}/role", {"role": "superuser"}),
        ("POST", f"/api/v1/users/{uuid.uuid4()}/role", {"role": "unassigned"}),
    ],
)
def test_user_management_refuses_an_unknown_role(engine, staff, method, path, body):
    _, response = _call(engine, staff, ADMIN, (method, path), step_up=True, body=body)
    assert response.status_code == 422, response.text
