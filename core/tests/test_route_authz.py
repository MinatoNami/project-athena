from __future__ import annotations

import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.routing import APIRoute, iter_route_contexts

from athena.api.app import create_app
from athena.api.deps import (
    ROLE_CHECK_ATTR,
    STEP_UP_CHECK_ATTR,
    STEP_UP_HEADER,
    STEP_UP_REQUIRED,
)

UNAUTHENTICATED_ROUTES = {
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("GET", "/api/v1/auth/bootstrap-required"),
    ("POST", "/api/v1/auth/bootstrap"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/step-up"),
    ("POST", "/api/v1/nodes/enrol"),
    ("GET", "/api/v1/nodes/tasks"),
    ("POST", "/api/v1/nodes/results"),
}

STEP_UP_ROUTES = {
    ("POST", "/api/v1/findings/{finding_id}/suppress"),
    ("POST", "/api/v1/suppressions/{suppression_id}/revoke"),
    ("POST", "/api/v1/nodes/enrol-token"),
    ("DELETE", "/api/v1/nodes/{node_id}"),
    ("POST", "/api/v1/auth/mfa/enrol"),
    ("POST", "/api/v1/users/invite"),
    ("POST", "/api/v1/users/{user_id}/role"),
    ("POST", "/api/v1/users/{user_id}/disable"),
    ("POST", "/api/v1/users/{user_id}/mfa/reset"),
    ("POST", "/api/v1/control/halt"),
    ("POST", "/api/v1/control/resume"),
    ("POST", "/api/v1/findings/{finding_id}/investigation/pause"),
    ("POST", "/api/v1/findings/{finding_id}/investigation/unpause"),
    ("POST", "/api/v1/findings/{finding_id}/investigation/cancel"),
}

MUTATION_WORDS = {"apply", "rotate", "block", "isolate", "revoke", "execute", "delete"}


def _api_routes(app) -> list[tuple[str, str, APIRoute]]:
    return [
        (method, context.path, context.route)
        for context in iter_route_contexts(app.routes)
        if isinstance(context.route, APIRoute)
        for method in sorted(context.methods)
    ]


def _dependency_calls(dependant):
    for dependency in dependant.dependencies:
        yield dependency.call
        yield from _dependency_calls(dependency)


def _requires_role(route: APIRoute) -> bool:
    return any(getattr(c, ROLE_CHECK_ATTR, None) for c in _dependency_calls(route.dependant))


def _requires_step_up(route: APIRoute) -> bool:
    return any(getattr(c, STEP_UP_CHECK_ATTR, False) for c in _dependency_calls(route.dependant))


def test_every_route_needs_a_role_unless_explicitly_exempt():
    app = create_app()
    framework_paths = {
        app.openapi_url,
        app.docs_url,
        app.redoc_url,
        app.swagger_ui_oauth2_redirect_url,
    }
    for context in iter_route_contexts(app.routes):
        if not isinstance(context.route, APIRoute):
            assert context.path in framework_paths, context.path

    unguarded = {
        (method, path) for method, path, route in _api_routes(app) if not _requires_role(route)
    }
    assert unguarded == UNAUTHENTICATED_ROUTES


def test_exempt_routes_carry_no_role_dependency():
    app = create_app()
    registered = {(m, p) for m, p, _ in _api_routes(app)}
    assert UNAUTHENTICATED_ROUTES <= registered


def test_the_most_sensitive_mutations_require_step_up():
    app = create_app()
    stepped = {(m, p) for m, p, route in _api_routes(app) if _requires_step_up(route)}
    assert stepped == STEP_UP_ROUTES


def test_no_registered_job_kind_names_a_mutation():
    from athena.api.routers import jobs  # noqa: F401
    from athena.queue import known_kinds

    for kind in known_kinds():
        words = set(re.split(r"[._\-]", kind.lower()))
        assert not words & MUTATION_WORDS, kind


def test_the_jobs_allowlist_is_exactly_the_scan_jobs():
    from athena.api.routers.assets import SCAN_JOBS
    from athena.api.routers.jobs import USER_ENQUEUEABLE
    from athena.queue import known_kinds

    assert set(USER_ENQUEUEABLE) == set(SCAN_JOBS.values())
    assert set(USER_ENQUEUEABLE) <= set(known_kinds())


@pytest.fixture
def people(engine):
    from sqlalchemy import delete
    from sqlalchemy.orm import Session

    from athena.api.auth import hash_token
    from athena.db.models import Session_, User

    created: dict[str, tuple[uuid.UUID, uuid.UUID, str]] = {}
    with Session(engine) as s:
        for label, role in (("admin", "admin"), ("stranger", "unassigned")):
            user = User(
                email=f"{label}-{uuid.uuid4().hex[:8]}@example.test",
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
            created[label] = (user.id, row.id, token)
        s.commit()

    yield created

    with Session(engine) as s:
        s.execute(delete(User).where(User.id.in_([u for u, _, _ in created.values()])))
        s.commit()


def _client(token: str | None):
    from fastapi.testclient import TestClient

    from athena.api.auth import SESSION_COOKIE

    cookies = {SESSION_COOKIE: token} if token else None
    return TestClient(create_app(), cookies=cookies)


def _set_step_up(engine, session_id: uuid.UUID, when: datetime | None) -> None:
    from sqlalchemy import update
    from sqlalchemy.orm import Session

    from athena.db.models import Session_

    with Session(engine) as s:
        s.execute(update(Session_).where(Session_.id == session_id).values(step_up_at=when))
        s.commit()


def _audited(engine, actor: str, action: str) -> int:
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from athena.db.models import AuditEvent

    with Session(engine) as s:
        return s.execute(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.actor == actor, AuditEvent.action == action)
        ).scalar_one()


READ_ROUTES = [
    "/api/v1/auth/me",
    "/api/v1/assets",
    "/api/v1/findings",
    "/api/v1/nodes",
    "/api/v1/jobs",
    "/api/v1/audit",
    "/api/v1/suppressions",
    "/api/v1/notifications",
    "/api/v1/metrics",
    "/api/v1/code-findings",
    "/api/v1/export/openvex",
    "/api/v1/control",
]

DENIED_ONLY_ROUTES = ["/api/v1/events"]


@pytest.mark.parametrize("path", READ_ROUTES)
def test_admin_may_read(people, path):
    response = _client(people["admin"][2]).get(path)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("path", READ_ROUTES + DENIED_ONLY_ROUTES)
def test_an_unknown_role_is_refused_and_audited(engine, people, path):
    user_id, _, token = people["stranger"]
    response = _client(token).get(path)
    assert response.status_code == 403
    assert _audited(engine, f"user:{user_id}", "ROLE_DENIED") >= 1


@pytest.mark.parametrize("path", READ_ROUTES + DENIED_ONLY_ROUTES)
def test_anonymous_is_unauthenticated(engine, path):
    assert _client(None).get(path).status_code == 401


@pytest.mark.parametrize(
    "method,path,body",
    [
        (
            "POST",
            f"/api/v1/findings/{uuid.uuid4()}/suppress",
            {"reason_code": "not_affected", "reason": "covered by a test"},
        ),
        ("POST", f"/api/v1/suppressions/{uuid.uuid4()}/revoke", None),
        ("DELETE", f"/api/v1/nodes/{uuid.uuid4()}", None),
        ("POST", "/api/v1/nodes/enrol-token", {"tier": "unknown"}),
        ("POST", "/api/v1/control/halt", {"reason": "step-up probe"}),
        ("POST", "/api/v1/control/resume", None),
        ("POST", f"/api/v1/findings/{uuid.uuid4()}/investigation/pause", None),
        ("POST", f"/api/v1/findings/{uuid.uuid4()}/investigation/unpause", None),
        ("POST", f"/api/v1/findings/{uuid.uuid4()}/investigation/cancel", None),
    ],
)
def test_sensitive_mutations_need_a_fresh_step_up(engine, people, method, path, body):
    user_id, session_id, token = people["admin"]
    client = _client(token)

    _set_step_up(engine, session_id, None)
    refused = client.request(method, path, json=body)
    assert refused.status_code == 403
    assert refused.json()["detail"] == STEP_UP_REQUIRED
    assert refused.headers[STEP_UP_HEADER] == "required"
    assert _audited(engine, f"user:{user_id}", "STEP_UP_REFUSED") >= 1

    _set_step_up(engine, session_id, datetime.now(UTC) - timedelta(days=1))
    assert client.request(method, path, json=body).status_code == 403

    _set_step_up(engine, session_id, datetime.now(UTC))
    allowed = client.request(method, path, json=body)
    assert allowed.status_code not in (401, 403), allowed.text


def test_a_stranger_with_step_up_still_lacks_the_role(engine, people):
    _, session_id, token = people["stranger"]
    _set_step_up(engine, session_id, datetime.now(UTC))
    response = _client(token).post("/api/v1/nodes/enrol-token", json={})
    assert response.status_code == 403
    assert response.json()["detail"] != STEP_UP_REQUIRED


def test_jobs_refuses_a_kind_that_is_not_allowlisted(engine, people):
    user_id, _, token = people["admin"]
    response = _client(token).post(
        "/api/v1/jobs", json={"kind": "system.echo", "key": "k", "payload": {}}
    )
    assert response.status_code == 403
    assert _audited(engine, f"user:{user_id}", "JOB_REFUSED") >= 1


def test_jobs_refuses_an_unregistered_kind(people):
    response = _client(people["admin"][2]).post(
        "/api/v1/jobs", json={"kind": "remediation.apply", "key": "k", "payload": {}}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "payload",
    [{}, {"asset_id": "not-a-uuid"}, {"asset_id": str(uuid.uuid4()), "command": "rm"}],
)
def test_jobs_refuses_a_bad_payload(engine, people, payload):
    user_id, _, token = people["admin"]
    before = _audited(engine, f"user:{user_id}", "JOB_REFUSED")
    response = _client(token).post(
        "/api/v1/jobs", json={"kind": "scan.image", "key": "k", "payload": payload}
    )
    assert response.status_code == 422
    assert _audited(engine, f"user:{user_id}", "JOB_REFUSED") == before + 1


def test_jobs_refuses_a_role_without_access(people):
    response = _client(people["stranger"][2]).post(
        "/api/v1/jobs",
        json={"kind": "scan.image", "key": "k", "payload": {"asset_id": str(uuid.uuid4())}},
    )
    assert response.status_code == 403


def test_jobs_accepts_an_allowlisted_kind(engine, people):
    from sqlalchemy import delete
    from sqlalchemy.orm import Session

    from athena.db.models import Job

    asset_id = str(uuid.uuid4())
    key = f"authz-test-{uuid.uuid4().hex}"
    response = _client(people["admin"][2]).post(
        "/api/v1/jobs",
        json={"kind": "scan.repository", "key": key, "payload": {"asset_id": asset_id}},
    )
    try:
        assert response.status_code == 202, response.text
        body = response.json()
        assert body["kind"] == "scan.repository"
        with Session(engine) as s:
            job = s.get(Job, body["id"])
            assert job.payload == {"asset_id": asset_id}
    finally:
        with Session(engine) as s:
            s.execute(delete(Job).where(Job.key == key))
            s.commit()


def test_halt_and_resume_are_audited_and_readable(engine, people):
    user_id, session_id, token = people["admin"]
    client = _client(token)
    _set_step_up(engine, session_id, datetime.now(UTC))
    try:
        halted = client.post("/api/v1/control/halt", json={"reason": "audit probe"})
        assert halted.status_code == 200, halted.text
        assert client.get("/api/v1/control").json()["halted"] is True
        assert _audited(engine, f"user:{user_id}", "ATHENA_HALTED") >= 1
    finally:
        resumed = client.post("/api/v1/control/resume")
    assert resumed.status_code == 200, resumed.text
    assert client.get("/api/v1/control").json()["halted"] is False
    assert _audited(engine, f"user:{user_id}", "ATHENA_RESUMED") >= 1


def test_a_stranger_cannot_halt(engine, people):
    _, session_id, token = people["stranger"]
    _set_step_up(engine, session_id, datetime.now(UTC))
    response = _client(token).post("/api/v1/control/halt", json={"reason": "not mine"})
    assert response.status_code == 403
    assert response.json()["detail"] != STEP_UP_REQUIRED
