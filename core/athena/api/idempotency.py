from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from athena.api.auth import SESSION_COOKIE, resolve_session
from athena.db.base import session_scope

IDEMPOTENCY_HEADER = "Idempotency-Key"
REPLAYED_HEADER = "Idempotent-Replayed"
MAX_KEY_LENGTH = 128
KEY_LIFETIME = timedelta(hours=24)
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
API_PREFIX = "/api/v1/"
EXCLUDED_PREFIXES = ("/api/v1/nodes", "/api/v1/auth/login", "/api/v1/auth/bootstrap")


def applies_to(request: Request) -> bool:
    path = request.url.path
    return (
        request.method in MUTATING_METHODS
        and path.startswith(API_PREFIX)
        and not path.startswith(EXCLUDED_PREFIXES)
        and request.headers.get(IDEMPOTENCY_HEADER) is not None
    )


def _problem(status_code: int, title: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"type": "about:blank", "title": title, "status": status_code},
    )


def _principal_user_id(token: str | None):
    with session_scope() as session:
        resolved = resolve_session(session, token)
        return None if resolved is None else resolved[0].id


def _lookup(user_id, key: str):
    with session_scope() as session:
        return session.execute(
            text(
                "SELECT method, path, body_sha256, response_status, response_body"
                " FROM idempotency_key WHERE user_id = :user_id AND key = :key"
                " AND created_at > now() - make_interval(secs => :lifetime)"
            ),
            {"user_id": user_id, "key": key, "lifetime": KEY_LIFETIME.total_seconds()},
        ).one_or_none()


def _store(user_id, key: str, method: str, path: str, digest: str, status_code: int, body) -> None:
    with session_scope() as session:
        session.execute(
            text(
                "INSERT INTO idempotency_key"
                " (user_id, key, method, path, body_sha256, response_status, response_body)"
                " VALUES (:user_id, :key, :method, :path, :digest, :status, CAST(:body AS jsonb))"
                " ON CONFLICT (user_id, key) DO UPDATE SET"
                " method = EXCLUDED.method, path = EXCLUDED.path,"
                " body_sha256 = EXCLUDED.body_sha256, response_status = EXCLUDED.response_status,"
                " response_body = EXCLUDED.response_body, created_at = now()"
                " WHERE idempotency_key.created_at <= now() - make_interval(secs => :lifetime)"
            ),
            {
                "user_id": user_id,
                "key": key,
                "method": method,
                "path": path,
                "digest": digest,
                "status": status_code,
                "body": None if body is None else json.dumps(body),
                "lifetime": KEY_LIFETIME.total_seconds(),
            },
        )


def sweep_idempotency_keys(session: Session) -> int:
    result = session.execute(
        text(
            "DELETE FROM idempotency_key"
            " WHERE created_at <= now() - make_interval(secs => :lifetime)"
        ),
        {"lifetime": KEY_LIFETIME.total_seconds()},
    )
    return result.rowcount or 0


def _replay(status_code: int, body: Any) -> Response:
    headers = {REPLAYED_HEADER: "true"}
    if body is None:
        return Response(status_code=status_code, headers=headers)
    return JSONResponse(status_code=status_code, content=body, headers=headers)


def _decode(raw: bytes) -> tuple[bool, Any]:
    if not raw:
        return True, None
    try:
        return True, json.loads(raw)
    except ValueError:
        return False, None


async def idempotent(request: Request, call_next):
    if not applies_to(request):
        return await call_next(request)

    key = request.headers[IDEMPOTENCY_HEADER]
    if not key or len(key) > MAX_KEY_LENGTH:
        return _problem(422, "Invalid Idempotency-Key")

    user_id = await run_in_threadpool(_principal_user_id, request.cookies.get(SESSION_COOKIE))
    if user_id is None:
        return await call_next(request)

    digest = hashlib.sha256(await request.body()).hexdigest()
    method = request.method
    path = request.url.path

    existing = await run_in_threadpool(_lookup, user_id, key)
    if existing is not None:
        if (existing.method, existing.path, existing.body_sha256) != (method, path, digest):
            return _problem(422, "Idempotency-Key reused with a different request")
        return _replay(existing.response_status, existing.response_body)

    response = await call_next(request)
    if response.status_code >= 500:
        return response

    raw = b"".join([chunk async for chunk in response.body_iterator])
    storable, body = _decode(raw)
    if storable:
        await run_in_threadpool(
            _store, user_id, key, method, path, digest, response.status_code, body
        )
    buffered = Response(content=raw, status_code=response.status_code)
    buffered.raw_headers = list(response.raw_headers)
    return buffered
