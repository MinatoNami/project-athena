from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from athena.api.auth import SESSION_COOKIE, has_fresh_step_up, resolve_session
from athena.audit import record_isolated
from athena.db.base import new_session
from athena.db.models import Session_, User

REQUEST_SESSION_ATTR = "athena_db_session"
ROLE_CHECK_ATTR = "athena_required_roles"
STEP_UP_CHECK_ATTR = "athena_requires_step_up"
STEP_UP_REQUIRED = "step_up_required"
STEP_UP_HEADER = "X-Athena-Step-Up"

ADMIN = "admin"
READ_ROLES = (ADMIN,)
OPERATE_ROLES = (ADMIN,)
ADMIN_ROLES = (ADMIN,)


def db(request: Request) -> Session:
    session = getattr(request.state, REQUEST_SESSION_ATTR, None)
    if session is None:
        session = new_session()
        setattr(request.state, REQUEST_SESSION_ATTR, session)
    return session


class Principal:
    def __init__(self, user: User, session_row: Session_):
        self.user = user
        self.session_row = session_row

    @property
    def actor(self) -> str:
        return f"user:{self.user.id}"


def current_principal(request: Request, session: Session = Depends(db)) -> Principal:
    resolved = resolve_session(session, request.cookies.get(SESSION_COOKIE))
    if resolved is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return Principal(*resolved)


def require_role(*roles: str):
    def check(request: Request, principal: Principal = Depends(current_principal)) -> Principal:
        if principal.user.role not in roles:
            record_isolated(
                actor=principal.actor,
                action="ROLE_DENIED",
                subject=f"user:{principal.user.id}",
                detail={
                    "role": principal.user.role,
                    "required": list(roles),
                    "method": request.method,
                    "path": request.url.path,
                },
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return principal

    setattr(check, ROLE_CHECK_ATTR, roles)
    return check


def require_step_up(*roles: str):
    role_check = require_role(*roles)

    def check(request: Request, principal: Principal = Depends(role_check)) -> Principal:
        if not has_fresh_step_up(principal.session_row):
            record_isolated(
                actor=principal.actor,
                action="STEP_UP_REFUSED",
                subject=f"user:{principal.user.id}",
                detail={"method": request.method, "path": request.url.path},
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                STEP_UP_REQUIRED,
                headers={STEP_UP_HEADER: "required"},
            )
        return principal

    setattr(check, STEP_UP_CHECK_ATTR, True)
    return check


can_read = require_role(*READ_ROLES)
can_operate = require_role(*OPERATE_ROLES)
can_administer = require_role(*ADMIN_ROLES)
operate_with_step_up = require_step_up(*OPERATE_ROLES)
administer_with_step_up = require_step_up(*ADMIN_ROLES)
