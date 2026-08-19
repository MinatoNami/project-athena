from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from athena.api.auth import SESSION_COOKIE, resolve_session
from athena.db.base import new_session
from athena.db.models import Session_, User

REQUEST_SESSION_ATTR = "athena_db_session"


def db(request: Request) -> Session:
    """Request-scoped session, committed by the transaction middleware.

    Deliberately not a `yield` dependency: FastAPI runs that teardown *after* the
    response is sent, so the client could act on a 201 before the transaction had
    committed — and a commit failure would have been reported as success. The
    middleware in `athena.api.app` closes the transaction before the response goes
    out. See docs/TECHNICAL_DESIGN.md §1 ("report outcomes faithfully").
    """
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
    def check(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return principal

    return check
