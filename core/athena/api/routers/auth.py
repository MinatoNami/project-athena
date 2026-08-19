from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from athena.api import auth as A
from athena.api.deps import Principal, current_principal, db
from athena.api.types import AccountEmail
from athena.audit import record, record_isolated
from athena.config import get_settings
from athena.db.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


class BootstrapRequest(BaseModel):
    token: str
    email: AccountEmail
    password: str = Field(min_length=A.MIN_PASSWORD_LENGTH)


class LoginRequest(BaseModel):
    email: AccountEmail
    password: str


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        A.SESSION_COOKIE,
        token,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="lax",
        max_age=get_settings().session_ttl_hours * 3600,
        path="/",
    )


@router.get("/bootstrap-required")
def bootstrap_required(session: Session = Depends(db)) -> dict:
    return {"required": not A.any_user_exists(session)}


@router.post("/bootstrap", status_code=status.HTTP_201_CREATED)
def bootstrap(body: BootstrapRequest, response: Response, session: Session = Depends(db)) -> dict:
    """Create the first admin account from the single-use bootstrap token."""
    if A.any_user_exists(session):
        raise HTTPException(status.HTTP_409_CONFLICT, "An account already exists")

    if (problem := A.validate_password_strength(body.password)) is not None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problem)

    if A.consume_bootstrap_token(session, body.token) is None:
        record_isolated(
            actor="anonymous",
            action="BOOTSTRAP_REJECTED",
            subject="bootstrap",
            detail={"reason": "invalid or expired token"},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid or expired bootstrap token")

    user = User(
        email=body.email,
        password_hash=A.hash_password(body.password),
        role="admin",
    )
    session.add(user)
    session.flush()

    record(
        session,
        actor=f"user:{user.id}",
        action="ADMIN_CREATED",
        subject=f"user:{user.id}",
        detail={"email": user.email},
    )
    _set_session_cookie(response, A.create_session(session, user))
    return {"id": str(user.id), "email": user.email, "role": user.role}


@router.post("/login")
def login(
    body: LoginRequest, request: Request, response: Response, session: Session = Depends(db)
) -> dict:
    from sqlalchemy import select

    user = session.execute(
        select(User).where(User.email == body.email)
    ).scalar_one_or_none()

    # Constant-ish work whether or not the account exists, so timing does not enumerate users.
    ok = user is not None and user.disabled_at is None and A.verify_password(
        user.password_hash, body.password
    )
    if not ok:
        record_isolated(
            actor="anonymous",
            action="LOGIN_FAILED",
            subject=f"email:{body.email}",
            detail={"ip": request.client.host if request.client else None},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    assert user is not None
    record(session, actor=f"user:{user.id}", action="LOGIN", subject=f"user:{user.id}", detail={})
    _set_session_cookie(response, A.create_session(session, user))
    return {"id": str(user.id), "email": user.email, "role": user.role}


@router.post("/logout")
def logout(request: Request, response: Response, session: Session = Depends(db)) -> dict:
    A.revoke_session(session, request.cookies.get(A.SESSION_COOKIE))
    response.delete_cookie(A.SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(principal: Principal = Depends(current_principal)) -> dict:
    return {
        "id": str(principal.user.id),
        "email": principal.user.email,
        "role": principal.user.role,
        "mfa_enabled": principal.user.mfa_enabled,
        "step_up_fresh": A.has_fresh_step_up(principal.session_row),
    }


@router.post("/step-up")
def step_up(
    body: LoginRequest,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict:
    """Re-authenticate for a consequential action. Required before every approval."""
    if body.email != principal.user.email or not A.verify_password(
        principal.user.password_hash, body.password
    ):
        record_isolated(
            actor=principal.actor,
            action="STEP_UP_FAILED",
            subject=f"user:{principal.user.id}",
            detail={},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Re-authentication failed")

    principal.session_row.step_up_at = datetime.now(UTC)
    record(
        session,
        actor=principal.actor,
        action="STEP_UP",
        subject=f"user:{principal.user.id}",
        detail={},
    )
    return {"ok": True, "expires_in": get_settings().step_up_ttl_seconds}
