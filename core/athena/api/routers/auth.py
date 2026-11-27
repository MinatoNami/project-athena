from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from athena.api import auth as A
from athena.api import totp
from athena.api.deps import Principal, can_read, current_principal, db
from athena.api.types import AccountEmail
from athena.audit import record, record_isolated
from athena.config import get_settings
from athena.db.models import User

router = APIRouter(prefix="/auth", tags=["auth"])

PASSWORD_CHANGE_REQUIRED = "Password change required"  # noqa: S105


class BootstrapRequest(BaseModel):
    token: str
    email: AccountEmail
    password: str = Field(min_length=A.MIN_PASSWORD_LENGTH)


class LoginRequest(BaseModel):
    email: AccountEmail
    password: str
    totp_code: str | None = Field(default=None, max_length=16)
    new_password: str | None = Field(default=None, max_length=1024)


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=totp.DIGITS, max_length=16)


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
    if user.mfa_enabled and not A.verify_totp(session, user, body.totp_code):
        record_isolated(
            actor="anonymous",
            action="MFA_FAILED",
            subject=f"user:{user.id}",
            detail={
                "stage": "login",
                "code_supplied": bool(body.totp_code),
                "ip": request.client.host if request.client else None,
            },
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if user.password_change_required:
        _replace_single_use_password(session, user, body)

    record(
        session,
        actor=f"user:{user.id}",
        action="LOGIN",
        subject=f"user:{user.id}",
        detail={"mfa": user.mfa_enabled},
    )
    _set_session_cookie(response, A.create_session(session, user))
    return {"id": str(user.id), "email": user.email, "role": user.role}


def _replace_single_use_password(session: Session, user: User, body: LoginRequest) -> None:
    if not body.new_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, PASSWORD_CHANGE_REQUIRED)
    session.flush()
    session.refresh(user, with_for_update=True)
    if not user.password_change_required or not A.verify_password(
        user.password_hash, body.password
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    if (problem := A.validate_password_strength(body.new_password)) is not None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problem)
    if body.new_password == body.password:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "The new password must differ from the old one."
        )
    user.password_hash = A.hash_password(body.new_password)
    user.password_change_required = False
    record(
        session,
        actor=f"user:{user.id}",
        action="PASSWORD_CHANGED",
        subject=f"user:{user.id}",
        detail={"reason": "single-use credential replaced"},
    )


@router.post("/logout")
def logout(request: Request, response: Response, session: Session = Depends(db)) -> dict:
    A.revoke_session(session, request.cookies.get(A.SESSION_COOKIE))
    response.delete_cookie(A.SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(principal: Principal = Depends(can_read)) -> dict:
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

    if principal.user.mfa_enabled and not A.verify_totp(
        session, principal.user, body.totp_code
    ):
        record_isolated(
            actor=principal.actor,
            action="MFA_FAILED",
            subject=f"user:{principal.user.id}",
            detail={"stage": "step_up", "code_supplied": bool(body.totp_code)},
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


@router.post("/mfa/enrol")
def mfa_enrol(
    principal: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict:
    user = principal.user
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already active; reset it first")
    if not A.has_fresh_step_up(principal.session_row):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Fresh step-up required")

    secret = totp.generate_secret()
    user.mfa_secret = totp.seal_secret(user.id, secret)
    user.mfa_last_counter = None
    record(
        session,
        actor=principal.actor,
        action="MFA_ENROL_STARTED",
        subject=f"user:{user.id}",
        detail={"method": "totp"},
    )
    return {"provisioning_uri": totp.provisioning_uri(secret, user.email)}


@router.post("/mfa/confirm")
def mfa_confirm(
    body: MfaCodeRequest,
    principal: Principal = Depends(can_read),
    session: Session = Depends(db),
) -> dict:
    user = principal.user
    if user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "No pending MFA enrolment")

    if not A.verify_totp(session, user, body.code):
        record_isolated(
            actor=principal.actor,
            action="MFA_FAILED",
            subject=f"user:{user.id}",
            detail={"stage": "confirm", "code_supplied": True},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authenticator code")

    user.mfa_enabled = True
    record(
        session,
        actor=principal.actor,
        action="MFA_ENABLED",
        subject=f"user:{user.id}",
        detail={"method": "totp"},
    )
    return {"mfa_enabled": True}
