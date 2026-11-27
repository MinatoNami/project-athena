from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from athena.api import auth as A
from athena.api.deps import Principal, administer_with_step_up, can_administer, db
from athena.api.types import AccountEmail
from athena.audit import record
from athena.db.models import Session_, User

router = APIRouter(prefix="/users", tags=["users"])

AssignableRole = Literal["viewer", "operator", "approver", "auditor", "admin"]


class InviteRequest(BaseModel):
    email: AccountEmail
    role: AssignableRole


class RoleRequest(BaseModel):
    role: AssignableRole


def _target(session: Session, principal: Principal, user_id: uuid.UUID) -> User:
    if user_id == principal.user.id:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Ask another admin to change your own account"
        )
    user = session.get(User, user_id, with_for_update=True)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such user")
    return user


def _lock_active_admin_ids(session: Session) -> set[uuid.UUID]:
    return set(
        session.execute(
            select(User.id)
            .where(User.role == "admin", User.disabled_at.is_(None))
            .order_by(User.id)
            .with_for_update()
        ).scalars()
    )


def _refuse_losing_the_last_admin(active_admin_ids: set[uuid.UUID], user: User) -> None:
    if active_admin_ids - {user.id}:
        return
    raise HTTPException(status.HTTP_409_CONFLICT, "Athena must keep at least one active admin")


def _revoke_sessions(session: Session, user: User) -> int:
    return session.execute(
        update(Session_)
        .where(Session_.user_id == user.id, Session_.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    ).rowcount


def _view(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
        "disabled": user.disabled_at is not None,
        "password_change_required": user.password_change_required,
    }


@router.get("")
def list_users(
    principal: Principal = Depends(can_administer),
    session: Session = Depends(db),
) -> list[dict]:
    return [_view(u) for u in session.execute(select(User).order_by(User.email)).scalars()]


@router.post("/invite", status_code=status.HTTP_201_CREATED)
def invite_user(
    body: InviteRequest,
    principal: Principal = Depends(administer_with_step_up),
    session: Session = Depends(db),
) -> dict:
    if session.execute(select(User.id).where(User.email == body.email)).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email exists")

    credential = secrets.token_urlsafe(24)
    user = User(
        email=body.email,
        password_hash=A.hash_password(credential),
        role=body.role,
        password_change_required=True,
    )
    session.add(user)
    session.flush()
    record(
        session,
        actor=principal.actor,
        action="USER_INVITED",
        subject=f"user:{user.id}",
        detail={"email": user.email, "role": user.role},
    )
    return {**_view(user), "invite_credential": credential}


@router.post("/{user_id}/role")
def set_role(
    user_id: uuid.UUID,
    body: RoleRequest,
    principal: Principal = Depends(administer_with_step_up),
    session: Session = Depends(db),
) -> dict:
    active_admin_ids = _lock_active_admin_ids(session)
    user = _target(session, principal, user_id)
    if user.id in active_admin_ids and body.role != "admin":
        _refuse_losing_the_last_admin(active_admin_ids, user)
    previous = user.role
    user.role = body.role
    record(
        session,
        actor=principal.actor,
        action="USER_ROLE_CHANGED",
        subject=f"user:{user.id}",
        detail={"from": previous, "to": user.role},
    )
    return _view(user)


@router.post("/{user_id}/disable")
def disable_user(
    user_id: uuid.UUID,
    principal: Principal = Depends(administer_with_step_up),
    session: Session = Depends(db),
) -> dict:
    active_admin_ids = _lock_active_admin_ids(session)
    user = _target(session, principal, user_id)
    if user.id in active_admin_ids:
        _refuse_losing_the_last_admin(active_admin_ids, user)
    if user.disabled_at is None:
        user.disabled_at = datetime.now(UTC)
    revoked = _revoke_sessions(session, user)
    record(
        session,
        actor=principal.actor,
        action="USER_DISABLED",
        subject=f"user:{user.id}",
        detail={"sessions_revoked": revoked},
    )
    return _view(user)


@router.post("/{user_id}/mfa/reset")
def reset_mfa(
    user_id: uuid.UUID,
    principal: Principal = Depends(administer_with_step_up),
    session: Session = Depends(db),
) -> dict:
    user = _target(session, principal, user_id)
    was_active = user.mfa_enabled
    A.clear_mfa(user)
    revoked = _revoke_sessions(session, user)
    record(
        session,
        actor=principal.actor,
        action="MFA_RESET",
        subject=f"user:{user.id}",
        detail={"via": "admin", "was_active": was_active, "sessions_revoked": revoked},
    )
    return _view(user)
