"""Node enrolment and task exchange.

Nodes always dial out: core never opens a connection to a protected host, so nothing
Athena protects needs an inbound listener.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.audit import record, record_isolated
from athena.db.models import Node, NodeEnrolmentToken, NodeNonce, NodeTask
from athena.nodes.keys import task_signing_key, task_signing_public_key
from athena.nodes.protocol import (
    CAPABILITIES,
    MAX_CLOCK_SKEW,
    ProtocolError,
    b64,
    build_task_envelope,
    sign_envelope,
    unb64,
    verify_node_signature,
)

router = APIRouter(prefix="/nodes", tags=["nodes"])

ENROLMENT_TTL = timedelta(minutes=15)
OBSERVE_CAPABILITIES = sorted(CAPABILITIES)


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


# ─── enrolment ───────────────────────────────────────────────────────────────


class EnrolTokenRequest(BaseModel):
    tier: str = "unknown"


class EnrolRequest(BaseModel):
    token: str
    public_key: str = Field(description="base64 Ed25519 public key, generated on the node")
    hostname: str = Field(max_length=255)
    machine_id: str | None = None
    hardware_uuid: str | None = None
    platform: str | None = None
    arch: str | None = None
    agent_version: str | None = None


@router.post("/enrol-token", status_code=status.HTTP_201_CREATED)
def mint_enrol_token(
    body: EnrolTokenRequest,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    """Mint a single-use, short-lived enrolment token."""
    token = secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + ENROLMENT_TTL
    session.add(
        NodeEnrolmentToken(
            token_hash=_hash(token),
            tier=body.tier,
            created_by=principal.actor,
            expires_at=expires,
        )
    )
    record(
        session,
        actor=principal.actor,
        action="NODE_ENROLMENT_TOKEN_MINTED",
        subject="nodes",
        detail={"tier": body.tier, "ttl_minutes": int(ENROLMENT_TTL.total_seconds() // 60)},
    )
    # Returned exactly once; only its hash is stored.
    return {"token": token, "expires_at": expires}


@router.post("/enrol", status_code=status.HTTP_201_CREATED)
def enrol(body: EnrolRequest, request: Request, session: Session = Depends(db)) -> dict[str, Any]:
    """Redeem an enrolment token.

    Unauthenticated by session on purpose: the token *is* the authentication, and it
    is single-use and short-lived. The node sends only its public key — the private
    half is generated on the host and never transmitted.
    """
    row = session.execute(
        select(NodeEnrolmentToken).where(NodeEnrolmentToken.token_hash == _hash(body.token))
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    if row is None or row.consumed_at is not None or row.expires_at < now:
        record_isolated(
            actor="anonymous",
            action="NODE_ENROLMENT_REJECTED",
            subject="nodes",
            detail={
                "hostname": body.hostname[:100],
                "reason": "invalid, expired, or already used token",
                "ip": request.client.host if request.client else None,
            },
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid or expired enrolment token")

    try:
        public_key = unb64(body.public_key)
    except ProtocolError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if len(public_key) != 32:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Expected an Ed25519 public key")

    from athena.inventory.identity import AssetKind, IdentityError, host_identity
    from athena.inventory.service import register_asset

    try:
        identity = host_identity(
            machine_id=body.machine_id,
            hardware_uuid=body.hardware_uuid,
            node_key=b64(public_key),
        )
    except IdentityError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    asset, created = register_asset(
        session,
        kind=AssetKind.HOST,
        identity_key=identity,
        display_name=body.hostname,
        attributes={"platform": body.platform, "arch": body.arch},
        tier=row.tier,
    )

    node = Node(
        asset_id=asset.id,
        display_name=body.hostname,
        public_key=public_key,
        agent_version=body.agent_version,
        platform=body.platform,
        arch=body.arch,
        capabilities=OBSERVE_CAPABILITIES,
    )
    session.add(node)
    session.flush()

    row.consumed_at = now
    row.consumed_by_node = node.id

    # A host re-enrolling under a new key is a candidate duplicate, never a silent
    # merge: re-imaging looks identical to a brand-new machine.
    _flag_possible_duplicates(session, node=node, asset=asset, machine_id=body.machine_id)

    record(
        session,
        actor=f"node:{node.id}",
        action="NODE_ENROLLED",
        subject=f"node:{node.id}",
        detail={
            "hostname": body.hostname,
            "asset_id": str(asset.id),
            "new_asset": created,
            "capabilities": OBSERVE_CAPABILITIES,
        },
    )

    return {
        "node_id": str(node.id),
        "asset_id": str(asset.id),
        "capabilities": OBSERVE_CAPABILITIES,
        # Pinned by the node so it executes nothing core did not sign.
        "core_public_key": b64(task_signing_public_key()),
    }


def _flag_possible_duplicates(
    session: Session, *, node: Node, asset, machine_id: str | None
) -> None:
    from athena.db.models import Asset
    from athena.inventory.service import flag_merge_candidate

    others = session.execute(
        select(Asset).where(
            Asset.kind == "host",
            Asset.id != asset.id,
            Asset.tombstoned_at.is_(None),
            Asset.display_name == node.display_name,
        )
    ).scalars().all()
    for other in others:
        flag_merge_candidate(
            session,
            asset=asset,
            other=other,
            reason=(
                f"another host asset shares the hostname {node.display_name!r}; "
                "possibly the same machine re-imaged or re-enrolled"
            ),
            confidence=0.6 if machine_id else 0.4,
        )


# ─── node-authenticated requests ─────────────────────────────────────────────


async def authenticated_node(
    request: Request,
    session: Session = Depends(db),
    x_athena_node: str = Header(...),
    x_athena_timestamp: str = Header(...),
    x_athena_nonce: str = Header(...),
    x_athena_signature: str = Header(...),
) -> Node:
    """Verify an Ed25519-signed node request, and refuse to accept it twice."""
    try:
        node_uuid = uuid.UUID(x_athena_node)
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown node") from exc

    node = session.get(Node, node_uuid)
    if node is None or node.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked node")

    body = await request.body()
    try:
        verify_node_signature(
            public_key=node.public_key,
            signature=x_athena_signature,
            method=request.method,
            path=request.url.path,
            timestamp=x_athena_timestamp,
            nonce=x_athena_nonce,
            body=body,
        )
    except ProtocolError as exc:
        record_isolated(
            actor=f"node:{node.id}",
            action="NODE_REQUEST_REJECTED",
            subject=f"node:{node.id}",
            detail={"reason": str(exc), "path": request.url.path},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    # Replay protection. The insert is the check: a nonce already present conflicts.
    inserted = session.execute(
        text(
            "INSERT INTO node_nonce (node_id, nonce) VALUES (:node, :nonce) "
            "ON CONFLICT DO NOTHING RETURNING nonce"
        ),
        {"node": node.id, "nonce": x_athena_nonce},
    ).first()
    if inserted is None:
        record_isolated(
            actor=f"node:{node.id}",
            action="NODE_REPLAY_REJECTED",
            subject=f"node:{node.id}",
            detail={"path": request.url.path},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Replayed request")

    node.last_seen_at = datetime.now(UTC)
    return node


@router.get("/tasks")
def poll_tasks(node: Node = Depends(authenticated_node), session: Session = Depends(db)) -> dict:
    """Hand the node its pending work, as envelopes signed by core."""
    now = datetime.now(UTC)
    pending = session.execute(
        select(NodeTask)
        .where(
            NodeTask.node_id == node.id,
            NodeTask.completed_at.is_(None),
            NodeTask.expires_at > now,
        )
        .order_by(NodeTask.issued_at)
        .limit(10)
    ).scalars().all()

    key = task_signing_key()
    envelopes = []
    for task in pending:
        task.dispatched_at = now
        envelopes.append(
            sign_envelope(
                build_task_envelope(
                    task_id=str(task.id),
                    capability=task.capability,
                    args=task.args,
                    nonce=task.nonce,
                    issued_at=task.issued_at,
                ),
                key,
            )
        )
    return {"tasks": envelopes}


class TaskResult(BaseModel):
    task_id: str
    succeeded: bool
    result: dict[str, Any] | None = None
    error: str | None = None


@router.post("/results")
def submit_result(
    body: TaskResult, node: Node = Depends(authenticated_node), session: Session = Depends(db)
) -> dict:
    task = session.get(NodeTask, uuid.UUID(body.task_id))
    if task is None or task.node_id != node.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such task for this node")
    if task.completed_at is not None:
        return {"accepted": False, "reason": "already completed"}

    task.completed_at = datetime.now(UTC)
    task.succeeded = body.succeeded
    task.result = body.result
    task.error = body.error

    if body.succeeded and body.result is not None:
        from athena.queue import enqueue

        enqueue(
            session,
            kind="ingest.node_observation",
            key=str(task.id),
            payload={"task_id": str(task.id)},
            priority=4,
        )
    return {"accepted": True}


# ─── management ──────────────────────────────────────────────────────────────


@router.get("")
def list_nodes(
    _: Principal = Depends(current_principal), session: Session = Depends(db)
) -> dict[str, Any]:
    nodes = session.execute(select(Node).order_by(Node.display_name)).scalars().all()
    now = datetime.now(UTC)
    return {
        "nodes": [
            {
                "id": str(n.id),
                "display_name": n.display_name,
                "asset_id": str(n.asset_id) if n.asset_id else None,
                "platform": n.platform,
                "arch": n.arch,
                "agent_version": n.agent_version,
                "capabilities": n.capabilities,
                "enrolled_at": n.enrolled_at,
                "last_seen_at": n.last_seen_at,
                "revoked": n.revoked_at is not None,
                # A node that has stopped reporting is not a healthy node. The UI
                # must not let silence read as "nothing to report".
                "offline": n.last_seen_at is None or (now - n.last_seen_at) > timedelta(minutes=5),
            }
            for n in nodes
        ]
    }


@router.post("/{node_id}/collect", status_code=status.HTTP_202_ACCEPTED)
def collect_now(
    node_id: str,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict:
    """Queue an immediate observe sweep for one node."""
    from athena.nodes.dispatch import enqueue_collection

    node = session.get(Node, uuid.UUID(node_id))
    if node is None or node.revoked_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such node")

    created = enqueue_collection(session, node)
    record(
        session,
        actor=principal.actor,
        action="NODE_COLLECTION_REQUESTED",
        subject=f"node:{node.id}",
        detail={"tasks": created},
    )
    return {"queued": created}


@router.delete("/{node_id}")
def revoke_node(
    node_id: str,
    principal: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict:
    """Revoke a node's credentials and tombstone its asset, retaining history."""
    node = session.get(Node, uuid.UUID(node_id))
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such node")

    node.revoked_at = datetime.now(UTC)
    if node.asset_id:
        from athena.db.models import Asset
        from athena.inventory.service import tombstone_asset

        asset = session.get(Asset, node.asset_id)
        if asset is not None:
            tombstone_asset(session, asset)

    record(
        session,
        actor=principal.actor,
        action="NODE_REVOKED",
        subject=f"node:{node.id}",
        detail={"display_name": node.display_name},
    )
    return {"revoked": True}


def sweep_nonces(session: Session) -> int:
    """Drop nonces older than the skew window; they can no longer be replayed."""
    cutoff = datetime.now(UTC) - MAX_CLOCK_SKEW * 2
    result = session.execute(delete(NodeNonce).where(NodeNonce.seen_at < cutoff))
    return result.rowcount or 0
