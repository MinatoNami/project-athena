from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Connection, text

GENESIS = b"\x00" * 32

AUDIT_LOCK = text("SELECT pg_advisory_xact_lock(hashtext('athena.audit'))")
LATEST_HASH = text("SELECT hash FROM audit_event ORDER BY seq DESC LIMIT 1")
DATABASE_NOW = text("SELECT now()")
INSERT_EVENT = text(
    "INSERT INTO audit_event (at, actor, action, subject, detail, prev_hash, hash) "
    "VALUES (:at, :actor, :action, :subject, CAST(:detail AS jsonb), :prev_hash, :hash) "
    "RETURNING seq"
)


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    at: datetime
    actor: str
    action: str
    subject: str
    detail: dict[str, Any]
    prev_hash: bytes
    hash: bytes


def canonical(
    *, at: datetime, actor: str, action: str, subject: str, detail: dict[str, Any], prev: bytes
) -> bytes:
    body = json.dumps(
        {
            "at": at.astimezone(UTC).isoformat(),
            "actor": actor,
            "action": action,
            "subject": subject,
            "detail": detail,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return prev + body


def chain_hash(
    *, at: datetime, actor: str, action: str, subject: str, detail: dict[str, Any], prev: bytes
) -> bytes:
    return hashlib.sha256(
        canonical(at=at, actor=actor, action=action, subject=subject, detail=detail, prev=prev)
    ).digest()


def record(
    connection: Connection,
    *,
    actor: str,
    action: str,
    subject: str,
    detail: dict[str, Any] | None = None,
) -> AuditEntry:
    connection.execute(AUDIT_LOCK)

    latest = connection.execute(LATEST_HASH).scalar_one_or_none()
    prev = bytes(latest) if latest else GENESIS

    at = connection.execute(DATABASE_NOW).scalar_one()
    detail = detail or {}
    digest = chain_hash(
        at=at, actor=actor, action=action, subject=subject, detail=detail, prev=prev
    )

    seq = connection.execute(
        INSERT_EVENT,
        {
            "at": at,
            "actor": actor,
            "action": action,
            "subject": subject,
            "detail": json.dumps(detail, default=str),
            "prev_hash": prev,
            "hash": digest,
        },
    ).scalar_one()
    return AuditEntry(
        seq=seq,
        at=at,
        actor=actor,
        action=action,
        subject=subject,
        detail=detail,
        prev_hash=prev,
        hash=digest,
    )
