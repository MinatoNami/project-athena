from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

INVESTIGATION_KIND_PREFIX = "investigate."


class Halted(RuntimeError):
    pass


@dataclass
class HaltState:
    halted: bool
    reason: str | None
    set_by: str | None
    set_at: datetime | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "halted": self.halted,
            "reason": self.reason,
            "set_by": self.set_by,
            "set_at": self.set_at,
        }


def halt_state(session: Session) -> HaltState:
    row = session.execute(
        text("SELECT halted, reason, set_by, set_at FROM control_state WHERE id = 1")
    ).first()
    if row is None:
        return HaltState(halted=False, reason=None, set_by=None, set_at=None)
    return HaltState(halted=row.halted, reason=row.reason, set_by=row.set_by, set_at=row.set_at)


def is_halted(session: Session) -> bool:
    return halt_state(session).halted


def set_halt(session: Session, *, halted: bool, reason: str | None, actor: str) -> HaltState:
    session.execute(
        text(
            """
            INSERT INTO control_state (id, halted, reason, set_by, set_at)
            VALUES (1, :halted, :reason, :actor, now())
            ON CONFLICT (id) DO UPDATE SET
                halted = EXCLUDED.halted,
                reason = EXCLUDED.reason,
                set_by = EXCLUDED.set_by,
                set_at = EXCLUDED.set_at
            """
        ),
        {"halted": halted, "reason": reason, "actor": actor},
    )
    return halt_state(session)


def is_investigation_paused(session: Session, finding_id: uuid.UUID) -> bool:
    found = session.execute(
        text("SELECT 1 FROM investigation_hold WHERE finding_id = :fid"),
        {"fid": finding_id},
    ).first()
    return found is not None


def is_investigation_blocked(session: Session, finding_id: uuid.UUID) -> bool:
    return is_halted(session) or is_investigation_paused(session, finding_id)


def pause_investigation(session: Session, finding_id: uuid.UUID, *, actor: str) -> bool:
    row = session.execute(
        text(
            """
            INSERT INTO investigation_hold (finding_id, held_by)
            VALUES (:fid, :actor)
            ON CONFLICT (finding_id) DO NOTHING
            RETURNING finding_id
            """
        ),
        {"fid": finding_id, "actor": actor},
    ).first()
    return row is not None


def resume_investigation(session: Session, finding_id: uuid.UUID) -> bool:
    row = session.execute(
        text("DELETE FROM investigation_hold WHERE finding_id = :fid RETURNING finding_id"),
        {"fid": finding_id},
    ).first()
    return row is not None


def cancel_investigation(session: Session, finding_id: uuid.UUID) -> list[uuid.UUID]:
    rows = session.execute(
        text(
            """
            DELETE FROM job
             WHERE kind LIKE :prefix
               AND payload->>'finding_id' = :fid
               AND finished_at IS NULL
               AND (lease_until IS NULL OR lease_until < now())
            RETURNING id
            """
        ),
        {"prefix": f"{INVESTIGATION_KIND_PREFIX}%", "fid": str(finding_id)},
    ).all()
    return [row.id for row in rows]
