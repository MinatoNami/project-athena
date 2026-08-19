"""Issue collection work to nodes."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.db.models import Node, NodeTask
from athena.nodes.protocol import CAPABILITIES, TASK_TTL

# The full observe sweep. Ordered so identity lands before anything that depends on
# it — a host's inventory is meaningless until we know which host it is.
COLLECTION_ORDER = [
    "get_system_info",
    "list_packages",
    "list_ports",
    "list_services",
    "list_processes",
    "inspect_docker",
]

# How often a node is swept. PRD §42 puts host inventory on a daily cadence; this is
# the floor between sweeps rather than the schedule itself.
COLLECTION_INTERVAL = timedelta(hours=6)


def enqueue_collection(
    session: Session, node: Node, *, capabilities: list[str] | None = None
) -> int:
    """Create signed-on-dispatch tasks for a node. Returns how many were created."""
    wanted = capabilities or COLLECTION_ORDER
    now = datetime.now(UTC)

    pending = {
        row.capability
        for row in session.execute(
            select(NodeTask).where(
                NodeTask.node_id == node.id,
                NodeTask.completed_at.is_(None),
                NodeTask.expires_at > now,
            )
        ).scalars()
    }

    created = 0
    for capability in wanted:
        if capability not in CAPABILITIES:
            continue
        # Do not pile identical work on a node that has not answered yet.
        if capability in pending:
            continue
        session.add(
            NodeTask(
                node_id=node.id,
                capability=capability,
                args={},
                issued_at=now,
                expires_at=now + TASK_TTL,
                nonce=secrets.token_hex(16),
            )
        )
        created += 1
    return created


def nodes_due(session: Session) -> list[Node]:
    """Nodes with no live tasks that have not been swept recently."""
    now = datetime.now(UTC)
    cutoff = now - COLLECTION_INTERVAL

    live_task_nodes = {
        row.node_id
        for row in session.execute(
            select(NodeTask.node_id).where(
                NodeTask.completed_at.is_(None), NodeTask.expires_at > now
            )
        )
    }

    due: list[Node] = []
    for node in session.execute(select(Node).where(Node.revoked_at.is_(None))).scalars():
        if node.id in live_task_nodes:
            continue
        last = session.execute(
            select(NodeTask.issued_at)
            .where(NodeTask.node_id == node.id)
            .order_by(NodeTask.issued_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if last is None or last < cutoff:
            due.append(node)
    return due
