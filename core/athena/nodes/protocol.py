"""Node ↔ core protocol.

Authentication is Ed25519 request signing rather than mutual TLS.

The property the design actually requires is that a node's private key never leaves
the host it protects, and that neither side can impersonate the other. Request
signing gives that without an internal CA, certificate issuance, rotation, and
revocation — machinery that is substantial to operate and easy to get wrong. TLS
still provides transport confidentiality. This supersedes the mTLS choice in
docs/TECHNICAL_DESIGN.md §11; moving to mTLS later changes only this module.

Both directions are authenticated:

  node → core   the node signs each request with its enrolment key
  core → node   core signs each task envelope with a key the node pinned at
                enrolment, so a node executes nothing core did not authorise
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Requests older than this are rejected outright, which bounds how long a captured
# request could be replayed even if the nonce cache were lost.
MAX_CLOCK_SKEW = timedelta(minutes=5)
TASK_TTL = timedelta(minutes=15)

# The observe set: every capability is a named, argument-validated operation.
# There is deliberately no `run_shell`. That absence is the difference between a
# node agent and a backdoor.
CAPABILITIES: dict[str, str] = {
    "get_system_info": "OS, kernel, hostname, machine identity",
    "list_packages": "installed OS packages and versions",
    "list_processes": "running processes",
    "list_services": "system services and their state",
    "list_ports": "listening sockets",
    "inspect_docker": "local images and containers",
}


class ProtocolError(ValueError):
    pass


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ProtocolError("Malformed base64") from exc


def canonical_request(
    *, method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    """The exact bytes a node signs.

    Binding method, path, timestamp, nonce, and a body digest means a captured
    signature cannot be replayed against a different endpoint or a modified payload.
    """
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path, timestamp, nonce, digest]).encode("utf-8")


def verify_node_signature(
    *, public_key: bytes, signature: str, method: str, path: str, timestamp: str,
    nonce: str, body: bytes,
) -> None:
    """Raise ProtocolError unless the request is authentic and inside the skew window."""
    try:
        issued = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ProtocolError("Malformed timestamp") from exc
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=UTC)

    if abs(datetime.now(UTC) - issued) > MAX_CLOCK_SKEW:
        raise ProtocolError("Request timestamp outside the accepted window")

    message = canonical_request(
        method=method, path=path, timestamp=timestamp, nonce=nonce, body=body
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(unb64(signature), message)
    except (InvalidSignature, ValueError) as exc:
        raise ProtocolError("Signature verification failed") from exc


def canonical_envelope(envelope: dict[str, Any]) -> bytes:
    body = {k: v for k, v in envelope.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_envelope(envelope: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Sign a task envelope so the node can prove core authorised it."""
    return {**envelope, "signature": b64(private_key.sign(canonical_envelope(envelope)))}


def build_task_envelope(
    *, task_id: str, capability: str, args: dict[str, Any], nonce: str,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    if capability not in CAPABILITIES:
        raise ProtocolError(f"Unknown capability {capability!r}")
    issued = issued_at or datetime.now(UTC)
    return {
        "task_id": task_id,
        "capability": capability,
        "args": args,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + TASK_TTL).isoformat(),
        "nonce": nonce,
    }
