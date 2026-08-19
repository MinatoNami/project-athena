"""Core's task-signing key.

Separate from the executor's grant key: they authorise different things, and a
compromise of one must not confer the other.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from athena.config import get_settings


class SigningKeyUnavailable(RuntimeError):
    pass


@lru_cache(maxsize=1)
def task_signing_key() -> Ed25519PrivateKey:
    path = get_settings().node_signing_key_file
    if not path or not Path(path).exists():
        raise SigningKeyUnavailable(
            "No node signing key. Set ATHENA_NODE_SIGNING_KEY_FILE to an Ed25519 "
            "private key in PEM form."
        )
    key = load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningKeyUnavailable("The node signing key must be Ed25519")
    return key


def task_signing_public_key() -> bytes:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    return task_signing_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
