"""Grant verification.

The executor can *verify* a grant signature. It holds no private key and therefore
cannot mint one — which is what stops a compromised reasoning layer from authorising
its own actions.
"""

from __future__ import annotations

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class GrantVerifier:
    def __init__(self, public_key: bytes | None) -> None:
        self._key = Ed25519PublicKey.from_public_bytes(public_key) if public_key else None

    @property
    def ready(self) -> bool:
        return self._key is not None

    def verify(self, grant: dict, signature: bytes) -> bool:
        if self._key is None:
            return False
        body = {k: v for k, v in grant.items() if k != "signature"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            self._key.verify(signature, canonical)
        except InvalidSignature:
            return False
        return True
