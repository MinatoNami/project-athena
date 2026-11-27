from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from athena_executor.canonical import canonical_json

Clock = Callable[[], datetime]

DEFAULT_CLOCK_SKEW = timedelta(seconds=30)


class GrantRejected(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class VerifiedGrant:
    action: str
    target: str
    parameters: Mapping[str, Any]
    dry_run_hash: str
    key_id: str
    nonce: str
    issued_at: datetime
    expires_at: datetime
    payload: Mapping[str, Any]


def key_fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def utc_now() -> datetime:
    return datetime.now(UTC)


class GrantVerifier:
    def __init__(
        self,
        public_key: bytes | None,
        *,
        key_id: str | None = None,
        clock: Clock = utc_now,
        clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
    ) -> None:
        self._key = Ed25519PublicKey.from_public_bytes(public_key) if public_key else None
        if key_id is None and public_key:
            key_id = key_fingerprint(public_key)
        self.key_id = key_id
        self._clock = clock
        self._clock_skew = clock_skew
        self._seen_nonces: dict[str, datetime] = {}
        self._nonce_lock = threading.Lock()

    @property
    def ready(self) -> bool:
        return self._key is not None and self.key_id is not None

    def verify(self, grant: Mapping[str, Any], signature: bytes) -> bool:
        try:
            self.admit(grant, signature)
        except GrantRejected:
            return False
        return True

    def admit(self, grant: Mapping[str, Any], signature: bytes) -> VerifiedGrant:
        if self._key is None or self.key_id is None:
            raise GrantRejected("no grant public key is configured")
        body = {k: v for k, v in grant.items() if k != "signature"}
        _check_signature(self._key, body, signature)
        verified = _parse(body)
        if not hmac.compare_digest(verified.key_id.encode(), self.key_id.encode()):
            raise GrantRejected("grant names a key this executor does not trust")
        now = self._now()
        if verified.expires_at <= verified.issued_at:
            raise GrantRejected("grant expires before it is issued")
        if verified.issued_at > now + self._clock_skew:
            raise GrantRejected("grant is issued in the future")
        if now >= verified.expires_at:
            raise GrantRejected("grant has expired")
        self._consume_nonce(verified.nonce, verified.expires_at, now)
        return verified

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise GrantRejected("the executor clock returned a time without a timezone")
        return now

    def _consume_nonce(self, nonce: str, expires_at: datetime, now: datetime) -> None:
        with self._nonce_lock:
            self._seen_nonces = {
                seen: until
                for seen, until in self._seen_nonces.items()
                if until + self._clock_skew > now
            }
            if nonce in self._seen_nonces:
                raise GrantRejected("grant nonce was already used")
            self._seen_nonces[nonce] = expires_at


def _check_signature(key: Ed25519PublicKey, body: dict[str, Any], signature: bytes) -> None:
    try:
        message = canonical_json(body)
    except (TypeError, ValueError):
        raise GrantRejected("grant is not canonical JSON") from None
    try:
        key.verify(signature, message)
    except (InvalidSignature, TypeError):
        raise GrantRejected("grant signature does not verify") from None


def _parse(body: Mapping[str, Any]) -> VerifiedGrant:
    parameters = body.get("parameters", {})
    if not isinstance(parameters, dict):
        raise GrantRejected("grant field parameters must be an object")
    return VerifiedGrant(
        action=_text(body, "action"),
        target=_text(body, "target"),
        parameters=dict(parameters),
        dry_run_hash=_text(body, "dry_run_hash"),
        key_id=_text(body, "key_id"),
        nonce=_text(body, "nonce"),
        issued_at=_timestamp(body, "issued_at"),
        expires_at=_timestamp(body, "expires_at"),
        payload=dict(body),
    )


def _text(body: Mapping[str, Any], name: str) -> str:
    value = body.get(name)
    if not isinstance(value, str) or not value:
        raise GrantRejected(f"grant field {name} must be a non-empty string")
    return value


def _timestamp(body: Mapping[str, Any], name: str) -> datetime:
    raw = _text(body, name)
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        raise GrantRejected(f"grant field {name} is not an ISO-8601 time") from None
    if parsed.tzinfo is None:
        raise GrantRejected(f"grant field {name} has no timezone")
    return parsed
