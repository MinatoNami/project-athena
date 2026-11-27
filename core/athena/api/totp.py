from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from athena.crypto.envelope import seal, unseal

STEP_SECONDS = 30
DIGITS = 6
WINDOW_STEPS = 1
SECRET_BYTES = 20
ISSUER = "Athena"
SEALED_PREFIX = "sealed-v1"


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def decode_secret(secret_b32: str) -> bytes:
    normalised = secret_b32.strip().replace(" ", "").upper()
    return base64.b32decode(normalised + "=" * (-len(normalised) % 8))


def counter_at(unix_seconds: float) -> int:
    return int(unix_seconds // STEP_SECONDS)


def hotp(key: bytes, counter: int, *, digits: int = DIGITS) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def totp(key: bytes, unix_seconds: float, *, digits: int = DIGITS) -> str:
    return hotp(key, counter_at(unix_seconds), digits=digits)


def matching_counter(
    key: bytes, code: str, *, last_counter: int | None, unix_seconds: float | None = None
) -> int | None:
    candidate = (code or "").strip().replace(" ", "")
    if len(candidate) != DIGITS or not candidate.isdigit():
        return None
    now = counter_at(time.time() if unix_seconds is None else unix_seconds)
    matched: int | None = None
    for counter in range(now - WINDOW_STEPS, now + WINDOW_STEPS + 1):
        if counter < 0 or (last_counter is not None and counter <= last_counter):
            continue
        if hmac.compare_digest(hotp(key, counter), candidate) and matched is None:
            matched = counter
    return matched


def provisioning_uri(secret_b32: str, account: str) -> str:
    label = quote(f"{ISSUER}:{account}", safe=":@")
    query = urlencode(
        {
            "secret": secret_b32,
            "issuer": ISSUER,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": STEP_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def _aad(user_id: object) -> str:
    return f"mfa_totp:{user_id}"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def seal_secret(user_id: object, secret_b32: str) -> str:
    sealed = seal(secret_b32, aad=_aad(user_id))
    parts = [sealed[name] for name in ("wrapped_dek", "dek_nonce", "ciphertext", "nonce")]
    return ".".join([SEALED_PREFIX, *(_b64(part) for part in parts)])


def unseal_secret(user_id: object, stored: str) -> str:
    prefix, *encoded = stored.split(".")
    if prefix != SEALED_PREFIX or len(encoded) != 4:
        raise ValueError("MFA secret is not in the sealed format")
    wrapped_dek, dek_nonce, ciphertext, nonce = (base64.urlsafe_b64decode(p) for p in encoded)
    return unseal(
        wrapped_dek=wrapped_dek,
        dek_nonce=dek_nonce,
        ciphertext=ciphertext,
        nonce=nonce,
        aad=_aad(user_id),
    )
