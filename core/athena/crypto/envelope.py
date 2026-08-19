"""Envelope encryption for stored secrets.

A per-secret data key (DEK) encrypts the value; the master key wraps the DEK.
The master key comes from a file or the environment and is never written to the
database, so a database dump alone discloses nothing.
"""

from __future__ import annotations

import base64
import os
import secrets as _secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from athena.config import get_settings

KEY_BYTES = 32
NONCE_BYTES = 12


class MasterKeyUnavailable(RuntimeError):
    pass


def generate_master_key() -> str:
    """A new base64 master key. Print once; store outside the database."""
    return base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def _master_key() -> bytes:
    raw = get_settings().master_key
    if not raw:
        raise MasterKeyUnavailable(
            "No master key. Set ATHENA_MASTER_KEY_FILE to a readable file "
            "containing a base64 32-byte key."
        )
    key = base64.b64decode(raw)
    if len(key) != KEY_BYTES:
        raise MasterKeyUnavailable(f"Master key must be {KEY_BYTES} bytes, got {len(key)}")
    return key


def seal(plaintext: str, *, aad: str) -> dict[str, bytes]:
    """Encrypt a value. `aad` binds the ciphertext to its logical name."""
    dek = _secrets.token_bytes(KEY_BYTES)
    nonce = _secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))

    dek_nonce = _secrets.token_bytes(NONCE_BYTES)
    wrapped_dek = AESGCM(_master_key()).encrypt(dek_nonce, dek, aad.encode("utf-8"))

    return {
        "wrapped_dek": wrapped_dek,
        "dek_nonce": dek_nonce,
        "ciphertext": ciphertext,
        "nonce": nonce,
    }


def unseal(
    *, wrapped_dek: bytes, dek_nonce: bytes, ciphertext: bytes, nonce: bytes, aad: str
) -> str:
    dek = AESGCM(_master_key()).decrypt(dek_nonce, wrapped_dek, aad.encode("utf-8"))
    return AESGCM(dek).decrypt(nonce, ciphertext, aad.encode("utf-8")).decode("utf-8")
