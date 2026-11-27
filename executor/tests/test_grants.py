from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from athena_executor.canonical import canonical_json
from athena_executor.grants import GrantRejected, GrantVerifier, key_fingerprint

NOW = datetime(2026, 11, 28, 12, 0, tzinfo=UTC)


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def clock():
    current = {"now": NOW}

    def now() -> datetime:
        return current["now"]

    now.current = current
    return now


@pytest.fixture
def verifier(signing_key, clock) -> GrantVerifier:
    return GrantVerifier(raw_public(signing_key), clock=clock)


def grant_for(key: Ed25519PrivateKey, **overrides) -> dict:
    grant = {
        "action": "noop",
        "target": "asset:1",
        "parameters": {},
        "approver": "user:1",
        "dry_run_hash": "0" * 64,
        "key_id": key_fingerprint(raw_public(key)),
        "nonce": "nonce-1",
        "issued_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
    }
    grant.update(overrides)
    return grant


def sign(key: Ed25519PrivateKey, grant: dict) -> bytes:
    return key.sign(canonical_json(grant))


def test_a_signed_grant_is_admitted(verifier, signing_key):
    grant = grant_for(signing_key)
    admitted = verifier.admit(grant, sign(signing_key, grant))
    assert admitted.action == "noop"
    assert admitted.target == "asset:1"
    assert admitted.nonce == "nonce-1"


def test_verify_still_answers_true_or_false(verifier, signing_key):
    grant = grant_for(signing_key)
    assert verifier.verify(grant, sign(signing_key, grant)) is True
    assert verifier.verify(grant_for(signing_key, nonce="other"), b"\x00" * 64) is False


def test_the_signature_field_inside_a_grant_is_not_signed(verifier, signing_key):
    grant = grant_for(signing_key)
    signature = sign(signing_key, grant)
    assert verifier.verify({**grant, "signature": signature.hex()}, signature) is True


def test_a_verifier_without_a_key_admits_nothing(signing_key):
    grant = grant_for(signing_key)
    verifier = GrantVerifier(None)
    assert verifier.ready is False
    assert verifier.verify(grant, sign(signing_key, grant)) is False


def test_a_tampered_grant_is_rejected(verifier, signing_key):
    grant = grant_for(signing_key)
    signature = sign(signing_key, grant)
    with pytest.raises(GrantRejected, match="signature"):
        verifier.admit({**grant, "target": "asset:2"}, signature)


def test_a_grant_signed_by_another_key_is_rejected(verifier, signing_key):
    intruder = Ed25519PrivateKey.generate()
    grant = grant_for(signing_key)
    with pytest.raises(GrantRejected, match="signature"):
        verifier.admit(grant, sign(intruder, grant))


def test_a_grant_naming_another_key_id_is_rejected(verifier, signing_key):
    grant = grant_for(signing_key, key_id="retired-key")
    with pytest.raises(GrantRejected, match="key"):
        verifier.admit(grant, sign(signing_key, grant))


def test_an_explicit_key_id_replaces_the_fingerprint(signing_key, clock):
    verifier = GrantVerifier(raw_public(signing_key), key_id="grant-2026-11", clock=clock)
    grant = grant_for(signing_key, key_id="grant-2026-11")
    assert verifier.verify(grant, sign(signing_key, grant)) is True


def test_an_expired_grant_is_rejected(verifier, signing_key, clock):
    grant = grant_for(signing_key)
    clock.current["now"] = NOW + timedelta(minutes=10)
    with pytest.raises(GrantRejected, match="expired"):
        verifier.admit(grant, sign(signing_key, grant))


def test_a_grant_is_admitted_until_its_expiry(verifier, signing_key, clock):
    grant = grant_for(signing_key)
    clock.current["now"] = NOW + timedelta(minutes=10) - timedelta(microseconds=1)
    assert verifier.verify(grant, sign(signing_key, grant)) is True


def test_a_grant_issued_in_the_future_is_rejected(verifier, signing_key):
    grant = grant_for(
        signing_key,
        issued_at=(NOW + timedelta(minutes=5)).isoformat(),
        expires_at=(NOW + timedelta(minutes=20)).isoformat(),
    )
    with pytest.raises(GrantRejected, match="future"):
        verifier.admit(grant, sign(signing_key, grant))


def test_small_clock_skew_on_issued_at_is_tolerated(verifier, signing_key):
    grant = grant_for(signing_key, issued_at=(NOW + timedelta(seconds=10)).isoformat())
    assert verifier.verify(grant, sign(signing_key, grant)) is True


def test_a_grant_that_expires_before_it_is_issued_is_rejected(verifier, signing_key):
    grant = grant_for(signing_key, expires_at=(NOW - timedelta(minutes=2)).isoformat())
    with pytest.raises(GrantRejected, match="before it is issued"):
        verifier.admit(grant, sign(signing_key, grant))


def test_a_replayed_grant_is_rejected(verifier, signing_key):
    grant = grant_for(signing_key)
    signature = sign(signing_key, grant)
    verifier.admit(grant, signature)
    with pytest.raises(GrantRejected, match="nonce"):
        verifier.admit(grant, signature)


def test_a_rejected_grant_does_not_spend_its_nonce(verifier, signing_key):
    good = grant_for(signing_key)
    assert verifier.verify(good, b"\x00" * 64) is False
    assert verifier.verify(good, sign(signing_key, good)) is True


@pytest.mark.parametrize(
    "field", ["action", "target", "dry_run_hash", "key_id", "nonce", "issued_at", "expires_at"]
)
def test_a_grant_missing_a_required_field_is_rejected(verifier, signing_key, field):
    grant = grant_for(signing_key)
    del grant[field]
    with pytest.raises(GrantRejected, match=field):
        verifier.admit(grant, sign(signing_key, grant))


def test_a_time_without_a_timezone_is_rejected(verifier, signing_key):
    grant = grant_for(signing_key, expires_at="2026-11-28T12:10:00")
    with pytest.raises(GrantRejected, match="timezone"):
        verifier.admit(grant, sign(signing_key, grant))


def test_a_naive_clock_is_refused(signing_key):
    verifier = GrantVerifier(raw_public(signing_key), clock=lambda: datetime(2026, 11, 28, 12))
    grant = grant_for(signing_key)
    with pytest.raises(GrantRejected, match="clock"):
        verifier.admit(grant, sign(signing_key, grant))
