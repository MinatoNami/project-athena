from __future__ import annotations

import base64
import os
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.exceptions import InvalidTag

from athena.api import totp
from athena.config import get_settings
from athena.crypto.envelope import MasterKeyUnavailable

RFC_KEY = b"12345678901234567890"

RFC6238_SHA1_SIX_DIGITS = [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
    (20000000000, "353130"),
]


@pytest.fixture
def master_key(monkeypatch):
    key = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(get_settings(), "master_key", key, raising=False)
    return key


@pytest.mark.parametrize(("unix_seconds", "expected"), RFC6238_SHA1_SIX_DIGITS)
def test_rfc6238_sha1_vectors_truncated_to_six_digits(unix_seconds, expected):
    assert totp.totp(RFC_KEY, unix_seconds) == expected


def test_rfc6238_sha1_eight_digit_vector():
    assert totp.totp(RFC_KEY, 59, digits=8) == "94287082"


def test_generated_secret_round_trips_through_base32():
    secret = totp.generate_secret()
    assert len(totp.decode_secret(secret)) == totp.SECRET_BYTES
    assert totp.decode_secret(secret.lower()) == totp.decode_secret(secret)


def test_window_accepts_one_step_either_side_and_nothing_further():
    now = 1_700_000_000
    current = totp.counter_at(now)
    for offset in (-1, 0, 1):
        code = totp.hotp(RFC_KEY, current + offset)
        assert totp.matching_counter(RFC_KEY, code, last_counter=None, unix_seconds=now) == (
            current + offset
        )
    for offset in (-2, 2):
        code = totp.hotp(RFC_KEY, current + offset)
        assert totp.matching_counter(RFC_KEY, code, last_counter=None, unix_seconds=now) is None


def test_replay_of_the_last_used_counter_or_earlier_is_refused():
    now = 1_700_000_000
    current = totp.counter_at(now)
    code = totp.hotp(RFC_KEY, current)
    assert totp.matching_counter(RFC_KEY, code, last_counter=current, unix_seconds=now) is None
    earlier = totp.hotp(RFC_KEY, current - 1)
    assert totp.matching_counter(RFC_KEY, earlier, last_counter=current, unix_seconds=now) is None
    later = totp.hotp(RFC_KEY, current + 1)
    assert (
        totp.matching_counter(RFC_KEY, later, last_counter=current, unix_seconds=now) == current + 1
    )


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 5", None])
def test_malformed_codes_are_refused(code):
    assert totp.matching_counter(RFC_KEY, code, last_counter=None, unix_seconds=59) is None


@pytest.mark.parametrize(
    "code", ["٢٨٧٠٨٢", "２８７０８２", "28708²"]
)
def test_non_ascii_digits_are_refused_without_raising(code):
    assert code.isdigit()
    assert totp.matching_counter(RFC_KEY, code, last_counter=None, unix_seconds=59) is None


def test_provisioning_uri_names_issuer_account_and_parameters():
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "ops@example.com")
    parts = urlsplit(uri)
    assert parts.scheme == "otpauth"
    assert parts.netloc == "totp"
    assert parts.path == "/Athena:ops@example.com"
    query = parse_qs(parts.query)
    assert query["secret"] == ["JBSWY3DPEHPK3PXP"]
    assert query["issuer"] == ["Athena"]
    assert query["algorithm"] == ["SHA1"]
    assert query["digits"] == ["6"]
    assert query["period"] == ["30"]


def test_sealed_secret_round_trips_and_hides_the_plaintext(master_key):
    secret = totp.generate_secret()
    stored = totp.seal_secret("user-1", secret)
    assert stored.startswith(totp.SEALED_PREFIX + ".")
    assert secret not in stored
    assert totp.unseal_secret("user-1", stored) == secret


def test_sealed_secret_is_bound_to_its_user(master_key):
    stored = totp.seal_secret("user-1", totp.generate_secret())
    with pytest.raises(InvalidTag):
        totp.unseal_secret("user-2", stored)


def test_sealed_secret_cannot_be_read_without_the_master_key(monkeypatch, master_key):
    stored = totp.seal_secret("user-1", totp.generate_secret())

    monkeypatch.setattr(get_settings(), "master_key", None, raising=False)
    with pytest.raises(MasterKeyUnavailable):
        totp.unseal_secret("user-1", stored)

    other = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(get_settings(), "master_key", other, raising=False)
    with pytest.raises(InvalidTag):
        totp.unseal_secret("user-1", stored)


def test_unsealed_format_is_refused(master_key):
    with pytest.raises(ValueError):
        totp.unseal_secret("user-1", "JBSWY3DPEHPK3PXP")
