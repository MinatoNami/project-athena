from __future__ import annotations

import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from athena.config import get_settings
from athena.crypto import envelope


@pytest.fixture(autouse=True)
def _master_key(monkeypatch):
    key = base64.b64encode(os.urandom(32)).decode()
    settings = get_settings()
    monkeypatch.setattr(settings, "master_key", key, raising=False)
    yield


def test_round_trip():
    sealed = envelope.seal("hunter2", aad="github_token")
    assert envelope.unseal(**sealed, aad="github_token") == "hunter2"


def test_ciphertext_does_not_contain_plaintext():
    sealed = envelope.seal("super-secret-value", aad="x")
    assert b"super-secret-value" not in sealed["ciphertext"]


def test_aad_is_binding():
    """A secret sealed under one name must not decrypt under another."""
    sealed = envelope.seal("v", aad="github_token")
    with pytest.raises(InvalidTag):
        envelope.unseal(**sealed, aad="registry_password")


def test_each_seal_uses_a_fresh_data_key():
    a = envelope.seal("same", aad="x")
    b = envelope.seal("same", aad="x")
    assert a["ciphertext"] != b["ciphertext"]
    assert a["wrapped_dek"] != b["wrapped_dek"]


def test_missing_master_key_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(get_settings(), "master_key", None, raising=False)
    with pytest.raises(envelope.MasterKeyUnavailable):
        envelope.seal("v", aad="x")
