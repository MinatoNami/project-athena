from __future__ import annotations

import base64
import os
import uuid
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from athena.api import auth as A
from athena.api import totp
from athena.config import get_settings
from athena.db.models import AuditEvent, User

PASSWORD = "correct-horse-battery"  # noqa: S105
START = 1_800_000_000.0


@pytest.fixture
def clock(monkeypatch):
    now = [START]
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: now[0]))
    return now


@pytest.fixture
def client(engine, monkeypatch):
    from fastapi.testclient import TestClient

    from athena.api.app import create_app

    key = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(get_settings(), "master_key", key, raising=False)
    return TestClient(create_app(), base_url="https://testserver")


@pytest.fixture
def account(session):
    email = f"mfa-{uuid.uuid4().hex[:12]}@example.com"
    user = User(email=email, password_hash=A.hash_password(PASSWORD), role="admin")
    session.add(user)
    session.commit()
    return user


def _login(client, email, code=None):
    body = {"email": email, "password": PASSWORD}
    if code is not None:
        body["totp_code"] = code
    return client.post("/api/v1/auth/login", json=body)


def _step_up(client, email, code=None):
    body = {"email": email, "password": PASSWORD}
    if code is not None:
        body["totp_code"] = code
    return client.post("/api/v1/auth/step-up", json=body)


def _actions(session, user):
    session.expire_all()
    return (
        session.execute(
            select(AuditEvent.action)
            .where(AuditEvent.subject == f"user:{user.id}")
            .order_by(AuditEvent.seq)
        )
        .scalars()
        .all()
    )


def _code(secret, at):
    return totp.totp(totp.decode_secret(secret), at)


def _enrol(client, account, clock):
    assert _login(client, account.email).status_code == 200
    assert _step_up(client, account.email).status_code == 200
    enrolled = client.post("/api/v1/auth/mfa/enrol")
    assert enrolled.status_code == 200
    uri = enrolled.json()["provisioning_uri"]
    secret = parse_qs(urlsplit(uri).query)["secret"][0]
    confirmed = client.post("/api/v1/auth/mfa/confirm", json={"code": _code(secret, clock[0])})
    assert confirmed.status_code == 200
    return secret


def test_enrol_needs_a_fresh_step_up(client, account, clock):
    assert _login(client, account.email).status_code == 200
    assert client.post("/api/v1/auth/mfa/enrol").status_code == 403


def test_enrol_and_confirm_activate_mfa_with_a_sealed_secret(client, session, account, clock):
    assert _login(client, account.email).status_code == 200
    assert _step_up(client, account.email).status_code == 200

    enrolled = client.post("/api/v1/auth/mfa/enrol")
    assert enrolled.status_code == 200
    secret = parse_qs(urlsplit(enrolled.json()["provisioning_uri"]).query)["secret"][0]

    session.expire_all()
    stored = session.get(User, account.id)
    assert stored.mfa_enabled is False
    assert stored.mfa_secret.startswith(totp.SEALED_PREFIX)
    assert secret not in stored.mfa_secret

    wrong = client.post("/api/v1/auth/mfa/confirm", json={"code": "000000"})
    if _code(secret, clock[0]) != "000000":
        assert wrong.status_code == 401

    confirmed = client.post("/api/v1/auth/mfa/confirm", json={"code": _code(secret, clock[0])})
    assert confirmed.status_code == 200
    assert client.get("/api/v1/auth/me").json()["mfa_enabled"] is True

    session.expire_all()
    stored = session.get(User, account.id)
    assert stored.mfa_enabled is True
    assert stored.mfa_last_counter == totp.counter_at(clock[0])

    again = client.post("/api/v1/auth/mfa/enrol")
    assert again.status_code == 409

    actions = _actions(session, account)
    assert "MFA_ENROL_STARTED" in actions
    assert "MFA_FAILED" in actions
    assert actions[-1] == "MFA_ENABLED"


def test_login_requires_the_code_once_mfa_is_active(client, session, account, clock):
    secret = _enrol(client, account, clock)
    client.cookies.clear()

    assert _login(client, account.email).status_code == 401
    assert _login(client, account.email, "not-a-code").status_code == 401

    replayed = _login(client, account.email, _code(secret, clock[0]))
    assert replayed.status_code == 401

    clock[0] += totp.STEP_SECONDS
    fresh = _code(secret, clock[0])
    assert _login(client, account.email, fresh).status_code == 200

    client.cookies.clear()
    assert _login(client, account.email, fresh).status_code == 401

    actions = _actions(session, account)
    assert actions.count("MFA_FAILED") >= 4
    assert actions[-1] == "MFA_FAILED"
    assert "LOGIN" in actions


def test_step_up_accepts_the_code_when_mfa_is_active(client, session, account, clock):
    secret = _enrol(client, account, clock)
    client.cookies.clear()

    clock[0] += totp.STEP_SECONDS
    assert _login(client, account.email, _code(secret, clock[0])).status_code == 200

    assert _step_up(client, account.email).status_code == 401
    assert _step_up(client, account.email, _code(secret, clock[0])).status_code == 401

    clock[0] += totp.STEP_SECONDS
    assert _step_up(client, account.email, _code(secret, clock[0])).status_code == 200
    assert client.get("/api/v1/auth/me").json()["step_up_fresh"] is True


def test_a_code_used_in_one_session_is_refused_in_another(engine, session, account, monkeypatch):
    from sqlalchemy.orm import sessionmaker

    key = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(get_settings(), "master_key", key, raising=False)
    secret = totp.generate_secret()
    user = session.get(User, account.id)
    user.mfa_secret = totp.seal_secret(user.id, secret)
    user.mfa_enabled = True
    session.commit()

    code = _code(secret, START)
    monkeypatch.setattr(totp, "time", SimpleNamespace(time=lambda: START))
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    first, second = factory(), factory()
    try:
        assert A.verify_totp(first, first.get(User, account.id), code) is True
        first.commit()
        assert A.verify_totp(second, second.get(User, account.id), code) is False
    finally:
        first.close()
        second.close()
