from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest

from athena.audit import record, verify_chain
from athena.audit.chain import GENESIS, _canonical

executor_audit = pytest.importorskip(
    "athena_executor.audit", reason="install the executor package to run the parity tests"
)

RECORDS = [
    {
        "at": datetime(2026, 11, 28, 12, 0, tzinfo=UTC),
        "actor": "executor",
        "action": "EXECUTION_STARTED",
        "subject": "grant:nonce-1",
        "detail": {},
    },
    {
        "at": datetime(2026, 11, 28, 12, 0, 0, 1, tzinfo=timezone(timedelta(hours=8))),
        "actor": "user:7",
        "action": "APPROVED",
        "subject": "change:1",
        "detail": {"z": [3, 2, 1], "a": {"nested": True, "none": None}, "n": 1.5},
    },
    {
        "at": datetime(2026, 11, 28, 23, 59, 59, 999999, tzinfo=UTC),
        "actor": "executor",
        "action": "EXECUTION_VERIFIED",
        "subject": "asset:Ωμέγα",
        "detail": {"note": 'naïve "quoted" \\ text\n', "big": 2**63, "neg": -0.0},
    },
    {
        "at": datetime(2026, 11, 29, tzinfo=UTC),
        "actor": "executor",
        "action": "EXECUTION_ROLLED_BACK",
        "subject": "grant:nonce-2",
        "detail": {"when": datetime(2026, 11, 29, tzinfo=UTC), "ids": (1, 2)},
    },
]


def core_chain(records: list[dict]) -> list[bytes]:
    prev, hashes = GENESIS, []
    for r in records:
        prev = hashlib.sha256(_canonical(prev=prev, **r)).digest()
        hashes.append(prev)
    return hashes


def executor_chain(records: list[dict]) -> list[bytes]:
    prev, hashes = executor_audit.GENESIS, []
    for r in records:
        prev = executor_audit.chain_hash(prev=prev, **r)
        hashes.append(prev)
    return hashes


def test_both_writers_start_from_the_same_genesis():
    assert executor_audit.GENESIS == GENESIS


@pytest.mark.parametrize("index", range(len(RECORDS)))
def test_canonical_bytes_are_identical(index):
    prev = hashlib.sha256(str(index).encode()).digest()
    assert executor_audit.canonical(prev=prev, **RECORDS[index]) == _canonical(
        prev=prev, **RECORDS[index]
    )


def test_chains_are_identical():
    assert executor_chain(RECORDS) == core_chain(RECORDS)


def test_interleaved_writers_keep_the_chain_intact(session):
    connection = session.connection()
    first = record(session, actor="core", action="PARITY_A", subject="s:1", detail={"i": 1})
    second = executor_audit.record(
        connection,
        actor="executor",
        action="PARITY_B",
        subject="grant:parity",
        detail={"plan": {"changes": []}, "status": "verified", "nested": {"b": 2, "a": 1}},
    )
    third = record(session, actor="core", action="PARITY_C", subject="s:3", detail={})
    fourth = executor_audit.record(connection, actor="executor", action="PARITY_D", subject="s:4")
    session.commit()

    assert second.prev_hash == bytes(first.hash)
    assert bytes(third.prev_hash) == second.hash
    assert fourth.prev_hash == bytes(third.hash)

    result = verify_chain(session)
    assert result["intact"] is True
    assert result["head"] == fourth.hash.hex()
