from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from athena_executor.audit import AUDIT_LOCK, GENESIS, canonical, chain_hash, record

AT = datetime(2026, 11, 28, 12, 0, 0, 123456, tzinfo=UTC)


class FakeResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalar_one(self):
        return self.value


class FakeConnection:
    def __init__(self, latest_hash: bytes | None) -> None:
        self.statements: list[str] = []
        self.inserted: dict | None = None
        self.latest_hash = latest_hash

    def execute(self, statement, params=None):
        sql = str(statement)
        self.statements.append(sql)
        if "pg_advisory_xact_lock" in sql:
            return FakeResult(None)
        if sql.startswith("SELECT hash"):
            return FakeResult(self.latest_hash)
        if sql == "SELECT now()":
            return FakeResult(AT)
        self.inserted = params
        return FakeResult(42)


def test_canonical_form_is_prev_then_sorted_compact_json():
    body = canonical(
        at=AT,
        actor="executor",
        action="NOOP",
        subject="grant:n",
        detail={"b": 1, "a": 2},
        prev=GENESIS,
    )
    assert body == GENESIS + (
        b'{"action":"NOOP","actor":"executor","at":"2026-11-28T12:00:00.123456+00:00",'
        b'"detail":{"a":2,"b":1},"subject":"grant:n"}'
    )


def test_chain_hash_is_sha256_of_the_canonical_form():
    kwargs = dict(at=AT, actor="a", action="b", subject="c", detail={}, prev=GENESIS)
    assert chain_hash(**kwargs) == hashlib.sha256(canonical(**kwargs)).digest()


def test_record_locks_before_reading_the_head_and_starts_from_genesis():
    conn = FakeConnection(latest_hash=None)
    entry = record(conn, actor="executor", action="NOOP", subject="grant:n")

    assert conn.statements[0] == str(AUDIT_LOCK)
    assert conn.statements[0] == "SELECT pg_advisory_xact_lock(hashtext('athena.audit'))"
    assert entry.prev_hash == GENESIS
    assert entry.seq == 42
    assert conn.inserted["hash"] == entry.hash
    assert conn.inserted["detail"] == "{}"


def test_record_chains_onto_the_latest_hash():
    head = hashlib.sha256(b"head").digest()
    conn = FakeConnection(latest_hash=memoryview(head))
    entry = record(conn, actor="executor", action="NOOP", subject="s", detail={"k": "v"})
    assert entry.prev_hash == head
    assert entry.hash == chain_hash(
        at=AT, actor="executor", action="NOOP", subject="s", detail={"k": "v"}, prev=head
    )
