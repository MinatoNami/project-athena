from __future__ import annotations

import pytest

from athena.queue import known_kinds
from athena.workers import worker  # noqa: F401
from athena.workers.scheduler import SCHEDULE


def test_every_scheduled_kind_has_a_handler():
    registered = set(known_kinds())
    scheduled = {kind for _, _, kind, _ in SCHEDULE}
    missing = scheduled - registered
    assert not missing, f"scheduled but unhandled: {sorted(missing)}"


@pytest.mark.parametrize(
    "kind",
    [
        "scan.repository",
        "ingest.node_observation",
        "intel.poll.osv",
        "intel.poll.kev",
        "intel.poll.epss",
        "intel.enrich.vulnrichment",
        "correlate.advisory",
        "correlate.asset",
        "correlate.stale",
    ],
)
def test_expected_handlers_are_registered(kind: str):
    assert kind in known_kinds(), f"{kind} has no handler"


def test_the_api_registers_the_same_handlers_as_the_worker():
    from athena.api.routers import jobs  # noqa: F401

    for kind in ("intel.poll.osv", "correlate.asset", "scan.repository"):
        assert kind in known_kinds()
