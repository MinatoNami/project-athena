from __future__ import annotations

import signal
import threading

import structlog

from athena_executor.config import ExecutorSettings
from athena_executor.grants import GrantVerifier
from athena_executor.registry import default_registry

log = structlog.get_logger(__name__)
_stop = threading.Event()


def main() -> int:
    settings = ExecutorSettings()
    verifier = GrantVerifier(settings.grant_public_key)
    registry = default_registry()

    def handle(signum, _frame):
        log.info("executor.shutdown", signal=signum)
        _stop.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)

    log.info(
        "executor.start",
        verifier_ready=verifier.ready,
        actions=sorted(registry.names()),
        note="grant claiming is not wired yet",
    )

    while not _stop.is_set():
        _stop.wait(5)

    log.info("executor.stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
