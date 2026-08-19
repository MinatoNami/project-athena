"""Privileged executor.

The only component permitted to mutate protected systems. It reasons about nothing:
it validates a signed grant it could not have produced, records the intent, acts, and
records the outcome.

Three properties make the boundary real rather than aspirational:

  1. Separate image — no model client library is installed here at all.
  2. Separate database role — write access limited to change records and audit.
  3. Grants are signed by a key this process can verify but not produce.

M0 ships the process, the signature verification, and the loop. Execution capabilities
land in M5.
"""

from __future__ import annotations

import signal
import threading

import structlog

from athena_executor.config import ExecutorSettings
from athena_executor.grants import GrantVerifier

log = structlog.get_logger(__name__)
_stop = threading.Event()


def main() -> int:
    settings = ExecutorSettings()
    verifier = GrantVerifier(settings.grant_public_key)

    def handle(signum, _frame):
        log.info("executor.shutdown", signal=signum)
        _stop.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)

    log.info(
        "executor.start",
        verifier_ready=verifier.ready,
        note="no execution capabilities registered until M5",
    )

    while not _stop.is_set():
        # M5: claim execute.change jobs, validate the grant, snapshot, apply, verify.
        _stop.wait(5)

    log.info("executor.stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
