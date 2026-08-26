"""Recompute stored scores from stored investigations.

The score is a pure function of signals that are already on disk, so changing that
function does not require asking a model anything again. Without this, a scoring fix
would stay invisible: the re-investigation guard deliberately declines to investigate
a finding whose advisory has not changed, which is right — an inconclusive answer is
not a reason to spend forty seconds asking again — but it also means a corrected
score would never reach the UI.

Verdicts are not re-derived here. What the model concluded is left exactly as it was;
only the arithmetic applied to those conclusions is redone.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select

from athena.db.base import session_scope
from athena.db.models import Finding, InvestigationRecord
from athena.queue.registry import handler
from athena.risk import score

log = structlog.get_logger(__name__)

BATCH = 500


def rescore_all(*, dry_run: bool = False) -> dict[str, Any]:
    """Rescore every investigated finding. Returns a summary of what moved."""
    from athena.workers.investigate import _verdict_of, signals_for

    moved: Counter[str] = Counter()
    unchanged = 0
    examined = 0
    last_id = None

    while True:
        with session_scope() as session:
            query = (
                select(Finding)
                .where(Finding.investigation_id.is_not(None))
                .order_by(Finding.id)
                .limit(BATCH)
            )
            if last_id is not None:
                query = query.where(Finding.id > last_id)
            findings = session.execute(query).scalars().all()
            if not findings:
                break
            last_id = findings[-1].id

            for finding in findings:
                record = session.get(InvestigationRecord, finding.investigation_id)
                if record is None:
                    # The verdict it was scored from is gone, so there is nothing to
                    # recompute honestly. Left alone rather than guessed at.
                    continue
                examined += 1
                before_band, before_score = finding.risk_band, finding.risk_score
                risk = score(signals_for(session, finding, _verdict_of(record)))
                if str(risk.band) == before_band and risk.value == before_score:
                    unchanged += 1
                    continue
                moved[f"{before_band} → {risk.band}"] += 1
                # A dry run reads and compares; it simply never assigns. There is
                # no rollback to rely on, so there is nothing to get wrong.
                if not dry_run:
                    finding.risk_score = risk.value
                    finding.risk_band = str(risk.band)
                    finding.last_evaluated_at = datetime.now(UTC)

    summary = {
        "examined": examined,
        "unchanged": unchanged,
        "changed": sum(moved.values()),
        "movements": dict(moved.most_common()),
        "dry_run": dry_run,
    }
    log.info("rescore.done", **{k: v for k, v in summary.items() if k != "movements"})
    return summary


@handler("rescore.findings")
def rescore_findings(payload: dict[str, Any]) -> dict[str, Any]:
    """Recompute every stored score. Enqueued after anything that changes the inputs.

    Classifying an asset changes its tier and exposure, which are scoring inputs — but
    the re-investigation guard rightly declines to ask a model again about an advisory
    that has not moved. Without this the user would classify their estate and watch
    nothing happen.
    """
    return rescore_all(dry_run=bool(payload.get("dry_run")))
