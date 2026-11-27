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
                    continue
                examined += 1
                before_band, before_score = finding.risk_band, finding.risk_score
                risk = score(signals_for(session, finding, _verdict_of(record)))
                if str(risk.band) == before_band and risk.value == before_score:
                    unchanged += 1
                    continue
                moved[f"{before_band} → {risk.band}"] += 1
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
    return rescore_all(dry_run=bool(payload.get("dry_run")))
