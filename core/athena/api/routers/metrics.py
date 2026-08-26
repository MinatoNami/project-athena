"""The success metrics, with their denominators and their gaps.

Every metric returns its denominator and a status. A rate with neither is an
assertion, and four of these cannot be computed on this system at all — reporting
those as zero would be the same lie as an empty findings list meaning "clean".
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from athena.api.deps import Principal, current_principal, db
from athena.metrics import all_metrics, sla_report

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
def metrics(
    _: Principal = Depends(current_principal),
    session: Session = Depends(db),
) -> dict[str, Any]:
    computed = all_metrics(session)
    return {
        "metrics": computed,
        "sla": sla_report(session),
        # Counted so the page can lead with how much of itself it cannot answer,
        # rather than leaving that to be discovered card by card.
        "summary": {
            "total": len(computed),
            "measured": sum(1 for m in computed if m["value"] is not None),
            "not_enough_data": sum(1 for m in computed if m["status"] == "unknown"),
            "not_implemented": sum(1 for m in computed if m["status"] == "not_implemented"),
            "missing_target": sum(1 for m in computed if m["status"] == "missing"),
        },
    }
