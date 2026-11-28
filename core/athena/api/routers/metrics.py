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
        "summary": {
            "total": len(computed),
            "measured": sum(1 for m in computed if m["value"] is not None),
            "not_enough_data": sum(1 for m in computed if m["status"] == "unknown"),
            "not_implemented": sum(1 for m in computed if m["status"] == "not_implemented"),
            "missing_target": sum(1 for m in computed if m["status"] == "missing"),
        },
    }
