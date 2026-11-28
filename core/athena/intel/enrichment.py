from __future__ import annotations

from typing import Any

from sqlalchemy import exists

from athena.db.models import Finding, Vulnerability

SKIP_STATES = ("resolved", "false_positive", "unmatched")


def eligible() -> list[Any]:
    return [
        Vulnerability.id.like("CVE-%"),
        Vulnerability.withdrawn_at.is_(None),
        exists().where(
            Finding.vulnerability_id == Vulnerability.id,
            Finding.state.notin_(SKIP_STATES),
        ),
    ]
