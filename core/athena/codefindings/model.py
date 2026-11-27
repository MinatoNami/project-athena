from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class CodeObservation:
    kind: str
    rule_id: str
    title: str
    severity: str
    path: str
    line: int | None
    fingerprint: str
    detail: dict[str, Any] = field(default_factory=dict)


def normalise_severity(value: Any, *, default: str = "medium") -> str:
    word = str(value or "").strip().lower()
    word = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "informational": "info",
        "moderate": "medium",
        "none": "info",
    }.get(word, word)
    return word if word in SEVERITIES else default
