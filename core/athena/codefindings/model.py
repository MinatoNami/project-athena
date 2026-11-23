"""The shape every code scanner adapter produces."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class CodeObservation:
    kind: str  # secret | misconfiguration
    rule_id: str
    title: str
    severity: str  # one of SEVERITIES
    path: str  # relative to the repository root
    line: int | None
    # Stable across scans of the same tree. Built by the adapter from the location
    # and rule — never from a secret's value, which is redacted before it reaches
    # this process. Observations told apart only by their order share a
    # `detail["identity_group"]`, so a scan never resolves one it cannot single out.
    fingerprint: str
    detail: dict[str, Any] = field(default_factory=dict)


def normalise_severity(value: Any, *, default: str = "medium") -> str:
    """A scanner's severity word, folded onto five values.

    `UNKNOWN` from a scanner is not "low": it becomes the default, which callers set
    to medium, for the same reason an unrated advisory is ranked as medium elsewhere.
    """
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
