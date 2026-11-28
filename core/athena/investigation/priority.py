from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


FLOORS = {
    "all": 0,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_RANK = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
}


@dataclass(frozen=True)
class Decision:
    investigate: bool
    reason: str
    forced: bool = False


def rank(severity: str | None) -> Severity:
    return _RANK.get((severity or "").strip().lower(), Severity.MEDIUM)


def always_investigate(facts: dict[str, Any]) -> str | None:
    advisory = facts.get("advisory") or {}
    asset = facts.get("asset") or {}

    if advisory.get("malicious"):
        return "the package is published malware"
    if advisory.get("known_exploited"):
        return "known to be exploited in the wild"
    if (advisory.get("cvss") or 0) >= 9.0:
        return f"CVSS {advisory['cvss']}"
    if (advisory.get("epss") or 0) >= 0.1:
        return f"EPSS {advisory['epss']:.0%} — materially likely to be exploited"
    if asset.get("exposure") == "internet" and asset.get("tier") == "production":
        return "internet-facing production asset"
    return None


def decide(facts: dict[str, Any], *, floor: str) -> Decision:
    if (gate := always_investigate(facts)) is not None:
        return Decision(True, f"Always investigated: {gate}.", forced=True)

    threshold = FLOORS.get((floor or "all").strip().lower(), 0)
    if not threshold:
        return Decision(True, "The investigation floor selects everything.")

    severity = (facts.get("advisory") or {}).get("severity")
    where = rank(severity)
    if where >= threshold:
        return Decision(True, f"{where.name.lower()} severity is at or above the floor.")

    named = (severity or "").strip().lower() or "unrated"
    qualifier = "" if named in _RANK else ", ranked as medium because it is unrated"
    return Decision(
        False,
        f"Not investigated: the floor is set to {floor} and this is "
        f"{named}{qualifier}. Nothing has checked whether it applies here — it is "
        f"unexamined, not dismissed, and will be picked up if the floor is lowered "
        f"or its severity is revised.",
    )
