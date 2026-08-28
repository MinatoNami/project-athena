"""Which findings are worth spending a model call on.

A budget buys a finite number of investigations, and something has to decide which
ones. This is that decision, and it is deliberately made from facts that exist before
any investigation runs — severity as published, whether the thing is known to be
exploited, what the asset is for. Nothing here is a judgement about whether the
vulnerability applies; that is what the investigation is for, and pre-empting it is
exactly the mistake this codebase refuses to make elsewhere.

So a deferred finding is never scored, never closed and never called low risk. It
stays `discovered`, still reports that nothing has checked it, and is picked up the
moment the floor is lowered or its facts change. The only claim made about it is that
the operator's floor did not select it — which is a statement about the floor.

Two rules keep it from becoming a blindfold.

Some findings are investigated whatever the floor says. Those gates already existed —
triage used them to override the model — and they are here now so that one definition
serves both, rather than two copies drifting until a KEV entry falls through the gap
between them.

Unknown is never treated as harmless. An advisory with no severity is ranked as
though it were medium, because "nobody has scored this yet" and "this is not serious"
are different statements and only one of them is evidence. The same principle already
governs risk scoring, where an unset tier is scored as middling rather than as zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so a floor can be a comparison."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# `all` is the floor that selects everything, and it is the default: an upgrade must
# not quietly start skipping findings a deployment was already investigating.
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
    # Phrased for somebody reading it on the finding, not for a log line.
    reason: str
    # True when a gate overrode the floor, so the caller can tell a finding that
    # cleared the bar from one that was never subject to it.
    forced: bool = False


def rank(severity: str | None) -> Severity:
    """Where an advisory sits, with unknown ranked as medium rather than as low.

    Most of this estate's advisories carry a severity and no CVSS at all — 528 of the
    findings awaiting investigation have no CVSS score between them — so severity is
    the axis that actually discriminates here, and treating an absent one as the
    bottom of the scale would push exactly the unmeasured findings out of view.
    """
    return _RANK.get((severity or "").strip().lower(), Severity.MEDIUM)


def always_investigate(facts: dict[str, Any]) -> str | None:
    """Reasons a finding is investigated whatever the floor or the model says.

    In code rather than in a prompt or a config value because they are requirements.
    A model asked nicely not to skip known-exploited vulnerabilities will still
    occasionally skip one, and a floor set in a hurry should not be able to.
    """
    advisory = facts.get("advisory") or {}
    asset = facts.get("asset") or {}

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
    """Whether this finding earns a model call under the configured floor."""
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
