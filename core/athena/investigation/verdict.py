"""The structured verdict a model must return, and the rules it must satisfy.

The model produces schema-validated claims; code decides what they mean. Enforcement
is here rather than in the prompt, because a prompt is a request and this is a
requirement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SIGNAL_NAMES = [
    "component_present",
    "version_in_range",
    "service_running",
    "vulnerable_feature_enabled",
    "network_reachable",
    "authentication_required",
    "compensating_controls",
    "reachable_in_code",
]

_SIGNAL_SCHEMA = {
    "type": "object",
    "properties": {
        "value": {
            "description": "true, false, or 'unknown' when it could not be determined",
            "anyOf": [{"type": "boolean"}, {"type": "string"}],
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Names of the tools whose output supports this value",
        },
    },
    "required": ["value", "confidence", "evidence"],
    "additionalProperties": False,
}

VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "signals": {
            "type": "object",
            "properties": {name: _SIGNAL_SCHEMA for name in SIGNAL_NAMES},
            "required": SIGNAL_NAMES,
            "additionalProperties": False,
        },
        "verdict": {"type": "string", "enum": ["applicable", "not_applicable", "uncertain"]},
        "verdict_confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
        "uncertainties": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["signals", "verdict", "verdict_confidence", "rationale", "uncertainties"],
    "additionalProperties": False,
}

# A signal asserted above this confidence must cite the tool output that supports it.
GROUNDING_THRESHOLD = 0.5

# Claims about how the flaw works. No tool in the registry inspects configuration or
# code, so these can only ever be read out of the advisory — which makes them
# ungroundable when the advisory says nothing about the flaw.
MECHANISM_SIGNALS = frozenset({
    "vulnerable_feature_enabled",
    "reachable_in_code",
    "authentication_required",
})

# What it takes for `not_applicable` to mean anything. A dismissal has to rest on
# something that actually establishes non-applicability; otherwise it is a guess
# wearing a verdict's clothes, and it is the guess that gets a real finding closed.
DISMISSING: dict[str, Any] = {
    "component_present": (False,),
    "version_in_range": (False,),
    "vulnerable_feature_enabled": (False,),
    "reachable_in_code": ("no", "unlikely"),
    "compensating_controls": (True,),
}


@dataclass
class Signal:
    value: Any
    confidence: float
    evidence: list[str] = field(default_factory=list)
    downgraded: bool = False


@dataclass
class Verdict:
    signals: dict[str, Signal]
    verdict: str
    verdict_confidence: float
    rationale: str
    uncertainties: list[str] = field(default_factory=list)
    corrections: list[str] = field(default_factory=list)

    def signal_value(self, name: str) -> Any:
        signal = self.signals.get(name)
        return None if signal is None else signal.value


class MalformedVerdict(ValueError):
    pass


def parse_verdict(
    payload: dict[str, Any],
    *,
    tools_called: set[str],
    established: dict[str, Any] | None = None,
    advisory_describes_flaw: bool = True,
) -> Verdict:
    """Validate a model reply into a Verdict, correcting what must be corrected.

    These rules are enforced here rather than requested in the prompt, because a
    prompt is a request and these are requirements.

    A signal asserted with real confidence but citing no tool output is downgraded to
    unknown. Otherwise the model can assert anything and have it treated as a fact —
    which is precisely how an unfounded conclusion becomes a finding.

    A signal citing a tool that was never called is treated the same way. A model that
    names a tool it did not use is not reporting evidence, it is guessing.

    A signal the system already determined is taken from the system, not the model.
    `established` carries those: whether the component is installed is an inventory
    observation, and whether the version falls in the affected range is what
    correlation computed to create this finding at all. The model was contradicting
    both — asserting `version_in_range=False` about a finding that exists precisely
    because the version is in range — and citing a tool it really had called, so
    citation-checking could never catch it.

    Claims about how the flaw works are downgraded when the advisory does not describe
    the flaw. No tool inspects configuration or code, so the advisory is the only
    possible source; when it carries no rating, no weakness class and no detail, there
    is nothing for such a claim to have come from.

    Finally, `not_applicable` is refused unless something survives that establishes
    it. Dismissal is the one direction where being wrong is silent, so it is the one
    that has to earn its place.
    """
    established = established or {}
    if not isinstance(payload, dict):
        raise MalformedVerdict("Verdict was not an object")

    verdict = payload.get("verdict")
    if verdict not in ("applicable", "not_applicable", "uncertain"):
        raise MalformedVerdict(f"Unknown verdict {verdict!r}")

    corrections: list[str] = []
    signals: dict[str, Signal] = {}

    for name in SIGNAL_NAMES:
        raw = (payload.get("signals") or {}).get(name) or {}
        try:
            confidence = float(raw.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(confidence, 1.0))
        cited = [e for e in (raw.get("evidence") or []) if isinstance(e, str)]
        value = raw.get("value", "unknown")

        if name in established:
            fact = established[name]
            if value != fact:
                corrections.append(
                    f"{name}: model said {value!r}, but this is not its question to "
                    f"answer — the system determined {fact!r}"
                )
            signals[name] = Signal(
                value=fact, confidence=1.0, evidence=["system of record"],
                downgraded=value != fact,
            )
            continue

        if name in MECHANISM_SIGNALS and not advisory_describes_flaw and value != "unknown":
            corrections.append(
                f"{name}: the advisory carries no rating, weakness class or detail, so "
                "nothing available describes how this flaw works — downgraded to unknown"
            )
            signals[name] = Signal(value="unknown", confidence=0.0, evidence=[],
                                   downgraded=True)
            continue

        uncited = [c for c in cited if c not in tools_called]
        if uncited:
            corrections.append(
                f"{name}: cited {', '.join(uncited)}, which was never called — "
                "downgraded to unknown"
            )
            value, confidence, cited = "unknown", 0.0, []
        elif confidence > GROUNDING_THRESHOLD and not cited:
            corrections.append(
                f"{name}: asserted at {confidence:.2f} with no supporting tool output — "
                "downgraded to unknown"
            )
            value, confidence = "unknown", 0.0

        signals[name] = Signal(
            value=value, confidence=confidence, evidence=cited,
            downgraded=bool(uncited) or (confidence == 0.0 and raw.get("confidence", 0)),
        )

    try:
        verdict_confidence = max(0.0, min(float(payload.get("verdict_confidence", 0.0)), 1.0))
    except (TypeError, ValueError):
        verdict_confidence = 0.0

    uncertainties = [str(u)[:500] for u in (payload.get("uncertainties") or [])][:10]

    # A verdict resting on downgraded signals cannot be more trustworthy than they
    # are. Half the signals corrected means the conclusion is not well-founded.
    if len(corrections) >= len(SIGNAL_NAMES) / 2 and verdict != "uncertain":
        corrections.append(
            f"{len(corrections)} of {len(SIGNAL_NAMES)} signals were unfounded — "
            "verdict forced to uncertain"
        )
        verdict, verdict_confidence = "uncertain", min(verdict_confidence, 0.3)

    # Dismissal is the asymmetric direction. An `applicable` that should have been
    # `not_applicable` costs somebody an hour; a `not_applicable` that should have
    # been `applicable` closes a real finding and nobody ever looks again. So it is
    # the direction required to show its working.
    if verdict == "not_applicable" and not _supports_dismissal(signals):
        corrections.append(
            "verdict was not_applicable, but no signal survived that establishes it — "
            "forced to uncertain"
        )
        verdict, verdict_confidence = "uncertain", min(verdict_confidence, 0.3)
        uncertainties.append(
            "Nothing available established that this does not apply; it was neither "
            "confirmed nor ruled out."
        )

    return Verdict(
        signals=signals,
        verdict=verdict,
        verdict_confidence=verdict_confidence,
        rationale=str(payload.get("rationale") or "")[:4000],
        uncertainties=uncertainties[:10],
        corrections=corrections,
    )


def _supports_dismissal(signals: dict[str, Signal]) -> bool:
    """Did anything survive grounding that actually rules this finding out?"""
    return any(
        (signal := signals.get(name)) is not None
        and signal.confidence > 0.0
        and signal.value in accepted
        for name, accepted in DISMISSING.items()
    )
