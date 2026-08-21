"""Deterministic risk scoring.

The model supplies signal *values*; this function supplies the *number*. It is pure,
unit-tested, and explainable — a score nobody can reconstruct is not evidence, and an
LLM-decided severity is neither auditable nor reproducible.

Implements docs/TECHNICAL_DESIGN.md §8.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Band(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# Ordered low to high, so escalation and floors are expressible as index arithmetic.
BAND_ORDER = [
    Band.INFORMATIONAL,
    Band.LOW,
    Band.MEDIUM,
    Band.HIGH,
    Band.CRITICAL,
]

THRESHOLDS: list[tuple[float, Band]] = [
    (0.70, Band.CRITICAL),
    (0.45, Band.HIGH),
    (0.20, Band.MEDIUM),
    (0.05, Band.LOW),
]

EXPOSURE_WEIGHT = {
    "internet": 1.00,
    "internal": 0.60,
    "isolated": 0.20,
    # Unknown exposure scores between internal and internet rather than at the
    # bottom: not knowing is not the same as being safe, and defaulting low would
    # quietly discount every asset nobody has classified.
    "unknown": 0.75,
}

TIER_WEIGHT = {
    "production": 1.00,
    "staging": 0.60,
    "development": 0.35,
    "personal": 0.30,
    # Same reasoning as exposure: an unclassified asset is not a low-value one.
    "unknown": 0.70,
}

# criticality 1..5; None means nobody has said, which is not the same as unimportant.
CRITICALITY_WEIGHT = {1: 0.40, 2: 0.60, 3: 0.75, 4: 0.90, 5: 1.00, None: 0.75}

REACHABILITY_WEIGHT = {
    "confirmed": 1.00,
    "likely": 0.80,
    "unknown": 0.60,
    "unlikely": 0.30,
    "no": 0.05,
}

# Qualitative severities, for advisories that carry a word instead of a CVSS vector.
SEVERITY_SCORE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}


@dataclass
class Signals:
    """Everything the score depends on. Nothing else may influence it."""

    cvss_score: float | None = None
    severity: str | None = None
    kev: bool = False
    epss: float | None = None
    exploit_public: bool = False
    exposure: str = "unknown"
    service_running: bool | None = None
    tier: str = "unknown"
    criticality: int | None = None
    reachable_in_code: str = "unknown"
    match_confidence: float = 1.0
    verdict_confidence: float = 1.0
    verdict: str = "uncertain"          # applicable | not_applicable | uncertain
    fix_available: bool = True
    fix_requires_entitlement: bool = False


@dataclass
class Score:
    value: int                          # 0..100
    band: Band
    confidence: float
    factors: dict[str, float]
    overrides: list[str] = field(default_factory=list)

    def explain(self) -> dict[str, Any]:
        """The breakdown the API returns and the UI renders.

        "Why is this critical?" must be answerable without reading code.
        """
        return {
            "score": self.value,
            "band": str(self.band),
            "confidence": round(self.confidence, 3),
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
            "overrides": self.overrides,
        }


def _base(signals: Signals) -> float:
    """Severity, normalised to 0..1.

    Falls back to the qualitative label because distribution advisories usually
    carry a word rather than a vector — ignoring those would score most distro
    findings at zero.
    """
    if signals.cvss_score is not None:
        return max(0.0, min(signals.cvss_score, 10.0)) / 10.0
    if signals.severity and signals.severity.lower() in SEVERITY_SCORE:
        return SEVERITY_SCORE[signals.severity.lower()] / 10.0
    # No severity at all. Scored as middling rather than zero: an unrated advisory
    # is unrated, not harmless.
    return 0.5


def _exploitation(signals: Signals) -> float:
    return max(
        1.0 if signals.kev else 0.0,
        signals.epss or 0.0,
        0.7 if signals.exploit_public else 0.0,
    )


def _band_for(raw: float) -> Band:
    for threshold, band in THRESHOLDS:
        if raw >= threshold:
            return band
    return Band.INFORMATIONAL


def _shift(band: Band, steps: int) -> Band:
    index = BAND_ORDER.index(band) + steps
    return BAND_ORDER[max(0, min(index, len(BAND_ORDER) - 1))]


def _at_least(band: Band, floor: Band) -> Band:
    return band if BAND_ORDER.index(band) >= BAND_ORDER.index(floor) else floor


def _at_most(band: Band, ceiling: Band) -> Band:
    return band if BAND_ORDER.index(band) <= BAND_ORDER.index(ceiling) else ceiling


def score(signals: Signals) -> Score:
    """Risk for one finding on one asset.

    Scored per instance, never per vulnerability: the same CVE is critical on an
    internet-facing production host and informational on an isolated laptop.
    """
    base = _base(signals)
    exploitation = _exploitation(signals)
    exposure = EXPOSURE_WEIGHT.get(signals.exposure, EXPOSURE_WEIGHT["unknown"])
    tier = TIER_WEIGHT.get(signals.tier, TIER_WEIGHT["unknown"])
    criticality = CRITICALITY_WEIGHT.get(signals.criticality, 0.75)
    reach = REACHABILITY_WEIGHT.get(signals.reachable_in_code, REACHABILITY_WEIGHT["unknown"])

    # A component that is installed but not running is a smaller problem than one
    # serving traffic — but "we do not know" must not earn the discount.
    running = 1.0 if signals.service_running is not False else 0.25

    importance = tier * criticality
    confidence = max(0.0, min(signals.match_confidence * signals.verdict_confidence, 1.0))

    raw = base * (0.30 + 0.70 * exploitation) * exposure * running * importance * reach
    band = _band_for(raw)
    overrides: list[str] = []

    # Applied after the arithmetic, and always recorded, so the number and the band
    # can disagree visibly rather than silently.
    if signals.verdict == "not_applicable":
        band = Band.INFORMATIONAL
        overrides.append("verdict is not_applicable, so the band is informational")

    elif signals.kev and signals.exposure == "internet" and signals.service_running:
        floor = _at_least(band, Band.HIGH)
        if floor != band:
            overrides.append(
                "known-exploited, internet-facing, and running: floored at high"
            )
            band = floor

    if signals.verdict != "not_applicable":
        if signals.tier == "production" and exploitation >= 0.9:
            escalated = _shift(band, 1)
            if escalated != band:
                overrides.append("production tier with active exploitation: escalated one band")
                band = escalated

        # Applied last, so it can override the known-exploitation floor above. That
        # ordering is deliberate: a floor on a finding we may have matched against
        # the wrong package manufactures urgency out of an uncertain match. Both
        # overrides are recorded, so the tension is visible rather than resolved
        # invisibly.
        if confidence < 0.4:
            capped = _at_most(band, Band.MEDIUM)
            if capped != band:
                overrides.append(
                    f"confidence {confidence:.2f} is low: capped at medium until investigated"
                )
                band = capped

        if signals.fix_requires_entitlement:
            overrides.append(
                "the only published fix needs a paid entitlement, so this may not be "
                "actionable here"
            )
        elif not signals.fix_available:
            overrides.append("no fix published: the remediation clock does not start")

    return Score(
        value=round(100 * raw),
        band=band,
        confidence=confidence,
        factors={
            "base": base,
            "exploitation": exploitation,
            "exposure": exposure,
            "running": running,
            "importance": importance,
            "reachability": reach,
            "raw": raw,
        },
        overrides=overrides,
    )
