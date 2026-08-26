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

# Exploitation pressure to assume when no EPSS score exists. Above an advisory
# measured as negligible, far below one measured as likely. An advisory usually lacks
# a score because it is new, and new is when exploitation is most likely to follow —
# so reading the absence as "nil" gets it backwards exactly when it matters.
EPSS_UNKNOWN = 0.15

# Below this, a conclusion is too weak to drive a high band on its own. Read on the
# product of match and verdict confidence, because two moderate doubts really do
# compound — but applied *before* the known-exploitation floor, so the floor can lift
# it. That ordering is the whole correction: the cap used to come last and undercut
# the floor.
CONFIDENCE_FLOOR = 0.4

# Below this, we may be looking at the wrong package, which invalidates every other
# conclusion rather than merely weakening it. Set to sit above `heuristic_range`
# (0.40, "the comparator is a guess for this ecosystem") and below `cpe_range` (0.70),
# so it separates matches whose versions we actually ordered from matches we
# estimated. See correlation.MATCH_CONFIDENCE for the values it discriminates.
MATCH_FLOOR = 0.5

# Ecosystems whose packages are libraries linked into a program rather than services
# in their own right. "Is it running?" is not a question that has an answer for them,
# so a "no" must not be read as one.
LIBRARY_ECOSYSTEMS = {
    "npm", "pypi", "golang", "maven", "gem", "cargo", "nuget",
    "composer", "hex", "pub", "cran", "conan", "swift",
}


def component_role(ecosystem: str | None, scope: str | None = None) -> str:
    """`library` or `unknown` — is running-state a meaningful question here?

    Never returns `service`, because nothing in the system currently establishes
    that a component is one: `asset_component.is_running` is null on every
    installation we hold. Claiming otherwise would put a four-fold discount behind
    a fact nobody has observed.
    """
    if (ecosystem or "").lower() in LIBRARY_ECOSYSTEMS:
        return "library"
    # A transitive dependency was pulled in by something else, whatever ecosystem it
    # came from. Nothing starts it; something else links it.
    if scope == "transitive":
        return "library"
    return "unknown"


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
    component_role: str = "unknown"     # library | unknown; see component_role()
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


def _stopped(signals: Signals) -> bool:
    """Is there positive evidence that the thing which would run is not running?

    One predicate, used by both the multiplier and the known-exploitation floor.
    They previously took opposite conventions on the same fact — the multiplier
    declined to discount an unknown, while the floor declined to raise one — so a
    known-exploited flaw on an internet-facing host was scored `medium` because
    nobody could confirm the service was up. Absence of evidence now means the same
    thing in both places, because it is the same question asked once.
    """
    if signals.component_role == "library":
        return False
    return signals.service_running is False


def _exploitation(signals: Signals) -> float:
    """How much exploitation pressure to assume, 0..1.

    `epss is None` and `epss == 0.0` are deliberately different: the first is the
    absence of a measurement, the second is a measurement of almost nothing. Reading
    them alike meant a brand-new critical advisory nobody had scored yet was treated
    as evidence of non-exploitation.
    """
    return max(
        1.0 if signals.kev else 0.0,
        EPSS_UNKNOWN if signals.epss is None else signals.epss,
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
    # serving traffic — but "we do not know" must not earn the discount, and neither
    # may a library, for which the question does not arise.
    running = 0.25 if _stopped(signals) else 1.0

    importance = tier * criticality
    # Reported as one number because it is the honest overall confidence, but never
    # acted on as one: the overrides below read the two halves separately.
    confidence = max(0.0, min(signals.match_confidence * signals.verdict_confidence, 1.0))

    raw = base * (0.30 + 0.70 * exploitation) * exposure * running * importance * reach
    band = _band_for(raw)
    overrides: list[str] = []
    factors = {
        "base": base,
        "exploitation": exploitation,
        "exposure": exposure,
        "running": running,
        "importance": importance,
        "reachability": reach,
        "raw": raw,
    }

    # Applied after the arithmetic, and always recorded, so the number and the band
    # can disagree visibly rather than silently. Order matters and is asserted by
    # tests: each step may undo the one before it, and the last word belongs to the
    # doubt that invalidates everything else — that we identified the wrong package.
    if signals.verdict == "not_applicable":
        band = Band.INFORMATIONAL
        overrides.append("verdict is not_applicable, so the band is informational")
        return Score(value=round(100 * raw), band=band, confidence=confidence,
                     factors=factors, overrides=overrides)

    # 1. A conclusion we have little faith in should not drive a high band by itself.
    if confidence < CONFIDENCE_FLOOR:
        capped = _at_most(band, Band.MEDIUM)
        if capped != band:
            overrides.append(
                f"confidence {confidence:.2f} is low: capped at medium pending a "
                "better answer"
            )
            band = capped

    # 2. ...but known-exploited and internet-facing is not "by itself". This sits
    # after the cap above so it can lift it: being unable to establish whether an
    # actively exploited flaw is reachable is a reason to look, not a reason to relax.
    if signals.kev and signals.exposure == "internet" and not _stopped(signals):
        floor = _at_least(band, Band.HIGH)
        if floor != band:
            overrides.append(
                "known-exploited and internet-facing, with nothing showing it stopped: "
                "floored at high"
            )
            band = floor

    # 3. Production plus active exploitation earns one more band.
    if signals.tier == "production" and exploitation >= 0.9:
        escalated = _shift(band, 1)
        if escalated != band:
            overrides.append("production tier with active exploitation: escalated one band")
            band = escalated

    # 4. Last, so nothing above can undo it. A match we may have got wrong is not an
    # uncertainty about severity — it is the possibility that every conclusion above
    # concerns software that is not installed here at all.
    #
    # This reads match confidence alone, and it is the half that was previously
    # entangled with the other. One cap on the product came last, so "we could not
    # establish whether this is exploitable here" undercut the floor exactly as hard
    # as "this may be the wrong package" — and the first of those is precisely when a
    # known-exploited internet-facing finding most needs escalating. Compounded doubt
    # still caps, at step 1; only a doubtful match gets the last word.
    if signals.match_confidence < MATCH_FLOOR:
        capped = _at_most(band, Band.MEDIUM)
        if capped != band:
            overrides.append(
                f"match confidence {signals.match_confidence:.2f} is low: this may be "
                "the wrong package, so capped at medium"
            )
            band = capped

    if signals.fix_requires_entitlement:
        overrides.append(
            "the only published fix needs a paid entitlement, so this may not be "
            "actionable here"
        )
    elif not signals.fix_available:
        overrides.append("no fix published: the remediation clock does not start")

    return Score(value=round(100 * raw), band=band, confidence=confidence,
                 factors=factors, overrides=overrides)
