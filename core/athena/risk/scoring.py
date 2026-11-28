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
    "unknown": 0.75,
}

TIER_WEIGHT = {
    "production": 1.00,
    "staging": 0.60,
    "development": 0.35,
    "personal": 0.30,
    "unknown": 0.70,
}

CRITICALITY_WEIGHT = {1: 0.40, 2: 0.60, 3: 0.75, 4: 0.90, 5: 1.00, None: 0.75}

REACHABILITY_WEIGHT = {
    "confirmed": 1.00,
    "likely": 0.80,
    "unknown": 0.60,
    "unlikely": 0.30,
    "no": 0.05,
}

SEVERITY_SCORE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}

EPSS_UNKNOWN = 0.15

CONFIDENCE_FLOOR = 0.4

MATCH_FLOOR = 0.5

LIBRARY_ECOSYSTEMS = {
    "npm", "pypi", "golang", "maven", "gem", "cargo", "nuget",
    "composer", "hex", "pub", "cran", "conan", "swift",
}


def component_role(ecosystem: str | None, scope: str | None = None) -> str:
    if (ecosystem or "").lower() in LIBRARY_ECOSYSTEMS:
        return "library"
    if scope == "transitive":
        return "library"
    return "unknown"


@dataclass
class Signals:
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
    component_role: str = "unknown"
    match_confidence: float = 1.0
    verdict_confidence: float = 1.0
    verdict: str = "uncertain"
    fix_available: bool = True
    fix_requires_entitlement: bool = False
    malicious: bool = False


@dataclass
class Score:
    value: int
    band: Band
    confidence: float
    factors: dict[str, float]
    overrides: list[str] = field(default_factory=list)

    def explain(self) -> dict[str, Any]:
        return {
            "score": self.value,
            "band": str(self.band),
            "confidence": round(self.confidence, 3),
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
            "overrides": self.overrides,
        }


def _base(signals: Signals) -> float:
    if signals.cvss_score is not None:
        return max(0.0, min(signals.cvss_score, 10.0)) / 10.0
    if signals.severity and signals.severity.lower() in SEVERITY_SCORE:
        return SEVERITY_SCORE[signals.severity.lower()] / 10.0
    return 0.5


def _stopped(signals: Signals) -> bool:
    if signals.component_role == "library":
        return False
    return signals.service_running is False


def _exploitation(signals: Signals) -> float:
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


def _malware(signals: Signals) -> Score:
    importance = TIER_WEIGHT.get(signals.tier, TIER_WEIGHT["unknown"]) * CRITICALITY_WEIGHT.get(
        signals.criticality, 0.75
    )
    raw = importance
    confidence = max(0.0, min(signals.match_confidence * signals.verdict_confidence, 1.0))
    factors = {
        "base": 1.0,
        "exploitation": 1.0,
        "exposure": 1.0,
        "running": 1.0,
        "importance": importance,
        "reachability": 1.0,
        "raw": raw,
    }
    overrides = [
        "malicious package: severity, exploitation, exposure and reachability do not "
        "discount malware, so they are pinned at 1.0",
        "malicious package present: floored at critical",
    ]
    band = Band.CRITICAL
    if signals.verdict == "not_applicable":
        overrides.append(
            "the investigation concluded not_applicable, which does not close a malware "
            "finding: a person has to"
        )
    if signals.match_confidence < MATCH_FLOOR:
        band = Band.MEDIUM
        overrides.append(
            f"match confidence {signals.match_confidence:.2f} is low: this may be a "
            "different package with a similar name, so capped at medium"
        )
    return Score(value=round(100 * raw), band=band, confidence=confidence,
                 factors=factors, overrides=overrides)


def score(signals: Signals) -> Score:
    if signals.malicious:
        return _malware(signals)

    base = _base(signals)
    exploitation = _exploitation(signals)
    exposure = EXPOSURE_WEIGHT.get(signals.exposure, EXPOSURE_WEIGHT["unknown"])
    tier = TIER_WEIGHT.get(signals.tier, TIER_WEIGHT["unknown"])
    criticality = CRITICALITY_WEIGHT.get(signals.criticality, 0.75)
    reach = REACHABILITY_WEIGHT.get(signals.reachable_in_code, REACHABILITY_WEIGHT["unknown"])

    running = 0.25 if _stopped(signals) else 1.0

    importance = tier * criticality
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

    if signals.verdict == "not_applicable":
        band = Band.INFORMATIONAL
        overrides.append("verdict is not_applicable, so the band is informational")
        return Score(value=round(100 * raw), band=band, confidence=confidence,
                     factors=factors, overrides=overrides)

    if confidence < CONFIDENCE_FLOOR:
        capped = _at_most(band, Band.MEDIUM)
        if capped != band:
            overrides.append(
                f"confidence {confidence:.2f} is low: capped at medium pending a "
                "better answer"
            )
            band = capped

    if signals.kev and signals.exposure == "internet" and not _stopped(signals):
        floor = _at_least(band, Band.HIGH)
        if floor != band:
            overrides.append(
                "known-exploited and internet-facing, with nothing showing it stopped: "
                "floored at high"
            )
            band = floor

    if signals.tier == "production" and exploitation >= 0.9:
        escalated = _shift(band, 1)
        if escalated != band:
            overrides.append("production tier with active exploitation: escalated one band")
            band = escalated

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
