from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from athena.intel import cvss

TRACK = "track"
TRACK_STAR = "track*"
ATTEND = "attend"
ACT = "act"

OUTCOME_ORDER = [TRACK, TRACK_STAR, ATTEND, ACT]

OUTCOME_MEANING = {
    TRACK: "No action needed now; remediate within standard update timelines.",
    TRACK_STAR: (
        "Contains characteristics that warrant closer monitoring; remediate within "
        "standard update timelines."
    ),
    ATTEND: ("Needs attention from leadership; remediate sooner than standard update timelines."),
    ACT: ("Needs attention from leadership and action as soon as possible; remediate immediately."),
}

_TABLE: dict[tuple[str, str, str], tuple[str, str, str]] = {
    ("none", "no", "partial"): (TRACK, TRACK, TRACK),
    ("none", "no", "total"): (TRACK, TRACK, TRACK_STAR),
    ("none", "yes", "partial"): (TRACK, TRACK, ATTEND),
    ("none", "yes", "total"): (TRACK, TRACK, ATTEND),
    ("poc", "no", "partial"): (TRACK, TRACK, TRACK_STAR),
    ("poc", "no", "total"): (TRACK, TRACK_STAR, ATTEND),
    ("poc", "yes", "partial"): (TRACK, TRACK, ATTEND),
    ("poc", "yes", "total"): (TRACK, TRACK_STAR, ATTEND),
    ("active", "no", "partial"): (TRACK, TRACK, ATTEND),
    ("active", "no", "total"): (TRACK, ATTEND, ACT),
    ("active", "yes", "partial"): (ATTEND, ATTEND, ACT),
    ("active", "yes", "total"): (ATTEND, ACT, ACT),
}

_MWB_INDEX = {"low": 0, "medium": 1, "high": 2}


@dataclass
class DecisionPoint:
    value: str
    basis: str
    assumed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"value": self.value, "basis": self.basis, "assumed": self.assumed}


@dataclass
class Decision:
    outcome: str
    points: dict[str, DecisionPoint]
    notes: list[str] = field(default_factory=list)

    @property
    def assumed(self) -> list[str]:
        return [name for name, p in self.points.items() if p.assumed]

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "meaning": OUTCOME_MEANING[self.outcome],
            "points": {name: p.as_dict() for name, p in self.points.items()},
            "assumed": self.assumed,
            "notes": self.notes,
            "framework": "CISA SSVC coordinator tree (2.0.3)",
        }


def _cisa_value(cisa: dict[str, Any] | None, key: str, allowed: tuple[str, ...]) -> str | None:
    if not cisa:
        return None
    value = str(cisa.get(key) or "").strip().lower().replace("public poc", "poc")
    return value if value in allowed else None


def _cisa_basis(cisa: dict[str, Any]) -> str:
    stamp = str(cisa.get("timestamp") or "")[:10]
    return f"CISA Vulnrichment assessment{f' ({stamp})' if stamp else ''}"


def exploitation(
    *, kev: bool, exploit_public: bool, cisa: dict[str, Any] | None = None
) -> DecisionPoint:
    if kev:
        return DecisionPoint("active", "listed in CISA's Known Exploited Vulnerabilities")
    if (value := _cisa_value(cisa, "exploitation", ("none", "poc", "active"))) is not None:
        return DecisionPoint(value, _cisa_basis(cisa or {}))
    if exploit_public:
        return DecisionPoint("poc", "a public exploit or proof of concept is recorded")
    return DecisionPoint(
        "none",
        "not in the known-exploited catalogue and no public exploit recorded",
    )


def automatable(vector: str | None, cisa: dict[str, Any] | None = None) -> DecisionPoint:
    if (value := _cisa_value(cisa, "automatable", ("yes", "no"))) is not None:
        return DecisionPoint(value, _cisa_basis(cisa or {}))
    try:
        parsed = cvss.parse(vector)
    except cvss.VectorError:
        return DecisionPoint("yes", "no CVSS vector to read; assumed automatable", True)
    m = parsed.metrics
    conditions = [m.get("AV") == "N", m.get("AC") == "L", m.get("PR") == "N", m.get("UI") == "N"]
    if parsed.version == "4.0":
        conditions.append(m.get("AT") == "N")
    if all(conditions):
        return DecisionPoint(
            "yes",
            f"CVSS {parsed.version}: network, low complexity, no privileges, no user interaction",
        )
    return DecisionPoint(
        "no", f"CVSS {parsed.version}: exploitation needs access, privileges or a user"
    )


def technical_impact(vector: str | None, cisa: dict[str, Any] | None = None) -> DecisionPoint:
    if (value := _cisa_value(cisa, "technical_impact", ("partial", "total"))) is not None:
        return DecisionPoint(value, _cisa_basis(cisa or {}))
    try:
        parsed = cvss.parse(vector)
    except cvss.VectorError:
        return DecisionPoint("total", "no CVSS vector to read; assumed total", True)
    m = parsed.metrics
    c, i = (m.get("VC"), m.get("VI")) if parsed.version == "4.0" else (m.get("C"), m.get("I"))
    if c == "H" and i == "H":
        return DecisionPoint(
            "total", f"CVSS {parsed.version}: high confidentiality and integrity impact"
        )
    return DecisionPoint(
        "partial", f"CVSS {parsed.version}: impact short of total control or disclosure"
    )


def mission_wellbeing(*, tier: str | None, criticality: int | None) -> DecisionPoint:
    tier = (tier or "unknown").lower()
    if criticality == 5 or (tier == "production" and (criticality or 3) >= 4):
        return DecisionPoint("high", f"{tier} tier, criticality {criticality}")
    if tier == "unknown" and criticality is None:
        return DecisionPoint("medium", "the asset has no tier or criticality; assumed medium", True)
    partial = criticality is None or tier == "unknown"
    if tier in ("production", "staging", "unknown") or (criticality or 0) >= 3:
        detail = f"criticality {criticality}" if criticality else "criticality unset"
        return DecisionPoint("medium", f"{tier} tier, {detail}", partial)
    return DecisionPoint("low", f"{tier} tier, criticality {criticality or 'unset'}", partial)


def decide(
    *,
    kev: bool,
    exploit_public: bool,
    vector: str | None,
    tier: str | None,
    criticality: int | None,
    malicious: bool = False,
    cisa: dict[str, Any] | None = None,
) -> Decision:
    points = {
        "exploitation": exploitation(kev=kev, exploit_public=exploit_public, cisa=cisa),
        "automatable": automatable(vector, cisa),
        "technical_impact": technical_impact(vector, cisa),
        "mission_wellbeing": mission_wellbeing(tier=tier, criticality=criticality),
    }
    notes: list[str] = []

    if malicious:
        points["exploitation"] = DecisionPoint(
            "active", "the package is published malware: installing it is the attack"
        )
        notes.append("Malicious package: decided as actively exploited.")

    key = (
        points["exploitation"].value,
        points["automatable"].value,
        points["technical_impact"].value,
    )
    outcome = _TABLE[key][_MWB_INDEX[points["mission_wellbeing"].value]]
    if any(p.assumed for p in points.values()):
        notes.append(
            "Some decision points were not established and were taken at their worse "
            "value; the outcome may fall once they are."
        )
    return Decision(outcome=outcome, points=points, notes=notes)
