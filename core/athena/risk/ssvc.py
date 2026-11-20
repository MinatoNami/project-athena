"""SSVC: CISA's Stakeholder-Specific Vulnerability Categorization.

A second opinion beside the risk score, not a replacement for it. The score ranks;
SSVC names what to *do* — Track, Track*, Attend, Act — and it is the vocabulary
CISA's own directives now speak, so a finding that says "Act" can be argued about
with people who have never seen Athena's arithmetic.

Like the score, it is a pure function of stored facts, and every decision point
states the fact it was read from. Where Athena does not hold the fact, the point is
taken at its worse value and listed in `assumed`: SSVC's guidance is to resolve
doubt conservatively, and a decision that silently took the comfortable branch would
be the "unknown rendered as clean" this product exists to refuse.

Decision points and the outcome table follow CISA's coordinator tree (SSVC 2.0.3).
Where CISA has published its own assessment for the CVE (the Vulnrichment ADP
container), its Exploitation, Automatable and Technical Impact values are used and
cited. Otherwise Exploitation reads the known-exploited catalogue and public-exploit
evidence, and Automatable and Technical Impact are mapped from the CVSS vector — a
mapping, labelled as such. Mission & Well-being reads the asset's tier and
criticality, which only the operator can set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from athena.intel import cvss

TRACK = "track"
TRACK_STAR = "track*"
ATTEND = "attend"
ACT = "act"

OUTCOME_ORDER = [TRACK, TRACK_STAR, ATTEND, ACT]

# What CISA says each outcome means, for the page.
OUTCOME_MEANING = {
    TRACK: "No action needed now; remediate within standard update timelines.",
    TRACK_STAR: (
        "Contains characteristics that warrant closer monitoring; remediate within "
        "standard update timelines."
    ),
    ATTEND: ("Needs attention from leadership; remediate sooner than standard update timelines."),
    ACT: ("Needs attention from leadership and action as soon as possible; remediate immediately."),
}

# (exploitation, automatable, technical_impact) → outcome for low / medium / high
# mission & well-being. CERTCC/SSVC data/csv/cisa/cisa_coordinator_2_0_3.csv.
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
    """One of CISA's Vulnrichment values, normalised, or None if it has none.

    The SSVC reference data spells the middle exploitation value "public poc" while
    Vulnrichment writes "poc"; both mean the same thing.
    """
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
    """active | poc | none.

    EPSS is deliberately not read here. It is a probability of future exploitation,
    and SSVC's Exploitation point asks what is already *known* — mixing the two would
    let a forecast stand in for a fact. The risk score reads EPSS; this does not.

    KEV outranks CISA's own SSVC entry: the ADP assessment is written once and is
    not always revisited, and CVEs exist that are in the catalogue while their
    Vulnrichment record still says "none".
    """
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
    """Can steps 1–4 of the kill chain be automated? Mapped from the CVSS vector.

    Network-reachable, low complexity, no privileges and no user interaction is the
    shape of a flaw a worm can use. Anything less needs a person somewhere in the
    loop. With no readable vector the answer is unknown and taken as `yes`. CISA's
    own assessment, where one exists, replaces the mapping entirely.
    """
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
    """partial | total — does success give total control or total disclosure?

    Read as high confidentiality *and* high integrity impact on the vulnerable
    system. With no readable vector it is unknown and taken as `total`.
    """
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
    """low | medium | high, from what the operator has said about the asset.

    An unclassified asset is `medium` and marked assumed — the same stance the risk
    function takes: not knowing what something is does not make it unimportant, and
    defaulting low would quietly discount everything nobody has classified.
    """
    tier = (tier or "unknown").lower()
    if criticality == 5 or (tier == "production" and (criticality or 3) >= 4):
        return DecisionPoint("high", f"{tier} tier, criticality {criticality}")
    if tier == "unknown" and criticality is None:
        return DecisionPoint("medium", "the asset has no tier or criticality; assumed medium", True)
    if tier in ("production", "staging", "unknown") or (criticality or 0) >= 3:
        detail = f"criticality {criticality}" if criticality else "criticality unset"
        return DecisionPoint("medium", f"{tier} tier, {detail}")
    return DecisionPoint("low", f"{tier} tier, criticality {criticality or 'unset'}")


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
    """The SSVC outcome for one finding on one asset."""
    points = {
        "exploitation": exploitation(kev=kev, exploit_public=exploit_public, cisa=cisa),
        "automatable": automatable(vector, cisa),
        "technical_impact": technical_impact(vector, cisa),
        "mission_wellbeing": mission_wellbeing(tier=tier, criticality=criticality),
    }
    notes: list[str] = []

    if malicious:
        # SSVC is a model for flaws. A malicious package is a compromise already in
        # progress, so its "exploitation" is active by construction.
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
