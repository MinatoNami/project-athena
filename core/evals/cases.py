"""Corpus case definitions.

Cases are TOML because `tomllib` is stdlib: the corpus adds no dependency to an
image that runs in production.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CORPUS = Path(__file__).parent / "corpus"

BANDS = ["informational", "low", "medium", "high", "critical"]


def band_rank(band: str | None) -> int:
    return BANDS.index(band) if band in BANDS else -1


@dataclass
class Expectation:
    verdict_in: list[str] = field(default_factory=list)
    band_at_least: str | None = None
    band_at_most: str | None = None
    never_below: str | None = None
    max_confidence: float | None = None
    outranks: list[str] = field(default_factory=list)
    require_uncertainties: bool = False
    no_unregistered_tool_calls: bool = False
    reject_injected_confidence: bool = False
    matches_control: str | None = None
    demands_verdict: str | None = None


@dataclass
class Case:
    id: str
    description: str
    asset: dict[str, Any]
    component: dict[str, Any]
    advisory: dict[str, Any]
    services: list[dict[str, Any]]
    fixed_version: str | None
    expected: Expectation

    @property
    def expects_applicable(self) -> bool:
        """True only when `applicable` is the sole accepted answer.

        A false negative is only meaningful where the case admits no other verdict;
        cases that also accept `uncertain` are not evidence of a miss.
        """
        return self.expected.verdict_in == ["applicable"]


def _expectation(raw: dict[str, Any]) -> Expectation:
    raw = dict(raw)
    # `verdict = "x"` is shorthand for `verdict_in = ["x"]`.
    if (single := raw.pop("verdict", None)) is not None:
        raw["verdict_in"] = [single]
    if unknown := set(raw) - set(Expectation.__dataclass_fields__):
        raise ValueError(f"unknown expectation keys: {sorted(unknown)}")
    for key in ("band_at_least", "band_at_most", "never_below"):
        if raw.get(key) is not None and raw[key] not in BANDS:
            raise ValueError(f"{key}={raw[key]!r} is not one of {BANDS}")
    return Expectation(**raw)


def _all_raw() -> list[dict[str, Any]]:
    return [tomllib.loads(p.read_text()) for p in sorted(CORPUS.glob("*.toml"))]


def load(only: str | None = None) -> list[Case]:
    wanted: set[str] | None = None
    if only:
        # A case that is checked against a control is meaningless without it, so
        # asking for one by name pulls its control in too.
        wanted = {only}
        for raw in _all_raw():
            if raw["id"] == only:
                if control := raw["expected"].get("matches_control"):
                    wanted.add(control)

    cases: list[Case] = []
    for path in sorted(CORPUS.glob("*.toml")):
        raw = tomllib.loads(path.read_text())
        if wanted is not None and raw["id"] not in wanted:
            continue
        cases.append(
            Case(
                id=raw["id"],
                description=" ".join(raw.get("description", "").split()),
                asset=raw["asset"],
                component=raw["component"],
                advisory=raw["advisory"],
                services=raw.get("services", []),
                fixed_version=raw.get("fixed_version"),
                expected=_expectation(raw["expected"]),
            )
        )
    if only and not cases:
        raise SystemExit(f"no case with id {only!r} in {CORPUS}")

    # An `outranks` pointing at a case that does not exist would silently never be
    # checked, which is the failure mode a corpus can least afford.
    known = {r["id"] for r in _all_raw()}
    for case in cases:
        if missing := [t for t in case.expected.outranks if t not in known]:
            raise ValueError(f"{case.id}: outranks unknown case(s) {missing}")
        control = case.expected.matches_control
        if control is not None and control not in known:
            raise ValueError(f"{case.id}: matches_control names unknown case {control!r}")
    return cases
