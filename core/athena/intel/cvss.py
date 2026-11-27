from __future__ import annotations

import math
from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_V3_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_V4_REQUIRED = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


class VectorError(ValueError):
    pass


@dataclass(frozen=True)
class Vector:
    version: str
    metrics: dict[str, str]

    def get(self, key: str) -> str | None:
        return self.metrics.get(key)


def parse(vector: str | None) -> Vector:
    if not vector or not isinstance(vector, str):
        raise VectorError("empty vector")
    parts = vector.strip().split("/")
    head = parts[0]
    if not head.startswith("CVSS:"):
        raise VectorError(f"not a CVSS vector: {vector[:40]!r}")
    version = head[5:]
    if version not in ("3.0", "3.1", "4.0"):
        raise VectorError(f"unsupported CVSS version {version!r}")

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or not key or not value:
            raise VectorError(f"malformed metric {part!r}")
        if key in metrics:
            raise VectorError(f"metric {key} repeated")
        metrics[key] = value

    required = _V4_REQUIRED if version == "4.0" else _V3_REQUIRED
    missing = [k for k in required if k not in metrics]
    if missing:
        raise VectorError(f"missing base metrics: {', '.join(missing)}")
    return Vector(version=version, metrics=metrics)


def _roundup_31(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def _roundup_30(value: float) -> float:
    return math.ceil(value * 10) / 10


def base_score(vector: str | None) -> float | None:
    try:
        parsed = parse(vector)
    except VectorError:
        return None
    if parsed.version == "4.0":
        return None

    m = parsed.metrics
    try:
        changed = m["S"] == "C"
        if m["S"] not in ("U", "C"):
            return None
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    roundup = _roundup_31 if parsed.version == "3.1" else _roundup_30
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity_of(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def choose(vectors: list[str]) -> str | None:
    ranked: list[tuple[int, str]] = []
    for v in vectors:
        if not isinstance(v, str):
            continue
        if v.startswith("CVSS:3.1/"):
            ranked.append((0, v))
        elif v.startswith("CVSS:3.0/"):
            ranked.append((1, v))
        elif v.startswith("CVSS:4.0/"):
            ranked.append((2, v))
    return min(ranked)[1] if ranked else None
