"""Ecosystem-aware version comparison and range evaluation.

Correlation asks one question of every candidate: *is the installed version inside
the advisory's affected range?* Answering it needs the ecosystem's own ordering —
string comparison gets `1.10 > 1.9` wrong, and every downstream conclusion inherits
the error.
"""

from __future__ import annotations

from collections.abc import Callable

from athena.versions import debian, pep440, rpm, semver

Comparator = Callable[[str, str], int]


class UnknownEcosystem(ValueError):
    pass


class UncomparableVersions(ValueError):
    """Raised when a version cannot be parsed by its ecosystem's rules.

    Deliberately not swallowed: a comparison Athena cannot make must surface as
    uncertainty, never as a quiet "not affected".
    """


def _generic(a: str, b: str) -> int:
    """Last-resort comparison for ecosystems with no defined ordering.

    Splits on separators and compares numeric runs numerically, which is right more
    often than lexical comparison. Callers must record low confidence when this is
    used — it is a heuristic, not an ordering.
    """
    import re

    def key(value: str):
        return [
            (0, int(part)) if part.isdigit() else (1, part)
            for part in re.split(r"[._\-+~]", value.strip().lstrip("vV"))
            if part
        ]

    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


COMPARATORS: dict[str, Comparator] = {
    "pypi": pep440.compare,
    "npm": semver.compare,
    "golang": semver.compare,
    "cargo": semver.compare,
    "hex": semver.compare,
    "pub": semver.compare,
    "composer": semver.compare,
    "nuget": semver.compare,
    "gem": semver.compare,
    "maven": _generic,      # Maven ordering has its own qualifier ranking; M7
    "deb": debian.compare,
    "rpm": rpm.compare,
    "apk": debian.compare,  # apk ordering is close enough to dpkg for suffixes
    "generic": _generic,
}

# Ecosystems whose comparator is a heuristic rather than the ecosystem's own rules.
# Correlation caps match confidence for these.
HEURISTIC_ECOSYSTEMS = {"generic", "maven", "apk"}


def comparator_for(ecosystem: str) -> Comparator:
    try:
        return COMPARATORS[ecosystem.lower()]
    except KeyError:
        raise UnknownEcosystem(f"No comparator for ecosystem {ecosystem!r}") from None


def compare(ecosystem: str, a: str, b: str) -> int:
    """-1 if a < b, 0 if equal, 1 if a > b."""
    try:
        return comparator_for(ecosystem)(a, b)
    except UnknownEcosystem:
        raise
    except Exception as exc:
        raise UncomparableVersions(
            f"Cannot compare {a!r} and {b!r} as {ecosystem}: {exc}"
        ) from exc


def in_affected_range(
    ecosystem: str,
    version: str,
    *,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
) -> bool:
    """Whether `version` falls in [introduced, fixed) or [introduced, last_affected].

    OSV models ranges as events rather than expressions, which is what this mirrors:
    `fixed` is exclusive (the fix is not vulnerable), `last_affected` is inclusive.

    An unparseable version raises rather than returning False. "We could not tell"
    and "not affected" are different answers, and collapsing them would silently
    under-report.
    """
    if introduced and introduced != "0" and compare(ecosystem, version, introduced) < 0:
        return False
    if fixed is not None and compare(ecosystem, version, fixed) >= 0:
        return False
    if last_affected is not None and compare(ecosystem, version, last_affected) > 0:
        return False
    # A range with no upper bound at all affects everything from `introduced` on.
    return True
