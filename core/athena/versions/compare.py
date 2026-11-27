from __future__ import annotations

from collections.abc import Callable

from athena.versions import apk, debian, maven, pep440, rpm, semver

Comparator = Callable[[str, str], int]


class UnknownEcosystem(ValueError):
    pass


class UncomparableVersions(ValueError):
    pass


def _generic(a: str, b: str) -> int:
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
    "maven": maven.compare,
    "deb": debian.compare,
    "rpm": rpm.compare,
    "apk": apk.compare,
    "generic": _generic,
}

HEURISTIC_ECOSYSTEMS = {"generic", "maven", "apk"}


def comparator_for(ecosystem: str) -> Comparator:
    try:
        return COMPARATORS[ecosystem.lower()]
    except KeyError:
        raise UnknownEcosystem(f"No comparator for ecosystem {ecosystem!r}") from None


def compare(ecosystem: str, a: str, b: str) -> int:
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
    if introduced and introduced != "0" and compare(ecosystem, version, introduced) < 0:
        return False
    if fixed is not None and compare(ecosystem, version, fixed) >= 0:
        return False
    if last_affected is not None and compare(ecosystem, version, last_affected) > 0:
        return False
    return True
