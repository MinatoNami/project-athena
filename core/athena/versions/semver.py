"""SemVer ordering, as npm and Go modules use it.

Build metadata is ignored for ordering (SemVer §10), and a pre-release sorts
before its release: `1.0.0-rc.1 < 1.0.0`.
"""

from __future__ import annotations

import re

_VERSION = re.compile(
    r"^\s*v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))?\s*$"
)


class InvalidVersion(ValueError):
    pass


def parse(version: str) -> tuple[int, int, int, tuple | None]:
    match = _VERSION.match(version)
    if match is None:
        raise InvalidVersion(f"Not a SemVer version: {version!r}")
    pre = tuple(match.group("pre").split(".")) if match.group("pre") else None
    return (
        int(match.group("major")),
        int(match.group("minor") or 0),
        int(match.group("patch") or 0),
        pre,
    )


def _compare_prerelease(a: tuple | None, b: tuple | None) -> int:
    # Absent pre-release outranks any pre-release.
    if a is None and b is None:
        return 0
    if a is None:
        return 1
    if b is None:
        return -1

    # Non-strict on purpose: a longer pre-release chain outranks its prefix,
    # which is decided after the common segments compare equal.
    for x, y in zip(a, b, strict=False):
        x_num, y_num = x.isdigit(), y.isdigit()
        if x_num and y_num:
            if int(x) != int(y):
                return 1 if int(x) > int(y) else -1
        elif x_num != y_num:
            return -1 if x_num else 1   # numeric identifiers rank below alphanumeric
        elif x != y:
            return 1 if x > y else -1
    # A longer pre-release chain outranks its prefix: 1.0.0-a.1 > 1.0.0-a
    return (len(a) > len(b)) - (len(a) < len(b))


def compare(a: str, b: str) -> int:
    major_a, minor_a, patch_a, pre_a = parse(a)
    major_b, minor_b, patch_b, pre_b = parse(b)
    if (major_a, minor_a, patch_a) != (major_b, minor_b, patch_b):
        return 1 if (major_a, minor_a, patch_a) > (major_b, minor_b, patch_b) else -1
    return _compare_prerelease(pre_a, pre_b)
