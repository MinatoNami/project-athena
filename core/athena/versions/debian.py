"""Debian/Ubuntu version ordering, per deb-version(7).

The algorithm is unusual and worth stating precisely, because a naive
implementation gets the common cases right and the security-relevant cases wrong:

  * `~` sorts *before* everything, including the empty string, so
    `1.0~rc1 < 1.0`. Distributions use this constantly for pre-releases.
  * Letters sort before non-letters, so `1.0a < 1.0+`.
  * Digit runs compare numerically, so `1.10 > 1.9`.
  * An absent epoch means 0, so `1:1.0 > 2.0`.

Ubuntu security updates are almost always a revision bump (`3.0.13-0ubuntu3.12`),
so revision comparison is not a detail — it is how "is this host patched?" is
answered.
"""

from __future__ import annotations

import re

_VERSION = re.compile(
    r"^(?:(?P<epoch>\d+):)?(?P<upstream>[^:-]*?)(?:-(?P<revision>[^:-]+))?$"
)


class InvalidVersion(ValueError):
    pass


def _order(char: str) -> int:
    """Character rank in dpkg's collation.

    `~` is below the end of string; letters are next; everything else follows,
    offset so it can never collide with a letter's rank.
    """
    if char == "~":
        return -1
    if char.isdigit():
        return 0          # digits are handled by the numeric pass, never here
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_fragment(a: str, b: str) -> int:
    """Compare one upstream or revision fragment."""
    i = j = 0
    while i < len(a) or j < len(b):
        # Non-digit run, compared by dpkg collation.
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                first_diff = ac - bc
                break
            i += 1 if i < len(a) and not a[i].isdigit() else 0
            j += 1 if j < len(b) and not b[j].isdigit() else 0
        if first_diff:
            return 1 if first_diff > 0 else -1

        # Digit run, compared numerically. Leading zeros are insignificant.
        start_a, start_b = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        num_a = int(a[start_a:i] or "0")
        num_b = int(b[start_b:j] or "0")
        if num_a != num_b:
            return 1 if num_a > num_b else -1

        if start_a == i and start_b == j:
            break   # neither side advanced; the strings are equal here
    return 0


def parse(version: str) -> tuple[int, str, str]:
    match = _VERSION.match(version.strip())
    if match is None:
        raise InvalidVersion(f"Not a Debian version: {version!r}")
    return (
        int(match.group("epoch") or 0),
        match.group("upstream") or "",
        match.group("revision") or "",
    )


def compare(a: str, b: str) -> int:
    epoch_a, upstream_a, revision_a = parse(a)
    epoch_b, upstream_b, revision_b = parse(b)

    if epoch_a != epoch_b:
        return 1 if epoch_a > epoch_b else -1
    if (result := _compare_fragment(upstream_a, upstream_b)) != 0:
        return result
    return _compare_fragment(revision_a, revision_b)
