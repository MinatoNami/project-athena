"""RPM EVR ordering (rpmvercmp).

Close to Debian's but not the same: `~` sorts low as in Debian, `^` sorts high,
and alphabetic and numeric segments never compare equal across types.
"""

from __future__ import annotations

import re

_SEGMENT = re.compile(r"([a-zA-Z]+|[0-9]+|~|\^)")


class InvalidVersion(ValueError):
    pass


def _segments(value: str) -> list[str]:
    return _SEGMENT.findall(value or "")


def _compare_fragment(a: str, b: str) -> int:
    sa, sb = _segments(a), _segments(b)
    # Deliberately non-strict: the shorter side running out is meaningful,
    # and the length difference is resolved below.
    for x, y in zip(sa, sb, strict=False):
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x == "^" or y == "^":
            if x != y:
                return 1 if x == "^" else -1
            continue

        x_num, y_num = x.isdigit(), y.isdigit()
        if x_num != y_num:
            return 1 if x_num else -1        # numeric outranks alphabetic
        if x_num:
            if int(x) != int(y):
                return 1 if int(x) > int(y) else -1
        elif x != y:
            return 1 if x > y else -1

    if len(sa) == len(sb):
        return 0
    # A trailing ~ makes the longer side *lower*, everywhere else it is higher.
    longer, sign = (sa, 1) if len(sa) > len(sb) else (sb, -1)
    return -sign if longer[len(min(sa, sb, key=len))] == "~" else sign


def parse(version: str) -> tuple[int, str, str]:
    epoch, _, rest = version.partition(":")
    if not _:
        epoch, rest = "0", version
    release_split = rest.rsplit("-", 1)
    if len(release_split) == 2:
        return int(epoch or 0), release_split[0], release_split[1]
    return int(epoch or 0), rest, ""


def compare(a: str, b: str) -> int:
    try:
        epoch_a, version_a, release_a = parse(a)
        epoch_b, version_b, release_b = parse(b)
    except ValueError as exc:
        raise InvalidVersion(f"Not an RPM version: {a!r} or {b!r}") from exc

    if epoch_a != epoch_b:
        return 1 if epoch_a > epoch_b else -1
    if (result := _compare_fragment(version_a, version_b)) != 0:
        return result
    return _compare_fragment(release_a, release_b)
