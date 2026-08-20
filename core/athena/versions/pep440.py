"""PEP 440 version ordering.

Python's ordering is not lexical and not SemVer: `1.0a1 < 1.0 < 1.0.post1`, and
`1.0.dev1` sorts before every other 1.0. Getting this wrong silently mismatches
advisory ranges, so the ordering key is built explicitly rather than approximated.
"""

from __future__ import annotations

import re
from typing import Any

_VERSION = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))
             |(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

# Normalised pre-release spellings. `c` and `pre` are aliases for `rc`.
_PRE_ALIASES = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}

# Sentinels that order correctly against real segment tuples.
_NEGATIVE_INFINITY = ("!",)   # sorts before any ("#", ...) tuple
_INFINITY = ("~",)            # sorts after


class InvalidVersion(ValueError):
    pass


def parse(version: str) -> dict[str, Any]:
    match = _VERSION.match(version)
    if match is None:
        raise InvalidVersion(f"Not a PEP 440 version: {version!r}")

    pre_l = match.group("pre_l")
    if pre_l:
        pre_l = _PRE_ALIASES.get(pre_l.lower(), pre_l.lower())
        pre = (pre_l, int(match.group("pre_n") or 0))
    else:
        pre = None

    if match.group("post_n1") is not None:
        post = ("post", int(match.group("post_n1")))
    elif match.group("post_l") is not None:
        post = ("post", int(match.group("post_n2") or 0))
    else:
        post = None

    dev = ("dev", int(match.group("dev_n") or 0)) if match.group("dev") else None

    return {
        "epoch": int(match.group("epoch") or 0),
        "release": tuple(int(p) for p in match.group("release").split(".")),
        "pre": pre,
        "post": post,
        "dev": dev,
        "local": match.group("local"),
    }


def sort_key(version: str) -> tuple:
    """A tuple that orders the same way PEP 440 says versions order."""
    parsed = parse(version)

    # Trailing zeros are not significant: 1.0 == 1.0.0.
    release = tuple(reversed(list(_drop_trailing_zeros(reversed(parsed["release"])))))

    pre = parsed["pre"]
    if pre is None:
        # No pre-release. A dev release with no pre still sorts before the final
        # release; otherwise the final release sorts after all its pre-releases.
        is_bare_dev = parsed["post"] is None and parsed["dev"] is not None
        pre = _NEGATIVE_INFINITY if is_bare_dev else _INFINITY

    post = parsed["post"] or _NEGATIVE_INFINITY
    dev = parsed["dev"] or _INFINITY   # absence of .devN sorts AFTER any .devN

    if parsed["local"] is None:
        local: tuple = _NEGATIVE_INFINITY
    else:
        # Numeric segments compare numerically and above alphabetic ones.
        local = tuple(
            (int(part), "") if part.isdigit() else (-1, part)
            for part in re.split(r"[._-]", parsed["local"])
        )

    return (parsed["epoch"], release, pre, post, dev, local)


def _drop_trailing_zeros(reversed_release):
    seen_nonzero = False
    for part in reversed_release:
        if part != 0:
            seen_nonzero = True
        if seen_nonzero:
            yield part


def compare(a: str, b: str) -> int:
    ka, kb = sort_key(a), sort_key(b)
    return (ka > kb) - (ka < kb)
