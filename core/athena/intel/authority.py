"""Which source to believe when they disagree.

This module exists because of backports. Ubuntu ships the fix for a CVE as
`3.0.13-0ubuntu3.12` while upstream's fixed version is `3.0.13` or later — so an
upstream range says "everything below 3.0.13 is vulnerable" and a patched Ubuntu
host matches it. Naive matching then reports a false positive on every Ubuntu host
in the estate, which is the fastest way to make the product untrustworthy.

The rule: for a distribution package, only the distribution's own tracker knows
whether the fix has been backported. Anything else is, at best, informational.
"""

from __future__ import annotations

from enum import IntEnum

# Ecosystems whose packages are built and patched by a distribution, and where
# upstream version numbers therefore do not describe what is installed.
DISTRO_ECOSYSTEMS = {"deb", "rpm", "apk"}


class Authority(IntEnum):
    """Higher wins. Ordering is the whole point, so it is an IntEnum."""

    HEURISTIC = 0            # inferred, no machine-readable range
    VENDOR_BULLETIN = 1      # vendor text without structured versions
    NVD_CPE = 2              # CPE ranges: coarse, and frequently wrong
    UPSTREAM_ADVISORY = 3    # OSV / GHSA for an ecosystem package
    DISTRO_TRACKER = 4       # the distribution's own security tracker


# Source name → the authority its ranges carry.
SOURCE_AUTHORITY: dict[str, Authority] = {
    "ubuntu": Authority.DISTRO_TRACKER,
    "debian": Authority.DISTRO_TRACKER,
    "redhat": Authority.DISTRO_TRACKER,
    "suse": Authority.DISTRO_TRACKER,
    "alpine": Authority.DISTRO_TRACKER,
    "osv": Authority.UPSTREAM_ADVISORY,
    "ghsa": Authority.UPSTREAM_ADVISORY,
    "pysec": Authority.UPSTREAM_ADVISORY,
    "nvd": Authority.NVD_CPE,
    "vendor": Authority.VENDOR_BULLETIN,
}


def authority_for(source: str) -> Authority:
    return SOURCE_AUTHORITY.get(source.lower(), Authority.HEURISTIC)


def is_distro_ecosystem(ecosystem: str) -> bool:
    return ecosystem.lower() in DISTRO_ECOSYSTEMS


def is_authoritative(ecosystem: str, authority: Authority) -> bool:
    """Whether a range from this authority may create a real candidate finding.

    For a distribution package, only the distribution's tracker may. Everything else
    is downgraded to informational rather than dropped — the disagreement is worth
    seeing, it just must not drive a finding.
    """
    if is_distro_ecosystem(ecosystem):
        return authority >= Authority.DISTRO_TRACKER
    return authority >= Authority.NVD_CPE
