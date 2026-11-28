from __future__ import annotations

from enum import IntEnum

DISTRO_ECOSYSTEMS = {"deb", "rpm", "apk"}


class Authority(IntEnum):
    HEURISTIC = 0
    VENDOR_BULLETIN = 1
    NVD_CPE = 2
    UPSTREAM_ADVISORY = 3
    DISTRO_TRACKER = 4


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
    if is_distro_ecosystem(ecosystem):
        return authority >= Authority.DISTRO_TRACKER
    return authority >= Authority.NVD_CPE
