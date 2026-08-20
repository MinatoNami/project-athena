"""OSV adapter.

OSV aggregates ecosystem advisories in one schema and, importantly, also carries
the distribution trackers (Ubuntu USN, Debian, Alpine) — so a single source gives
both the upstream range and the distro's backport-aware range for the same CVE.
That is exactly what the authority rule needs to work.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from athena.intel.authority import authority_for
from athena.intel.model import NormalisedAdvisory, NormalisedRange

log = structlog.get_logger(__name__)

# OSV ecosystem names → Athena ecosystems. Distro ecosystems carry a release
# suffix ("Ubuntu:24.04"), which is split out rather than discarded: a fix in
# 22.04 says nothing about 24.04.
ECOSYSTEM_MAP = {
    "pypi": "pypi", "npm": "npm", "go": "golang", "crates.io": "cargo",
    "maven": "maven", "nuget": "nuget", "rubygems": "gem", "packagist": "composer",
    "hex": "hex", "pub": "pub", "debian": "deb", "ubuntu": "deb",
    "alpine": "apk", "red hat": "rpm", "rocky linux": "rpm", "almalinux": "rpm",
    "suse": "rpm", "opensuse": "rpm", "mageia": "rpm", "photon os": "rpm",
    "chainguard": "apk", "wolfi": "apk",
}

# OSV ecosystem prefix → the distribution it belongs to, for authority resolution.
DISTRO_OF = {
    "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine",
    "red hat": "redhat", "suse": "suse", "opensuse": "suse",
    "rocky linux": "rocky", "almalinux": "alma",
}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _split_ecosystem(raw: str) -> tuple[str | None, str | None, str | None]:
    """"Ubuntu:24.04:LTS" → (deb, ubuntu, 24.04)."""
    parts = raw.split(":")
    base = parts[0].strip().lower()
    release = parts[1].strip() if len(parts) > 1 else None
    return ECOSYSTEM_MAP.get(base), DISTRO_OF.get(base), release


def _severity(advisory: dict[str, Any]) -> tuple[str | None, float | None]:
    """Prefer a CVSS v3/v4 vector; fall back to the database_specific label."""
    for entry in advisory.get("severity") or []:
        if entry.get("type", "").upper().startswith("CVSS_V") and entry.get("score"):
            return entry["score"], None
    return None, None


def parse(advisory: dict[str, Any]) -> NormalisedAdvisory | None:
    """Translate one OSV record. Returns None if it carries nothing usable."""
    osv_id = advisory.get("id")
    if not osv_id:
        return None

    aliases = [a for a in advisory.get("aliases") or [] if a]
    # Prefer the CVE as the canonical id so every source converges on one row.
    canonical = next((a for a in aliases if a.upper().startswith("CVE-")), osv_id)
    if canonical != osv_id:
        aliases = [a for a in aliases if a != canonical] + [osv_id]

    vector, _ = _severity(advisory)
    ranges: list[NormalisedRange] = []

    for affected in advisory.get("affected") or []:
        package = affected.get("package") or {}
        raw_ecosystem = package.get("ecosystem") or ""
        name = package.get("name")
        if not name:
            continue

        ecosystem, distro, release = _split_ecosystem(raw_ecosystem)
        if ecosystem is None:
            continue

        source = distro or ("ghsa" if osv_id.startswith("GHSA-") else "osv")
        authority = authority_for(source)

        for entry in affected.get("ranges") or []:
            if entry.get("type") == "GIT":
                continue    # commit ranges cannot be compared against a package version
            introduced = fixed = last_affected = None
            for event in entry.get("events") or []:
                introduced = event.get("introduced", introduced)
                fixed = event.get("fixed", fixed)
                last_affected = event.get("last_affected", last_affected)
            if introduced is None and fixed is None and last_affected is None:
                continue
            ranges.append(
                NormalisedRange(
                    ecosystem=ecosystem, package=name,
                    introduced=introduced, fixed=fixed, last_affected=last_affected,
                    source=source, authority=authority,
                    distro=distro, distro_release=release,
                )
            )

        # Some records list explicit versions instead of ranges.
        if not (affected.get("ranges") or []):
            for version in affected.get("versions") or []:
                ranges.append(
                    NormalisedRange(
                        ecosystem=ecosystem, package=name,
                        introduced=version, last_affected=version,
                        source=source, authority=authority,
                        distro=distro, distro_release=release,
                    )
                )

    if not ranges:
        # An advisory with no comparable range cannot produce a finding. Recorded
        # by the caller as a skip rather than silently dropped.
        return None

    return NormalisedAdvisory(
        id=canonical,
        aliases=sorted(set(aliases)),
        summary=advisory.get("summary"),
        details=(advisory.get("details") or "")[:20000] or None,
        cwe=[
            c for c in (advisory.get("database_specific") or {}).get("cwe_ids") or [] if c
        ],
        cvss_vector=vector,
        severity=(advisory.get("database_specific") or {}).get("severity"),
        published_at=_parse_time(advisory.get("published")),
        modified_at=_parse_time(advisory.get("modified")),
        withdrawn_at=_parse_time(advisory.get("withdrawn")),
        references=[
            {"type": r.get("type"), "url": r.get("url")}
            for r in advisory.get("references") or []
            if r.get("url")
        ][:50],
        ranges=ranges,
        source="osv",
    )


def parse_many(records: list[dict[str, Any]]) -> tuple[list[NormalisedAdvisory], int]:
    """Returns (advisories, skipped). Skips are reported, never hidden."""
    advisories, skipped = [], 0
    for record in records:
        parsed = parse(record)
        if parsed is None:
            skipped += 1
            continue
        advisories.append(parsed)
    return advisories, skipped
