"""OSV adapter.

OSV aggregates ecosystem advisories in one schema and, importantly, also carries
the distribution trackers (Ubuntu USN, Debian, Alpine) — so a single source gives
both the upstream range and the distro's backport-aware range for the same CVE.
That is exactly what the authority rule needs to work.
"""

from __future__ import annotations

import re
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


_RELEASE = re.compile(r"^\d+(\.\d+)*$")

# Ubuntu delivers some fixes only through Ubuntu Pro. The ecosystem string carries
# the channel ("Ubuntu:Pro:18.04:LTS") and the version usually does too (~esm1,
# fips). Either signal is enough.
_CHANNEL_MARKERS = {"pro": "esm", "esm": "esm", "fips": "fips", "fips-updates": "fips"}
_VERSION_MARKERS = (("~esm", "esm"), ("+esm", "esm"), ("fips", "fips"))


def _channel(raw_ecosystem: str, fixed: str | None) -> str:
    for part in raw_ecosystem.split(":")[1:]:
        if (channel := _CHANNEL_MARKERS.get(part.strip().lower())) is not None:
            return channel
    lowered = (fixed or "").lower()
    for marker, channel in _VERSION_MARKERS:
        if marker in lowered:
            return channel
    return "standard"


def _split_ecosystem(raw: str) -> tuple[str | None, str | None, str | None]:
    """"Ubuntu:24.04:LTS" → (deb, ubuntu, 24.04).

    The release is not always the second segment: Ubuntu ESM advisories arrive as
    "Ubuntu:Pro:18.04:LTS", which naively yields a release of "Pro" and then matches
    no host at all. The first version-shaped segment is taken instead.
    """
    parts = [p.strip() for p in raw.split(":")]
    base = parts[0].lower()
    release = next((p for p in parts[1:] if _RELEASE.match(p)), None)
    return ECOSYSTEM_MAP.get(base), DISTRO_OF.get(base), release


QUALITATIVE = {"negligible", "low", "medium", "moderate", "high", "critical"}

# Distro severity words map onto Athena's bands. "moderate" is SUSE/Red Hat's word
# for medium; treating it as unknown would leave most distro advisories unlabelled.
SEVERITY_ALIASES = {"moderate": "medium", "negligible": "low", "important": "high"}


def _severity(advisory: dict[str, Any]) -> tuple[str | None, str | None]:
    """(CVSS vector, qualitative label).

    Ecosystem advisories carry a CVSS vector; distribution trackers usually carry a
    single word instead ({"type": "Ubuntu", "score": "medium"}). Reading only the
    vector left every Ubuntu finding with no severity at all, which is unusable for
    triage even before real risk scoring exists.
    """
    vector = label = None
    for entry in advisory.get("severity") or []:
        score = (entry.get("score") or "").strip()
        if not score:
            continue
        if entry.get("type", "").upper().startswith("CVSS_V"):
            vector = vector or score
        elif score.lower() in QUALITATIVE:
            label = label or SEVERITY_ALIASES.get(score.lower(), score.lower())

    if label is None:
        db_specific = (advisory.get("database_specific") or {}).get("severity")
        if isinstance(db_specific, str) and db_specific.lower() in QUALITATIVE:
            label = SEVERITY_ALIASES.get(db_specific.lower(), db_specific.lower())
    return vector, label


def parse(advisory: dict[str, Any]) -> NormalisedAdvisory | None:
    """Translate one OSV record. Returns None if it carries nothing usable."""
    osv_id = advisory.get("id")
    if not osv_id:
        return None

    # Distribution records put the CVE in `upstream` rather than `aliases`
    # (UBUNTU-CVE-2014-3613 upstream ["CVE-2014-3613"]), so all three are considered.
    # Converging on the CVE is what lets an upstream advisory and a distro tracker
    # for the same flaw merge into one row with both sets of ranges — which is
    # exactly what the authority rule needs to compare them.
    aliases = [
        a
        for a in (
            (advisory.get("aliases") or [])
            + (advisory.get("upstream") or [])
            + (advisory.get("related") or [])
        )
        if a
    ]
    canonical = next((a for a in aliases if a.upper().startswith("CVE-")), osv_id)
    if canonical != osv_id:
        aliases = [a for a in aliases if a != canonical] + [osv_id]

    vector, label = _severity(advisory)
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
                    channel=_channel(raw_ecosystem, fixed),
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
                        channel=_channel(raw_ecosystem, None),
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
        severity=label,
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
