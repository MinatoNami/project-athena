"""The normalised advisory model every adapter produces."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from athena.intel.authority import Authority


@dataclass(frozen=True)
class NormalisedRange:
    ecosystem: str
    package: str
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    source: str = "osv"
    authority: Authority = Authority.UPSTREAM_ADVISORY
    distro: str | None = None
    distro_release: str | None = None
    # How the fix is delivered. "esm" and "fips" are only installable with an Ubuntu
    # Pro entitlement, so recommending one without saying so is advice the operator
    # may be unable to follow.
    channel: str = "standard"


@dataclass
class NormalisedAdvisory:
    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str | None = None
    details: str | None = None
    cwe: list[str] = field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    withdrawn_at: datetime | None = None
    references: list[dict[str, Any]] = field(default_factory=list)
    ranges: list[NormalisedRange] = field(default_factory=list)
    source: str = "osv"


# Only fields that could change a verdict. A reworded summary must not re-correlate
# the whole estate, but a changed range or severity must.
def content_hash(advisory: NormalisedAdvisory) -> str:
    material = {
        "id": advisory.id,
        "aliases": sorted(advisory.aliases),
        "cvss_vector": advisory.cvss_vector,
        "cvss_score": advisory.cvss_score,
        "severity": advisory.severity,
        "withdrawn": advisory.withdrawn_at.isoformat() if advisory.withdrawn_at else None,
        # Sorted so the hash is order-independent. Bounds are frequently absent, so
        # the key coerces None rather than comparing None against str.
        "ranges": sorted(
            (
                [r.ecosystem, r.package, r.introduced, r.fixed, r.last_affected,
                 r.source, int(r.authority), r.distro, r.distro_release, r.channel]
                for r in advisory.ranges
            ),
            key=lambda row: tuple("" if v is None else str(v) for v in row),
        ),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
