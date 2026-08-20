"""Correlation: which installed components fall inside which advisory ranges.

Correlation produces *candidates*, never confirmations. A version match means the
package looks affected on paper; whether it is actually exploitable here is
investigation's job (M3). Nothing in this module may set a finding to `confirmed`.

The hard part is not the matching, it is the backports. See
athena/intel/authority.py.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from athena.db.models import (
    AffectedRange,
    Asset,
    AssetComponent,
    Component,
    Evidence,
    Finding,
    Vulnerability,
)
from athena.intel.authority import Authority, is_authoritative, is_distro_ecosystem
from athena.inventory.purl import normalise_name
from athena.versions import in_affected_range
from athena.versions.compare import (
    HEURISTIC_ECOSYSTEMS,
    UncomparableVersions,
    UnknownEcosystem,
)

log = structlog.get_logger(__name__)


# How much to trust a match, by how it was made. Investigation can raise a
# finding's overall confidence with evidence; it cannot raise this.
MATCH_CONFIDENCE: dict[str, float] = {
    "distro_advisory": 0.95,    # the distribution's own tracker for its own package
    "purl_exact_range": 0.95,   # ecosystem advisory, exact package, real comparator
    "cpe_range": 0.70,          # CPE is coarse and frequently over-broad
    "heuristic_range": 0.40,    # comparator is a heuristic for this ecosystem
    "uncomparable": 0.20,       # we could not order the versions
}


@dataclass
class CandidateFinding:
    vulnerability_id: str
    asset_id: uuid.UUID
    component_id: uuid.UUID
    match_method: str
    match_confidence: float
    matched_range_id: int | None
    fixed_version: str | None
    advisory_revision: int
    rationale: str
    # Ranges that pointed the other way, or that were outranked. Recorded so a
    # disagreement between sources is visible rather than silently resolved.
    conflicts: list[dict[str, Any]]


def _method_for(ecosystem: str, authority: Authority) -> str:
    if is_distro_ecosystem(ecosystem):
        return "distro_advisory"
    if authority == Authority.NVD_CPE:
        return "cpe_range"
    if ecosystem.lower() in HEURISTIC_ECOSYSTEMS:
        return "heuristic_range"
    return "purl_exact_range"


def _applies_to_release(r: AffectedRange, distro_release: str | None) -> bool:
    """Whether a distro range describes the release actually installed.

    OSV returns ranges for every supported release of a distribution under the same
    package. Ubuntu 22.04 fixed openssl in 3.0.2-0ubuntu1.12 while 24.04 fixed it in
    3.0.13-0ubuntu3.12; comparing a 24.04 host against the 22.04 range makes a
    vulnerable host look patched, because 3.0.13 sorts above 3.0.2.

    A range with no release attached applies everywhere. A host whose release is
    unknown is not matched against release-specific ranges at all — an unknown
    release is a coverage gap, not a licence to guess.
    """
    if r.distro_release is None:
        return True
    if distro_release is None:
        return False
    return r.distro_release.split(":")[0] == distro_release


def evaluate(
    *,
    ecosystem: str,
    package: str,
    version: str,
    ranges: list[AffectedRange],
    distro_release: str | None = None,
) -> tuple[bool, str, float, AffectedRange | None, str, list[dict[str, Any]]]:
    """Decide whether one component is affected, given every range for it.

    Returns (affected, method, confidence, matched_range, rationale, conflicts).

    Only ranges from an authoritative source for this ecosystem can make a
    component affected. For a distribution package that means the distribution's
    own tracker: an upstream range cannot tell whether the fix was backported, and
    trusting it produces a false positive on every patched host.
    """
    normalised = normalise_name(ecosystem, package)
    conflicts: list[dict[str, Any]] = []

    if is_distro_ecosystem(ecosystem):
        wrong_release = [r for r in ranges if not _applies_to_release(r, distro_release)]
        if wrong_release and distro_release is None:
            conflicts.append(
                {
                    "source": "release",
                    "says": "unknown",
                    "note": (
                        "the asset's distribution release is unknown, so "
                        f"{len(wrong_release)} release-specific range(s) could not be "
                        "applied"
                    ),
                }
            )
        ranges = [r for r in ranges if _applies_to_release(r, distro_release)]

    authoritative = [r for r in ranges if is_authoritative(ecosystem, Authority(r.authority))]
    advisory_only = [r for r in ranges if r not in authoritative]

    # Record what the non-authoritative sources said, whichever way it went.
    for r in advisory_only:
        try:
            said_affected = in_affected_range(
                ecosystem, version,
                introduced=r.introduced, fixed=r.fixed, last_affected=r.last_affected,
            )
        except (UncomparableVersions, UnknownEcosystem):
            continue
        if said_affected:
            conflicts.append(
                {
                    "source": r.source,
                    "authority": int(r.authority),
                    "says": "affected",
                    "fixed": r.fixed,
                    "note": (
                        "upstream range; cannot account for distribution backports"
                        if is_distro_ecosystem(ecosystem)
                        else "lower-authority source"
                    ),
                }
            )

    if not authoritative:
        rationale = (
            f"No authoritative range for {normalised} in {ecosystem}. "
            + (
                "Only the distribution's security tracker can say whether the fix "
                "was backported, so an upstream range is recorded as a conflict "
                "rather than a match."
                if is_distro_ecosystem(ecosystem) and conflicts
                else "No source with sufficient authority supplied a comparable range."
            )
        )
        return False, "none", 0.0, None, rationale, conflicts

    uncomparable = False
    for r in authoritative:
        try:
            affected = in_affected_range(
                ecosystem, version,
                introduced=r.introduced, fixed=r.fixed, last_affected=r.last_affected,
            )
        except (UncomparableVersions, UnknownEcosystem) as exc:
            uncomparable = True
            conflicts.append({"source": r.source, "says": "uncomparable", "error": str(exc)})
            continue

        if affected:
            method = _method_for(ecosystem, Authority(r.authority))
            rationale = (
                f"{normalised} {version} is inside the affected range from {r.source} "
                f"(introduced {r.introduced or '0'}"
                + (f", fixed {r.fixed}" if r.fixed else "")
                + (f", last affected {r.last_affected}" if r.last_affected else "")
                + ")"
            )
            return True, method, MATCH_CONFIDENCE[method], r, rationale, conflicts

    if uncomparable:
        return (
            False, "uncomparable", MATCH_CONFIDENCE["uncomparable"], None,
            f"Could not order {version} against the advisory range for {normalised}. "
            "Recorded as uncertain rather than unaffected.",
            conflicts,
        )

    fixed_versions = sorted({r.fixed for r in authoritative if r.fixed})
    rationale = (
        f"{normalised} {version} is outside every authoritative affected range"
        + (f" (fixed in {', '.join(fixed_versions)})" if fixed_versions else "")
    )
    return False, "none", 0.0, None, rationale, conflicts


def _ranges_for(session: Session, ecosystem: str, package: str) -> dict[str, list[AffectedRange]]:
    """Every range touching this package, grouped by vulnerability."""
    rows = session.execute(
        select(AffectedRange).where(
            AffectedRange.ecosystem == ecosystem,
            AffectedRange.package == package,
        )
    ).scalars().all()

    grouped: dict[str, list[AffectedRange]] = {}
    for row in rows:
        grouped.setdefault(row.vulnerability_id, []).append(row)
    return grouped


def _record(
    session: Session, candidate: CandidateFinding, *, vulnerability: Vulnerability
) -> tuple[Finding, bool]:
    """Create or refresh a candidate finding. Always `discovered`, never confirmed."""
    existing = session.execute(
        select(Finding).where(
            Finding.vulnerability_id == candidate.vulnerability_id,
            Finding.asset_id == candidate.asset_id,
            Finding.component_id == candidate.component_id,
        )
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    if existing is not None:
        # A fix appearing later moves the finding back into actionable work.
        if existing.state == "no_fix_available" and candidate.fixed_version:
            existing.state = "discovered"
            existing.state_changed_at = datetime.now(UTC)
        existing.match_method = candidate.match_method
        existing.match_confidence = candidate.match_confidence
        existing.matched_range_id = candidate.matched_range_id
        existing.fixed_version = candidate.fixed_version
        existing.advisory_revision = candidate.advisory_revision
        existing.last_evaluated_at = now
        return existing, False

    # A distribution routinely publishes an advisory before, or without, a fix.
    # Those are real findings but nothing can be done about them, and mixing them
    # with actionable work is the volume-over-action failure the product exists to
    # avoid. The lifecycle already has a state for it.
    state = "discovered" if candidate.fixed_version else "no_fix_available"

    finding = Finding(
        group_key=candidate.vulnerability_id,
        vulnerability_id=candidate.vulnerability_id,
        asset_id=candidate.asset_id,
        component_id=candidate.component_id,
        state=state,
        match_method=candidate.match_method,
        match_confidence=candidate.match_confidence,
        matched_range_id=candidate.matched_range_id,
        fixed_version=candidate.fixed_version,
        advisory_revision=candidate.advisory_revision,
    )
    session.add(finding)
    session.flush()

    _attach_evidence(session, finding, candidate, vulnerability)
    return finding, True


def _attach_evidence(
    session: Session,
    finding: Finding,
    candidate: CandidateFinding,
    vulnerability: Vulnerability,
) -> None:
    """Every conclusion carries the reasoning that produced it."""
    import hashlib
    import json

    def add(kind: str, claim: str, value: dict[str, Any], source_ref: str | None = None) -> None:
        payload = json.dumps(value, sort_keys=True, default=str)
        session.add(
            Evidence(
                finding_id=finding.id,
                kind=kind,
                claim=claim,
                value=value,
                source_ref=source_ref,
                content_hash=hashlib.sha256(payload.encode()).hexdigest(),
            )
        )

    add(
        "version_match",
        candidate.rationale,
        {
            "method": candidate.match_method,
            "confidence": candidate.match_confidence,
            "fixed_version": candidate.fixed_version,
        },
        source_ref=f"advisory:{vulnerability.id}@rev{vulnerability.revision}",
    )
    for conflict in candidate.conflicts:
        add(
            "source_conflict",
            f"{conflict.get('source')} says {conflict.get('says')}"
            + (f": {conflict['note']}" if conflict.get("note") else ""),
            conflict,
        )


def release_of(asset: Asset) -> str | None:
    """The distribution release an asset runs, if it is known."""
    attributes = asset.attributes or {}
    return attributes.get("distro_release")


def correlate_asset(session: Session, asset: Asset) -> dict[str, Any]:
    """Match every component on one asset against known advisories."""
    distro_release = release_of(asset)
    rows = session.execute(
        select(Component)
        .join(AssetComponent, AssetComponent.component_id == Component.id)
        .where(AssetComponent.asset_id == asset.id)
    ).scalars().all()

    created = evaluated = matched = 0
    for component in rows:
        grouped = _ranges_for(session, component.ecosystem, component.name)
        for vuln_id, ranges in grouped.items():
            evaluated += 1
            vulnerability = session.get(Vulnerability, vuln_id)
            if vulnerability is None or vulnerability.withdrawn_at is not None:
                continue

            affected, method, confidence, matched_range, rationale, conflicts = evaluate(
                ecosystem=component.ecosystem,
                package=component.name,
                version=component.version,
                ranges=ranges,
                distro_release=distro_release,
            )
            if not affected:
                continue

            matched += 1
            _, is_new = _record(
                session,
                CandidateFinding(
                    vulnerability_id=vuln_id,
                    asset_id=asset.id,
                    component_id=component.id,
                    match_method=method,
                    match_confidence=confidence,
                    matched_range_id=matched_range.id if matched_range else None,
                    fixed_version=matched_range.fixed if matched_range else None,
                    advisory_revision=vulnerability.revision,
                    rationale=rationale,
                    conflicts=conflicts,
                ),
                vulnerability=vulnerability,
            )
            created += int(is_new)

    return {"components": len(rows), "evaluated": evaluated, "matched": matched, "created": created}


def correlate_advisory(session: Session, vulnerability_id: str) -> dict[str, Any]:
    """Match one advisory against everything already inventoried.

    This is the reverse direction that makes new-CVE correlation fast: it queries
    the component index rather than rescanning any asset.
    """
    vulnerability = session.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        return {"status": "unknown_advisory"}
    if vulnerability.withdrawn_at is not None:
        return {"status": "withdrawn", "matched": 0}

    ranges = session.execute(
        select(AffectedRange).where(AffectedRange.vulnerability_id == vulnerability_id)
    ).scalars().all()

    by_package: dict[tuple[str, str], list[AffectedRange]] = {}
    for r in ranges:
        by_package.setdefault((r.ecosystem, r.package), []).append(r)

    matched = created = candidates = 0
    for (ecosystem, package), package_ranges in by_package.items():
        installed = session.execute(
            select(Component, AssetComponent.asset_id)
            .join(AssetComponent, AssetComponent.component_id == Component.id)
            .where(Component.ecosystem == ecosystem, Component.name == package)
        ).all()

        for component, asset_id in installed:
            candidates += 1
            asset = session.get(Asset, asset_id)
            affected, method, confidence, matched_range, rationale, conflicts = evaluate(
                ecosystem=ecosystem,
                package=package,
                version=component.version,
                ranges=package_ranges,
                distro_release=release_of(asset) if asset else None,
            )
            if not affected:
                continue

            matched += 1
            _, is_new = _record(
                session,
                CandidateFinding(
                    vulnerability_id=vulnerability_id,
                    asset_id=asset_id,
                    component_id=component.id,
                    match_method=method,
                    match_confidence=confidence,
                    matched_range_id=matched_range.id if matched_range else None,
                    fixed_version=matched_range.fixed if matched_range else None,
                    advisory_revision=vulnerability.revision,
                    rationale=rationale,
                    conflicts=conflicts,
                ),
                vulnerability=vulnerability,
            )
            created += int(is_new)

    return {
        "status": "ok",
        "packages": len(by_package),
        "candidates": candidates,
        "matched": matched,
        "created": created,
    }


def stale_findings(session: Session, limit: int = 500) -> list[str]:
    """Findings evaluated against an older advisory revision.

    A revised advisory must re-correlate what it already produced, including
    findings previously closed — a corrected range can make a dismissed finding
    real again.
    """
    rows = session.execute(
        text(
            "SELECT DISTINCT f.vulnerability_id FROM finding f "
            "  JOIN vulnerability v ON v.id = f.vulnerability_id "
            " WHERE f.advisory_revision < v.revision LIMIT :limit"
        ),
        {"limit": limit},
    ).all()
    return [row[0] for row in rows]
