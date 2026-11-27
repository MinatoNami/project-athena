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


MATCH_CONFIDENCE: dict[str, float] = {
    "distro_advisory": 0.95,
    "purl_exact_range": 0.95,
    "cpe_range": 0.70,
    "heuristic_range": 0.40,
    "uncomparable": 0.20,
}


@dataclass
class CandidateFinding:
    vulnerability_id: str
    asset_id: uuid.UUID
    component_id: uuid.UUID
    match_method: str
    match_confidence: float
    matched_range_id: int | None
    matched_source: str | None
    matched_release: str | None
    fix_channel: str | None
    fixed_version: str | None
    advisory_revision: int
    rationale: str
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


def _candidate(
    *,
    vulnerability_id: str,
    asset_id,
    component_id,
    method: str,
    confidence: float,
    matched_range: AffectedRange | None,
    revision: int,
    rationale: str,
    conflicts: list[dict[str, Any]],
) -> CandidateFinding:
    return CandidateFinding(
        vulnerability_id=vulnerability_id,
        asset_id=asset_id,
        component_id=component_id,
        match_method=method,
        match_confidence=confidence,
        matched_range_id=matched_range.id if matched_range else None,
        matched_source=matched_range.source if matched_range else None,
        matched_release=matched_range.distro_release if matched_range else None,
        fix_channel=getattr(matched_range, "channel", None) if matched_range else None,
        fixed_version=matched_range.fixed if matched_range else None,
        advisory_revision=revision,
        rationale=rationale,
        conflicts=conflicts,
    )


def _ranges_for(session: Session, ecosystem: str, package: str) -> dict[str, list[AffectedRange]]:
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
) -> tuple[Finding, str]:
    existing = session.execute(
        select(Finding).where(
            Finding.vulnerability_id == candidate.vulnerability_id,
            Finding.asset_id == candidate.asset_id,
            Finding.component_id == candidate.component_id,
        )
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    if existing is not None:
        if existing.state == "no_fix_available" and (
            candidate.fixed_version or vulnerability.malicious
        ):
            existing.state = "discovered"
            existing.state_changed_at = datetime.now(UTC)
        reopened = existing.state == "unmatched"
        decided = existing.match_method == "uncomparable"
        if reopened:
            from athena.audit import record

            existing.state = (
                "discovered"
                if candidate.fixed_version or vulnerability.malicious
                else "no_fix_available"
            )
            existing.state_changed_at = now
            previous = existing.investigation_id
            existing.investigation_id = None
            existing.risk_score = None
            existing.risk_band = None
            existing.confidence = None
            existing.triage_disposition = None
            existing.triage_reason = None
            existing.triage_confidence = None
            existing.triaged_at = None
            record(
                session,
                actor="system:correlation",
                action="FINDING_REMATCHED",
                subject=f"finding:{existing.id}",
                detail={
                    "vulnerability_id": vulnerability.id,
                    "advisory_revision": vulnerability.revision,
                    "state": existing.state,
                    "assessment_cleared": str(previous) if previous else None,
                },
            )
        existing.match_method = candidate.match_method
        existing.match_confidence = candidate.match_confidence
        existing.matched_range_id = candidate.matched_range_id
        existing.matched_source = candidate.matched_source
        existing.matched_release = candidate.matched_release
        existing.fix_channel = candidate.fix_channel
        existing.fixed_version = candidate.fixed_version
        existing.advisory_revision = candidate.advisory_revision
        existing.last_evaluated_at = now
        if reopened:
            return existing, "reopened"
        if decided:
            from athena.audit import record

            record(
                session,
                actor="system:correlation",
                action="FINDING_MATCH_DECIDED",
                subject=f"finding:{existing.id}",
                detail={
                    "vulnerability_id": vulnerability.id,
                    "advisory_revision": vulnerability.revision,
                    "match_method": existing.match_method,
                    "fixed_version": existing.fixed_version,
                },
            )
            return existing, "decided"
        return existing, "refreshed"

    actionable = candidate.fixed_version or vulnerability.malicious
    state = "discovered" if actionable else "no_fix_available"

    finding = Finding(
        group_key=candidate.vulnerability_id,
        vulnerability_id=candidate.vulnerability_id,
        asset_id=candidate.asset_id,
        component_id=candidate.component_id,
        state=state,
        match_method=candidate.match_method,
        match_confidence=candidate.match_confidence,
        matched_range_id=candidate.matched_range_id,
        matched_source=candidate.matched_source,
        matched_release=candidate.matched_release,
        fix_channel=candidate.fix_channel,
        fixed_version=candidate.fixed_version,
        advisory_revision=candidate.advisory_revision,
    )
    session.add(finding)
    session.flush()

    _attach_evidence(session, finding, candidate, vulnerability)
    return finding, "created"


def _attach_evidence(
    session: Session,
    finding: Finding,
    candidate: CandidateFinding,
    vulnerability: Vulnerability,
) -> None:
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
            "fix_channel": candidate.fix_channel,
        },
        source_ref=f"advisory:{vulnerability.id}@rev{vulnerability.revision}",
    )
    if candidate.fix_channel and candidate.fix_channel != "standard":
        add(
            "fix_availability",
            f"The only published fix ({candidate.fixed_version}) is delivered through "
            f"the {candidate.fix_channel.upper()} channel, which needs an Ubuntu Pro "
            "entitlement. Without one this package cannot be upgraded on this host.",
            {"channel": candidate.fix_channel, "fixed_version": candidate.fixed_version},
        )
    for conflict in candidate.conflicts:
        add(
            "source_conflict",
            f"{conflict.get('source')} says {conflict.get('says')}"
            + (f": {conflict['note']}" if conflict.get("note") else ""),
            conflict,
        )


def release_of(asset: Asset) -> str | None:
    attributes = asset.attributes or {}
    return attributes.get("distro_release")


def correlate_asset(session: Session, asset: Asset) -> dict[str, Any]:
    distro_release = release_of(asset)
    rows = session.execute(
        select(Component)
        .join(AssetComponent, AssetComponent.component_id == Component.id)
        .where(AssetComponent.asset_id == asset.id)
    ).scalars().all()

    created = evaluated = matched = reopened = decided = 0
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
            _, outcome = _record(
                session,
                _candidate(
                    vulnerability_id=vuln_id,
                    asset_id=asset.id,
                    component_id=component.id,
                    method=method,
                    confidence=confidence,
                    matched_range=matched_range,
                    revision=vulnerability.revision,
                    rationale=rationale,
                    conflicts=conflicts,
                ),
                vulnerability=vulnerability,
            )
            created += int(outcome == "created")
            reopened += int(outcome == "reopened")
            decided += int(outcome == "decided")

    return {
        "components": len(rows),
        "evaluated": evaluated,
        "matched": matched,
        "created": created,
        "reopened": reopened,
        "decided": decided,
    }


def correlate_advisory(session: Session, vulnerability_id: str) -> dict[str, Any]:
    vulnerability = session.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        return {"status": "unknown_advisory"}
    if vulnerability.withdrawn_at is not None:
        _mark_evaluated(session, vulnerability)
        return {"status": "withdrawn", "matched": 0}

    ranges = session.execute(
        select(AffectedRange).where(AffectedRange.vulnerability_id == vulnerability_id)
    ).scalars().all()

    by_package: dict[tuple[str, str], list[AffectedRange]] = {}
    for r in ranges:
        by_package.setdefault((r.ecosystem, r.package), []).append(r)

    matched = created = candidates = reopened = decided = 0
    matched_pairs: set[tuple[Any, Any]] = set()
    undecided: set[tuple[Any, Any]] = set()
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
                if _undecided(method, conflicts):
                    undecided.add((asset_id, component.id))
                continue

            matched += 1
            matched_pairs.add((asset_id, component.id))
            _, outcome = _record(
                session,
                _candidate(
                    vulnerability_id=vulnerability_id,
                    asset_id=asset_id,
                    component_id=component.id,
                    method=method,
                    confidence=confidence,
                    matched_range=matched_range,
                    revision=vulnerability.revision,
                    rationale=rationale,
                    conflicts=conflicts,
                ),
                vulnerability=vulnerability,
            )
            created += int(outcome == "created")
            reopened += int(outcome == "reopened")
            decided += int(outcome == "decided")

    unmatched, became_undecided = _close_unmatched(
        session, vulnerability, matched_pairs, undecided
    )
    _mark_evaluated(session, vulnerability)

    return {
        "status": "ok",
        "packages": len(by_package),
        "candidates": candidates,
        "matched": matched,
        "created": created,
        "reopened": reopened,
        "unmatched": unmatched,
        "undecided": became_undecided,
        "decided": decided,
    }


def _mark_evaluated(session: Session, vulnerability: Vulnerability) -> None:
    session.execute(
        text(
            "UPDATE finding SET advisory_revision = :rev"
            " WHERE vulnerability_id = :id AND advisory_revision < :rev"
        ),
        {"rev": vulnerability.revision, "id": vulnerability.id},
    )


OPEN_STATES = ("discovered", "investigating", "confirmed", "no_fix_available", "regressed")


def _undecided(method: str, conflicts: list[dict[str, Any]]) -> bool:
    return method == "uncomparable" or any(
        c.get("says") in ("uncomparable", "unknown") for c in conflicts
    )


def _close_unmatched(
    session: Session,
    vulnerability: Vulnerability,
    matched: set[tuple[Any, Any]],
    undecided: set[tuple[Any, Any]],
) -> tuple[int, int]:
    from athena.audit import record

    open_findings = session.execute(
        select(Finding).where(
            Finding.vulnerability_id == vulnerability.id,
            Finding.state.in_(OPEN_STATES),
        )
    ).scalars().all()
    now = datetime.now(UTC)
    closed = became_undecided = 0
    for finding in open_findings:
        pair = (finding.asset_id, finding.component_id)
        if pair in matched:
            continue
        if pair in undecided:
            if finding.match_method != "uncomparable":
                became_undecided += 1
                record(
                    session,
                    actor="system:correlation",
                    action="FINDING_MATCH_UNDECIDED",
                    subject=f"finding:{finding.id}",
                    detail={
                        "vulnerability_id": vulnerability.id,
                        "advisory_revision": vulnerability.revision,
                        "previous": {
                            "match_method": finding.match_method,
                            "matched_source": finding.matched_source,
                            "fixed_version": finding.fixed_version,
                            "fix_channel": finding.fix_channel,
                        },
                    },
                )
            finding.match_method = "uncomparable"
            finding.match_confidence = MATCH_CONFIDENCE["uncomparable"]
            finding.matched_range_id = None
            finding.matched_source = None
            finding.matched_release = None
            finding.fixed_version = None
            finding.fix_channel = None
            finding.last_evaluated_at = now
            continue
        installed = session.execute(
            select(AssetComponent.asset_id).where(
                AssetComponent.asset_id == finding.asset_id,
                AssetComponent.component_id == finding.component_id,
            )
        ).first()
        if installed is None:
            continue
        finding.state = "unmatched"
        finding.state_changed_at = now
        finding.last_evaluated_at = now
        finding.advisory_revision = vulnerability.revision
        record(
            session,
            actor="system:correlation",
            action="FINDING_UNMATCHED",
            subject=f"finding:{finding.id}",
            detail={
                "vulnerability_id": vulnerability.id,
                "advisory_revision": vulnerability.revision,
                "reason": "no published range covers the installed version any more",
            },
        )
        closed += 1
    return closed, became_undecided


def stale_findings(session: Session, limit: int = 500) -> list[str]:
    rows = session.execute(
        text(
            "SELECT DISTINCT f.vulnerability_id FROM finding f "
            "  JOIN vulnerability v ON v.id = f.vulnerability_id "
            " WHERE f.advisory_revision < v.revision LIMIT :limit"
        ),
        {"limit": limit},
    ).all()
    return [row[0] for row in rows]
