"""Advisory ingestion and revision tracking."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from athena.db.models import AffectedRange, IntelSource, Vulnerability
from athena.intel.model import NormalisedAdvisory, content_hash

log = structlog.get_logger(__name__)


def upsert_advisory(session: Session, advisory: NormalisedAdvisory) -> str:
    """Insert or update one advisory. Returns 'new', 'revised', or 'unchanged'.

    A revision bump means something that could change a verdict has changed, so the
    caller re-correlates. A reworded summary does not qualify — otherwise every
    upstream edit would re-evaluate the whole estate.
    """
    digest = content_hash(advisory)
    existing = session.get(Vulnerability, advisory.id)
    now = datetime.now(UTC)

    if existing is None:
        session.add(
            Vulnerability(
                id=advisory.id,
                aliases=advisory.aliases,
                summary=advisory.summary,
                details=advisory.details,
                cwe=advisory.cwe,
                cvss_vector=advisory.cvss_vector,
                cvss_score=advisory.cvss_score,
                severity=advisory.severity,
                published_at=advisory.published_at,
                modified_at=advisory.modified_at,
                withdrawn_at=advisory.withdrawn_at,
                references_=advisory.references,
                revision=1,
                content_hash=digest,
            )
        )
        session.flush()
        _replace_ranges(session, advisory)
        return "new"

    # Always refresh descriptive fields; they are free and improve the UI.
    existing.summary = advisory.summary or existing.summary
    existing.details = advisory.details or existing.details
    existing.aliases = sorted(set(existing.aliases) | set(advisory.aliases))
    existing.references_ = advisory.references or existing.references_
    existing.modified_at = advisory.modified_at or existing.modified_at

    if existing.content_hash == digest:
        return "unchanged"

    existing.cvss_vector = advisory.cvss_vector
    existing.cvss_score = advisory.cvss_score
    existing.severity = advisory.severity
    existing.withdrawn_at = advisory.withdrawn_at
    existing.content_hash = digest
    existing.revision += 1
    existing.revised_at = now
    _replace_ranges(session, advisory)
    return "revised"


def _replace_ranges(session: Session, advisory: NormalisedAdvisory) -> None:
    """Ranges are replaced wholesale.

    A range that an advisory has retracted must disappear, not linger and keep
    matching — a stale range is a false positive that nobody can explain.
    """
    session.execute(
        delete(AffectedRange).where(AffectedRange.vulnerability_id == advisory.id)
    )
    for r in advisory.ranges:
        session.add(
            AffectedRange(
                vulnerability_id=advisory.id,
                ecosystem=r.ecosystem,
                package=r.package,
                introduced=r.introduced,
                fixed=r.fixed,
                last_affected=r.last_affected,
                source=r.source,
                authority=int(r.authority),
                distro=r.distro,
                distro_release=r.distro_release,
                channel=r.channel,
            )
        )


def apply_kev(session: Session, entries: list[dict[str, Any]]) -> int:
    """Mark known-exploited vulnerabilities.

    KEV is the strongest exploitation signal available, so it is applied even to
    advisories that arrived from another source.
    """
    marked = 0
    for entry in entries:
        cve = entry.get("cveID")
        if not cve:
            continue
        result = session.execute(
            text(
                "UPDATE vulnerability SET kev = true, kev_ransomware = :ransom, "
                "kev_added_at = COALESCE(kev_added_at, now()) "
                " WHERE id = :cve AND kev IS DISTINCT FROM true"
            ),
            {
                "cve": cve,
                "ransom": (entry.get("knownRansomwareCampaignUse") or "").lower() == "known",
            },
        )
        marked += result.rowcount or 0
    return marked


def apply_epss(session: Session, scores: dict[str, tuple[float, float]]) -> int:
    """Attach exploit-probability scores. Refreshed daily upstream."""
    updated = 0
    now = datetime.now(UTC)
    for cve, (score, percentile) in scores.items():
        result = session.execute(
            text(
                "UPDATE vulnerability SET epss_score = :score, "
                "epss_percentile = :pct, epss_updated_at = :now WHERE id = :cve"
            ),
            {"cve": cve, "score": score, "pct": percentile, "now": now},
        )
        updated += result.rowcount or 0
    return updated


def record_source_result(
    session: Session,
    *,
    name: str,
    succeeded: bool,
    advisories: int = 0,
    cursor: str | None = None,
    error: str | None = None,
) -> None:
    """Track per-source health.

    Feed age is a first-class signal: stale intelligence looks exactly like a quiet
    week, and the UI must be able to tell them apart.
    """
    now = datetime.now(UTC)
    source = session.get(IntelSource, name)
    if source is None:
        source = IntelSource(name=name)
        session.add(source)

    source.last_attempt_at = now
    if succeeded:
        source.last_success_at = now
        source.last_error = None
        source.advisories = (source.advisories or 0) + advisories
        if cursor:
            source.cursor = cursor
    else:
        source.last_error = (error or "unknown error")[:2000]


def source_health(session: Session) -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    rows = session.execute(select(IntelSource).order_by(IntelSource.name)).scalars().all()
    return [
        {
            "name": s.name,
            "last_success_at": s.last_success_at,
            "last_attempt_at": s.last_attempt_at,
            "age_seconds": (now - s.last_success_at).total_seconds() if s.last_success_at else None,
            "advisories": s.advisories,
            "last_error": s.last_error,
            # Never fetched successfully is not the same as fetched a while ago.
            "never_succeeded": s.last_success_at is None,
        }
        for s in rows
    ]
