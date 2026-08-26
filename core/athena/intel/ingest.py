"""Advisory ingestion and revision tracking."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from athena.db.models import AffectedRange, IntelSource
from athena.intel.model import NormalisedAdvisory, content_hash

log = structlog.get_logger(__name__)


def upsert_advisory(session: Session, advisory: NormalisedAdvisory) -> str:
    """Ingest one source record. Returns 'new', 'revised', or 'unchanged'.

    State is tracked per source record, not per vulnerability. Several records
    converge on one CVE by design — an upstream advisory and each distribution's
    tracker — and the authority rule needs their ranges side by side. Replacing all
    ranges on every write made them overwrite each other, so whichever was ingested
    last won and the others simply vanished.
    """
    digest = content_hash(advisory)
    source_record = advisory.source_record or advisory.id
    source = _dominant_source(advisory)
    now = datetime.now(UTC)

    known = session.execute(
        text(
            "SELECT content_hash FROM advisory_source "
            " WHERE vulnerability_id = :id AND source_record = :rec"
        ),
        {"id": advisory.id, "rec": source_record},
    ).scalar_one_or_none()

    if known == digest:
        return "unchanged"

    is_new_vulnerability = session.execute(
        text("SELECT 1 FROM vulnerability WHERE id = :id"), {"id": advisory.id}
    ).first() is None

    session.execute(
        text(
            """
            INSERT INTO vulnerability (
                id, aliases, summary, details, cwe, cvss_vector, cvss_score, severity,
                published_at, modified_at, withdrawn_at, "references",
                revision, revised_at, content_hash
            ) VALUES (
                :id, :aliases, :summary, :details, :cwe, :vector, :score, :severity,
                :published, :modified, :withdrawn, CAST(:refs AS jsonb),
                1, NULL, :hash
            )
            ON CONFLICT (id) DO UPDATE SET
                aliases     = ARRAY(SELECT DISTINCT unnest(
                                  vulnerability.aliases || EXCLUDED.aliases)),
                summary     = COALESCE(vulnerability.summary, EXCLUDED.summary),
                details     = COALESCE(vulnerability.details, EXCLUDED.details),
                cwe         = CASE WHEN cardinality(EXCLUDED.cwe) > 0
                                   THEN EXCLUDED.cwe ELSE vulnerability.cwe END,
                -- A CVSS vector is better information than a distribution's single
                -- word, so it is never overwritten by one.
                cvss_vector = COALESCE(vulnerability.cvss_vector, EXCLUDED.cvss_vector),
                cvss_score  = COALESCE(vulnerability.cvss_score, EXCLUDED.cvss_score),
                severity    = COALESCE(vulnerability.severity, EXCLUDED.severity),
                modified_at = GREATEST(vulnerability.modified_at, EXCLUDED.modified_at),
                withdrawn_at = COALESCE(EXCLUDED.withdrawn_at, vulnerability.withdrawn_at),
                "references" = CASE
                                   WHEN jsonb_array_length(EXCLUDED."references") > 0
                                   THEN EXCLUDED."references"
                                   ELSE vulnerability."references" END,
                revision    = vulnerability.revision + 1,
                revised_at  = :now,
                content_hash = EXCLUDED.content_hash
            """
        ),
        {
            "id": advisory.id,
            "aliases": advisory.aliases,
            "summary": advisory.summary,
            "details": advisory.details,
            "cwe": advisory.cwe,
            "vector": advisory.cvss_vector,
            "score": advisory.cvss_score,
            "severity": advisory.severity,
            "published": advisory.published_at,
            "modified": advisory.modified_at,
            "withdrawn": advisory.withdrawn_at,
            "refs": json.dumps(advisory.references, default=str),
            "hash": digest,
            "now": now,
        },
    )

    _replace_ranges(session, advisory, source_record=source_record)

    session.execute(
        text(
            """
            INSERT INTO advisory_source
                (vulnerability_id, source_record, source, content_hash, modified_at)
            VALUES (:id, :rec, :source, :hash, :modified)
            ON CONFLICT (vulnerability_id, source_record) DO UPDATE SET
                content_hash = EXCLUDED.content_hash,
                modified_at  = EXCLUDED.modified_at,
                ingested_at  = now()
            """
        ),
        {
            "id": advisory.id,
            "rec": source_record,
            "source": source,
            "hash": digest,
            "modified": advisory.modified_at,
        },
    )

    return "new" if is_new_vulnerability else "revised"


def _dominant_source(advisory: NormalisedAdvisory) -> str:
    """The source this record speaks for, used only for reporting."""
    for r in advisory.ranges:
        if r.source:
            return r.source
    return advisory.source


def _replace_ranges(
    session: Session, advisory: NormalisedAdvisory, *, source_record: str
) -> None:
    """Replace this source record's ranges, and only its own.

    A range the source has retracted must disappear rather than linger and keep
    matching. But a CVE routinely carries ranges from several records — an upstream
    advisory and each distribution's tracker — so deleting all of them drops every
    other source's, which is the bug this replaces.
    """
    session.execute(
        delete(AffectedRange).where(
            AffectedRange.vulnerability_id == advisory.id,
            AffectedRange.source_record == source_record,
        )
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
                source_record=source_record,
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
        # Set once and never moved: this is the start line detection latency is
        # measured from, and a moving one would make the metric meaningless.
        if source.first_success_at is None:
            source.first_success_at = now
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
