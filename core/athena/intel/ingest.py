from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import Any

import structlog
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from athena.db.models import AffectedRange, IntelSource
from athena.intel import cvss
from athena.intel.model import NormalisedAdvisory, content_hash

log = structlog.get_logger(__name__)


def upsert_advisory(session: Session, advisory: NormalisedAdvisory) -> str:
    digest = content_hash(advisory)
    source_record = advisory.source_record or advisory.id
    source = _dominant_source(advisory)
    now = datetime.now(UTC)

    stored = session.execute(
        text(
            "SELECT content_hash, malicious FROM advisory_source "
            " WHERE vulnerability_id = :id AND source_record = :rec"
        ),
        {"id": advisory.id, "rec": source_record},
    ).first()
    known = stored.content_hash if stored else None
    unclassified = stored is not None and stored.malicious is None

    if known == digest:
        if unclassified:
            return _classify(session, advisory, source_record=source_record, now=now)
        return "unchanged"

    if advisory.source_withdrawn_at is not None:
        return _retract_source(
            session, advisory, source_record=source_record, digest=digest, now=now
        )

    is_new_vulnerability = session.execute(
        text("SELECT 1 FROM vulnerability WHERE id = :id"), {"id": advisory.id}
    ).first() is None

    scoring_vector: str | None = None
    if advisory.cvss_score is not None:
        score = advisory.cvss_score
    else:
        candidate = advisory.scoring_vector or advisory.cvss_vector
        score = cvss.base_score(candidate)
        scoring_vector = candidate if score is not None else None

    session.execute(
        text(
            """
            INSERT INTO vulnerability (
                id, aliases, summary, details, cwe, cvss_vector, cvss_score, severity,
                published_at, modified_at, withdrawn_at, "references",
                revision, revised_at, content_hash, malicious, cvss_scoring_vector
            ) VALUES (
                :id, :aliases, :summary, :details, :cwe, :vector, :score, :severity,
                :published, :modified, :withdrawn, CAST(:refs AS jsonb),
                1, NULL, :hash, :malicious, :scoring_vector
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
                -- Follows the score it explains: kept while the score is kept, taken
                -- with the score when the score is.
                cvss_scoring_vector = CASE WHEN vulnerability.cvss_score IS NULL
                                           THEN EXCLUDED.cvss_scoring_vector
                                           ELSE vulnerability.cvss_scoring_vector END,
                severity    = COALESCE(vulnerability.severity, EXCLUDED.severity),
                modified_at = GREATEST(vulnerability.modified_at, EXCLUDED.modified_at),
                withdrawn_at = COALESCE(EXCLUDED.withdrawn_at, vulnerability.withdrawn_at),
                "references" = CASE
                                   WHEN jsonb_array_length(EXCLUDED."references") > 0
                                   THEN EXCLUDED."references"
                                   ELSE vulnerability."references" END,
                -- Sticky: once any source calls the package malware, a later
                -- record that does not say so is silence, not a retraction.
                malicious   = vulnerability.malicious OR EXCLUDED.malicious,
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
            "score": score,
            "scoring_vector": scoring_vector,
            "severity": advisory.severity,
            "published": advisory.published_at,
            "modified": advisory.modified_at,
            "withdrawn": advisory.withdrawn_at,
            "refs": json.dumps(advisory.references, default=str),
            "hash": digest,
            "now": now,
            "malicious": is_malicious(advisory),
        },
    )

    _replace_ranges(session, advisory, source_record=source_record)
    _record_source(
        session,
        advisory,
        source_record=source_record,
        source=source,
        digest=digest,
        malicious=is_malicious(advisory),
    )
    if unclassified:
        _settle_malicious(session, advisory.id)

    return "new" if is_new_vulnerability else "revised"


def _classify(
    session: Session, advisory: NormalisedAdvisory, *, source_record: str, now: datetime
) -> str:
    malicious = advisory.source_withdrawn_at is None and is_malicious(advisory)
    session.execute(
        text(
            "UPDATE advisory_source SET malicious = :malicious"
            " WHERE vulnerability_id = :id AND source_record = :rec"
        ),
        {"id": advisory.id, "rec": source_record, "malicious": malicious},
    )
    if _settle_malicious(session, advisory.id):
        _revise(session, advisory.id, now)
        return "revised"
    return "unchanged"


def _settle_malicious(session: Session, vulnerability_id: str) -> bool:
    cleared = session.execute(
        text(
            """
            UPDATE vulnerability SET malicious = false
             WHERE id = :id AND malicious
               AND upper(id) NOT LIKE 'MAL-%'
               AND NOT EXISTS (
                   SELECT 1 FROM advisory_source s
                    WHERE s.vulnerability_id = :id AND s.malicious IS NOT FALSE)
            """
        ),
        {"id": vulnerability_id},
    ).rowcount
    return bool(cleared)


def _revise(session: Session, vulnerability_id: str, now: datetime) -> None:
    session.execute(
        text(
            "UPDATE vulnerability SET revision = revision + 1, revised_at = :now"
            " WHERE id = :id"
        ),
        {"id": vulnerability_id, "now": now},
    )


def _record_source(
    session: Session,
    advisory: NormalisedAdvisory,
    *,
    source_record: str,
    source: str,
    digest: str,
    malicious: bool,
) -> None:
    session.execute(
        text(
            """
            INSERT INTO advisory_source
                (vulnerability_id, source_record, source, content_hash, modified_at,
                 malicious)
            VALUES (:id, :rec, :source, :hash, :modified, :malicious)
            ON CONFLICT (vulnerability_id, source_record) DO UPDATE SET
                content_hash = EXCLUDED.content_hash,
                modified_at  = EXCLUDED.modified_at,
                malicious    = EXCLUDED.malicious,
                ingested_at  = now()
            """
        ),
        {
            "id": advisory.id,
            "rec": source_record,
            "source": source,
            "hash": digest,
            "modified": advisory.modified_at,
            "malicious": malicious,
        },
    )


def _retract_source(
    session: Session,
    advisory: NormalisedAdvisory,
    *,
    source_record: str,
    digest: str,
    now: datetime,
) -> str:
    exists = session.execute(
        text("SELECT 1 FROM vulnerability WHERE id = :id"), {"id": advisory.id}
    ).first()
    if exists is None:
        return "unchanged"

    removed = session.execute(
        delete(AffectedRange).where(
            AffectedRange.vulnerability_id == advisory.id,
            AffectedRange.source_record == source_record,
        )
    ).rowcount
    _record_source(
        session,
        advisory,
        source_record=source_record,
        source=advisory.source,
        digest=digest,
        malicious=False,
    )
    cleared = _settle_malicious(session, advisory.id)
    if removed or cleared:
        _revise(session, advisory.id, now)
    return "revised" if removed or cleared else "unchanged"


def is_malicious(advisory: NormalisedAdvisory) -> bool:
    if advisory.malicious:
        return True
    ids = [advisory.id, advisory.source_record]
    return any(isinstance(i, str) and i.upper().startswith("MAL-") for i in ids)


def _dominant_source(advisory: NormalisedAdvisory) -> str:
    for r in advisory.ranges:
        if r.source:
            return r.source
    return advisory.source


def _replace_ranges(
    session: Session, advisory: NormalisedAdvisory, *, source_record: str
) -> None:
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
    marked = 0
    for entry in entries:
        cve = entry.get("cveID")
        if not cve:
            continue
        params = {
            "cve": cve,
            "ransom": (entry.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "added": _kev_date(entry.get("dateAdded")),
            "due": _kev_date(entry.get("dueDate")),
            "triage": {"yes": True, "no": False}.get(
                str(entry.get("forensicTriage") or "").strip().lower()
            ),
        }
        result = session.execute(
            text(
                "UPDATE vulnerability SET kev = true, kev_ransomware = :ransom, "
                "kev_added_at = COALESCE(kev_added_at, now()), "
                "kev_date_added = :added, kev_due_date = :due, "
                "kev_forensic_triage = :triage "
                " WHERE id = :cve AND kev IS DISTINCT FROM true"
            ),
            params,
        )
        marked += result.rowcount or 0
        session.execute(
            text(
                "UPDATE vulnerability SET kev_ransomware = :ransom, "
                "kev_date_added = :added, kev_due_date = :due, "
                "kev_forensic_triage = :triage "
                " WHERE id = :cve AND kev IS true "
                "   AND (kev_date_added IS DISTINCT FROM :added "
                "        OR kev_due_date IS DISTINCT FROM :due "
                "        OR kev_forensic_triage IS DISTINCT FROM :triage "
                "        OR kev_ransomware IS DISTINCT FROM :ransom)"
            ),
            params,
        )
    return marked


def _kev_date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def apply_epss(session: Session, scores: dict[str, tuple[float, float]]) -> int:
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
    now = datetime.now(UTC)
    source = session.get(IntelSource, name)
    if source is None:
        source = IntelSource(name=name)
        session.add(source)

    source.last_attempt_at = now
    if succeeded:
        source.last_success_at = now
        if source.first_success_at is None:
            source.first_success_at = now
        source.last_error = None
        source.advisories = (source.advisories or 0) + advisories
        if cursor:
            source.cursor = cursor
    else:
        source.last_error = (error or "unknown error")[:2000]


STALE_AFTER = {"epss": 2 * 86400, "vulnrichment": 2 * 86400}
STALE_AFTER_DEFAULT = 6 * 3600


def stale_after(name: str) -> int:
    return STALE_AFTER.get(name, STALE_AFTER_DEFAULT)


def source_health(session: Session) -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    rows = session.execute(select(IntelSource).order_by(IntelSource.name)).scalars().all()
    return [
        {
            "stale_after_seconds": stale_after(s.name),
            "stale": s.last_success_at is None
            or (now - s.last_success_at).total_seconds() > stale_after(s.name),
            "name": s.name,
            "last_success_at": s.last_success_at,
            "last_attempt_at": s.last_attempt_at,
            "age_seconds": (now - s.last_success_at).total_seconds() if s.last_success_at else None,
            "advisories": s.advisories,
            "last_error": s.last_error,
            "cursor": s.cursor,
            "never_succeeded": s.last_success_at is None,
        }
        for s in rows
    ]
