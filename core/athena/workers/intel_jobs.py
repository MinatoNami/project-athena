"""Intelligence ingestion and correlation jobs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from athena.audit import record
from athena.correlation import correlate_advisory, correlate_asset
from athena.correlation.engine import stale_findings
from athena.db.base import session_scope
from athena.db.models import Asset, IntelSource, Vulnerability
from athena.intel import feeds
from athena.intel.ingest import (
    apply_epss,
    apply_kev,
    record_source_result,
    upsert_advisory,
)
from athena.intel.osv import parse_many
from athena.queue import enqueue, publish
from athena.queue.registry import handler

log = structlog.get_logger(__name__)

# Advisories are ingested in batches so one ecosystem does not hold a transaction
# open for minutes.
BATCH = 500


@handler("intel.poll.osv")
def poll_osv(payload: dict[str, Any]) -> dict[str, Any]:
    """Ingest one OSV ecosystem archive, then correlate what changed."""
    ecosystem = payload.get("ecosystem") or "PyPI"
    limit = payload.get("limit")

    counts = {"new": 0, "revised": 0, "unchanged": 0}
    changed: list[str] = []
    records = skipped = 0
    batch: list = []

    def flush(pending: list) -> None:
        if not pending:
            return
        with session_scope() as session:
            for advisory in pending:
                outcome = upsert_advisory(session, advisory)
                counts[outcome] += 1
                if outcome in ("new", "revised"):
                    changed.append(advisory.id)
        pending.clear()

    try:
        # Committed in batches as the archive streams, so a backfill of tens of
        # thousands of advisories makes visible progress and never holds one
        # transaction open for the whole download.
        for record_ in feeds.fetch_osv_ecosystem(ecosystem, limit=limit):
            records += 1
            parsed, skipped_here = parse_many([record_])
            skipped += skipped_here
            batch.extend(parsed)
            if len(batch) >= BATCH:
                flush(batch)
                log.info("intel.progress", ecosystem=ecosystem, records=records, **counts)
        flush(batch)
    except feeds.FeedError as exc:
        flush(batch)
        with session_scope() as session:
            record_source_result(
                session, name=f"osv:{ecosystem}".lower(), succeeded=False, error=str(exc)
            )
        log.warning("intel.fetch_failed", source="osv", ecosystem=ecosystem, error=str(exc))
        return {"status": "failed", "ecosystem": ecosystem, "error": str(exc), **counts}

    with session_scope() as session:
        record_source_result(
            session,
            name=f"osv:{ecosystem}".lower(),
            succeeded=True,
            advisories=counts["new"],
        )
        # Only advisories that actually changed are re-correlated. Correlating
        # everything on every poll would be enormous and pointless.
        for advisory_id in changed[:5000]:
            enqueue(
                session,
                kind="correlate.advisory",
                key=advisory_id,
                payload={"vulnerability_id": advisory_id},
                priority=4,
            )

    log.info(
        "intel.ingested", source="osv", ecosystem=ecosystem,
        records=records, skipped=skipped, **counts,
    )
    return {"status": "ok", "ecosystem": ecosystem, "skipped": skipped, **counts}


@handler("intel.poll.kev")
def poll_kev(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        entries = feeds.fetch_kev()
    except feeds.FeedError as exc:
        with session_scope() as session:
            record_source_result(session, name="kev", succeeded=False, error=str(exc))
        return {"status": "failed", "error": str(exc)}

    with session_scope() as session:
        marked = apply_kev(session, entries)
        record_source_result(session, name="kev", succeeded=True, advisories=len(entries))
    log.info("intel.kev", entries=len(entries), newly_marked=marked)
    return {"status": "ok", "entries": len(entries), "newly_marked": marked}


@handler("intel.poll.epss")
def poll_epss(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        scores, meta = feeds.fetch_epss()
    except feeds.FeedError as exc:
        with session_scope() as session:
            record_source_result(session, name="epss", succeeded=False, error=str(exc))
        return {"status": "failed", "error": str(exc)}

    updated = 0
    entries = list(scores.items())
    for start in range(0, len(entries), 5000):
        with session_scope() as session:
            updated += apply_epss(session, dict(entries[start : start + 5000]))

    model = meta.get("model_version")
    with session_scope() as session:
        record_source_result(
            session, name="epss", succeeded=True, advisories=len(scores),
            # The cursor carries the model, so the intel page can say which EPSS the
            # scores on every finding came from. Written even when the file did not
            # name one: an empty cursor is not stored, and the page then credited
            # these scores to whichever model the previous fetch named.
            cursor=f"{model or 'unknown'}@{meta.get('score_date', '')}",
        )
    log.info("intel.epss", scored=len(scores), matched=updated, model=model)
    return {"status": "ok", "scored": len(scores), "matched": updated, "model": model}


# How long CISA's answer is trusted before asking again. Vulnrichment updates about
# twice a day, but an assessment, once written, rarely moves.
VULNRICHMENT_RECHECK_DAYS = 7
VULNRICHMENT_BATCH = 200


def vulnrichment_due(session: Any, *, limit: int) -> list[str]:
    """CVEs to ask CISA about: eligible, and with no answer or a stale one.

    Eligibility is shared with the coverage figure on /intel/sources
    (`athena.intel.enrichment`); the recheck window is this job's alone. Unchecked
    first, then known-exploited.
    """
    from datetime import timedelta

    from sqlalchemy import or_, select

    from athena.intel.enrichment import eligible

    cutoff = datetime.now(UTC) - timedelta(days=VULNRICHMENT_RECHECK_DAYS)
    return list(
        session.execute(
            select(Vulnerability.id)
            .where(
                *eligible(),
                or_(
                    Vulnerability.ssvc_checked_at.is_(None),
                    Vulnerability.ssvc_checked_at < cutoff,
                ),
            )
            .order_by(
                Vulnerability.ssvc_checked_at.asc().nulls_first(),
                Vulnerability.kev.desc(),
                Vulnerability.id,
            )
            .limit(limit)
        ).scalars()
    )


@handler("intel.enrich.vulnrichment")
def enrich_vulnrichment(payload: dict[str, Any]) -> dict[str, Any]:
    """Fetch CISA's SSVC assessment for CVEs that have findings here.

    Only those: the corpus holds hundreds of thousands of CVEs and CISA's file for
    each is a separate request, while the ones that matter are the few hundred that
    matched something in this estate. Unchecked ones go first.

    A CISA "poc" or "active" sets `exploit_public` — the one risk input nothing else
    in Athena could establish — and a rescore follows, because that input moves the
    exploitation factor.
    """
    batch = int(payload.get("limit") or VULNRICHMENT_BATCH)
    with session_scope() as session:
        ids = vulnrichment_due(session, limit=batch)

    found = absent = failed = moved = 0
    errors: list[str] = []
    with feeds.http_client(timeout=30.0) as client:
        for cve in ids:
            try:
                record = feeds.fetch_vulnrichment(client, cve)
            except feeds.FeedError as exc:
                failed += 1
                errors.append(str(exc))
                continue
            assessment = feeds.parse_vulnrichment(record) if record else None
            with session_scope() as session:
                vulnerability = session.get(Vulnerability, cve)
                if vulnerability is None:
                    continue
                exploited = (assessment or {}).get("exploitation") in ("poc", "active")
                if assessment is not None and vulnerability.exploit_public != exploited:
                    vulnerability.exploit_public = exploited
                    moved += 1
                vulnerability.ssvc_cisa = assessment
                vulnerability.ssvc_checked_at = datetime.now(UTC)
            if assessment:
                found += 1
            else:
                absent += 1

    with session_scope() as session:
        # A run that could not reach CISA at all is a failure; one where some
        # lookups failed is recorded as a success with the error kept, because the
        # rest of the batch is real data and its age must not read as stale.
        succeeded = not ids or failed < len(ids)
        record_source_result(
            session, name="vulnrichment", succeeded=succeeded, advisories=found,
            error="; ".join(errors[:3]) if errors else None,
        )
        if succeeded and errors:
            source = session.get(IntelSource, "vulnrichment")
            source.last_error = f"{failed} of {len(ids)} lookups failed: {errors[0]}"[:2000]
        if moved:
            enqueue(
                session, kind="rescore.findings",
                key=f"vulnrichment:{datetime.now(UTC):%Y%m%d%H}", payload={}, priority=6,
            )
    log.info("intel.vulnrichment", checked=len(ids), found=found, absent=absent,
             failed=failed, exploit_signal_changed=moved)
    return {"checked": len(ids), "found": found, "absent": absent, "failed": failed,
            "exploit_signal_changed": moved}


@handler("correlate.advisory")
def correlate_one_advisory(payload: dict[str, Any]) -> dict[str, Any]:
    """Match a new or revised advisory against everything already inventoried."""
    vulnerability_id = payload["vulnerability_id"]
    with session_scope() as session:
        result = correlate_advisory(session, vulnerability_id)
        if result.get("created"):
            record(
                session,
                actor="system:worker",
                action="FINDINGS_CREATED",
                subject=f"advisory:{vulnerability_id}",
                detail=result,
            )
        # Any change a page shows, not only new findings: a run that only closes
        # findings a retracted range supported, or reopens one, otherwise left a
        # connected page listing what was no longer there. Each closure and reopening
        # is audited on its own finding.
        if result.get("created") or result.get("unmatched") or result.get("reopened"):
            publish(session, topic="findings", subject_id=vulnerability_id)
    return result


@handler("correlate.asset")
def correlate_one_asset(payload: dict[str, Any]) -> dict[str, Any]:
    """Match one asset's components against every known advisory."""
    asset_id = payload["asset_id"]
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            return {"status": "unknown_asset"}
        result = correlate_asset(session, asset)
        if result.get("created"):
            record(
                session,
                actor="system:worker",
                action="FINDINGS_CREATED",
                subject=f"asset:{asset_id}",
                detail=result,
            )
        if result.get("created") or result.get("reopened"):
            publish(session, topic="findings", subject_id=str(asset_id))
    return result


@handler("correlate.stale")
def correlate_stale(payload: dict[str, Any]) -> dict[str, Any]:
    """Re-correlate findings whose advisory has been revised since evaluation."""
    with session_scope() as session:
        advisory_ids = stale_findings(session)
        for advisory_id in advisory_ids:
            enqueue(
                session,
                kind="correlate.advisory",
                key=f"{advisory_id}:restale",
                payload={"vulnerability_id": advisory_id},
                priority=4,
            )
    return {"status": "ok", "requeued": len(advisory_ids)}
