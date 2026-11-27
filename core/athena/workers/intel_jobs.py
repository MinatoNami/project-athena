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
from athena.investigation.compromise import open_compromise_assessments
from athena.queue import enqueue, publish
from athena.queue.registry import handler

log = structlog.get_logger(__name__)

BATCH = 500


@handler("intel.poll.osv")
def poll_osv(payload: dict[str, Any]) -> dict[str, Any]:
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
            cursor=f"{model or 'unknown'}@{meta.get('score_date', '')}",
        )
    log.info("intel.epss", scored=len(scores), matched=updated, model=model)
    return {"status": "ok", "scored": len(scores), "matched": updated, "model": model}


VULNRICHMENT_RECHECK_DAYS = 7
VULNRICHMENT_BATCH = 200


def vulnrichment_due(session: Any, *, limit: int) -> list[str]:
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
    vulnerability_id = payload["vulnerability_id"]
    with session_scope() as session:
        result = correlate_advisory(session, vulnerability_id)
        assessments = open_compromise_assessments(session, vulnerability_id=vulnerability_id)
        if assessments:
            result["compromise_assessments"] = assessments
        if result.get("created"):
            record(
                session,
                actor="system:worker",
                action="FINDINGS_CREATED",
                subject=f"advisory:{vulnerability_id}",
                detail=result,
            )
        if changed_findings(result):
            publish(session, topic="findings", subject_id=vulnerability_id)
    return result


FINDING_CHANGES = ("created", "reopened", "unmatched", "undecided", "decided")


def changed_findings(result: dict[str, Any]) -> bool:
    return any(result.get(change) for change in FINDING_CHANGES)


@handler("correlate.asset")
def correlate_one_asset(payload: dict[str, Any]) -> dict[str, Any]:
    asset_id = payload["asset_id"]
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            return {"status": "unknown_asset"}
        result = correlate_asset(session, asset)
        assessments = open_compromise_assessments(session, asset_id=asset.id)
        if assessments:
            result["compromise_assessments"] = assessments
        if result.get("created"):
            record(
                session,
                actor="system:worker",
                action="FINDINGS_CREATED",
                subject=f"asset:{asset_id}",
                detail=result,
            )
        if changed_findings(result):
            publish(session, topic="findings", subject_id=str(asset_id))
    return result


@handler("correlate.stale")
def correlate_stale(payload: dict[str, Any]) -> dict[str, Any]:
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
