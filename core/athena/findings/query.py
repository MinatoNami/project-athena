from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Integer, Select, case, func, literal, or_, select, tuple_
from sqlalchemy.orm import Session

from athena.db.models import Asset, Component, Finding, Suppression, Vulnerability
from athena.risk import deadline, ssvc
from athena.suppression import active_predicate

MAX_LIMIT = 200
DEFAULT_LIMIT = 50

SORTS = ("risk", "spread", "recent")

_BAND_RANK = case(
    (Finding.risk_band == "critical", 4),
    (Finding.risk_band == "high", 3),
    (Finding.risk_band == "medium", 2),
    (Finding.risk_band == "low", 1),
    (Finding.risk_band == "informational", 0),
    else_=-1,
)

_SEVERITY_RANK = case(
    (Vulnerability.cvss_score >= 9.0, 4),
    (Vulnerability.cvss_score >= 7.0, 3),
    (Vulnerability.cvss_score >= 4.0, 2),
    (Vulnerability.cvss_score.is_not(None), 1),
    (func.lower(Vulnerability.severity) == "critical", 4),
    (func.lower(Vulnerability.severity) == "high", 3),
    (func.lower(Vulnerability.severity) == "medium", 2),
    (func.lower(Vulnerability.severity) == "low", 1),
    else_=0,
)


@dataclass
class FindingQuery:
    state: str | None = None
    asset_id: str | None = None
    include_no_fix: bool = False
    include_suppressed: bool = False
    include_baseline: bool = False

    q: str | None = None
    assessed: bool | None = None
    fully_assessed: bool | None = None
    kev: bool = False
    malicious: bool = False
    exposure: str | None = None
    tier: str | None = None
    has_fix: bool | None = None
    min_band: str | None = None
    needs_attention: bool | None = None

    sort: str = "risk"
    cursor: str | None = None
    limit: int = DEFAULT_LIMIT

    def facets_active(self) -> bool:
        return any(
            (
                self.q,
                self.assessed is not None,
                self.fully_assessed is not None,
                self.kev,
                self.malicious,
                self.exposure,
                self.tier,
                self.has_fix is not None,
                self.min_band,
                self.needs_attention is not None,
            )
        )


@dataclass
class Page:
    groups: list[dict[str, Any]] = field(default_factory=list)
    next_cursor: str | None = None
    group_count: int = 0
    matching_group_count: int = 0
    instance_count: int = 0
    assessed_count: int = 0
    suppressed_group_count: int = 0
    baseline_group_count: int = 0
    unbaselined_asset_count: int = 0
    facets: dict[str, dict[str, int]] = field(default_factory=dict)


def _base(query: FindingQuery) -> Select:
    stmt = (
        select(Finding, Vulnerability, Asset)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .join(Asset, Asset.id == Finding.asset_id)
    )
    if query.state:
        stmt = stmt.where(Finding.state == query.state)
    else:
        stmt = stmt.where(Finding.state != "unmatched")
        if not query.include_no_fix:
            stmt = stmt.where(Finding.state != "no_fix_available")
    if query.asset_id:
        stmt = stmt.where(Finding.asset_id == query.asset_id)
    stmt = stmt.where(Vulnerability.withdrawn_at.is_(None))
    if not query.include_suppressed:
        stmt = stmt.where(~_suppressed_exists())
    if not query.include_baseline:
        stmt = stmt.where(_is_new())
    return stmt


def _is_new() -> Any:
    return or_(
        Asset.baseline_at.is_(None),
        Finding.first_seen > Asset.baseline_at,
        Vulnerability.kev.is_(True),
        Vulnerability.malicious.is_(True),
        _BAND_RANK >= 3,
    )


def _suppressed_exists() -> Any:
    from athena.suppression.service import scope_matches_finding

    return (
        select(literal(1))
        .select_from(Suppression)
        .where(scope_matches_finding(), active_predicate())
        .exists()
    )


def _facet_predicates(query: FindingQuery) -> list[Any]:
    preds: list[Any] = []
    if query.q:
        needle = f"%{query.q.strip().lower()}%"
        preds.append(
            or_(
                func.lower(Vulnerability.id).like(needle),
                func.lower(func.coalesce(Vulnerability.summary, "")).like(needle),
            )
        )
    if query.kev:
        preds.append(Vulnerability.kev.is_(True))
    if query.malicious:
        preds.append(Vulnerability.malicious.is_(True))
    if query.exposure:
        preds.append(Asset.exposure == query.exposure)
    if query.tier:
        preds.append(Asset.tier == query.tier)
    if query.min_band:
        floor = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        preds.append(_BAND_RANK >= floor.get(query.min_band, 0))
    return preds


def _needs_attention_having() -> Any:
    return or_(
        func.max(_BAND_RANK) >= 2,
        func.max(func.cast(Vulnerability.kev, Integer)) > 0,
        func.max(func.cast(Vulnerability.malicious, Integer)) > 0,
    )


_AGG = (
    Finding.group_key.label("group_key"),
    func.max(_BAND_RANK).label("worst_rank"),
    func.max(Finding.risk_score).label("worst_score"),
    func.count().label("instance_count"),
    func.count(Finding.investigation_id).label("investigated_count"),
    func.count(Finding.fixed_version).label("fixed_count"),
    func.max(func.cast(Vulnerability.kev, Integer)).label("kev"),
    func.max(func.cast(Vulnerability.malicious, Integer)).label("malicious"),
    func.max(_SEVERITY_RANK).label("severity_rank"),
    func.max(func.coalesce(Vulnerability.cvss_score, 0.0)).label("cvss"),
    func.max(func.coalesce(Vulnerability.epss_score, 0.0)).label("epss"),
    func.max(Vulnerability.published_at).label("published_at"),
    *[
        func.max(case((Asset.exposure == value, 1), else_=0)).label(f"exposure_{value}")
        for value in ("internet", "internal", "isolated", "unknown")
    ],
)


def _grouped(query: FindingQuery, *, with_facets: bool) -> Select:
    stmt = _base(query)
    if with_facets:
        for pred in _facet_predicates(query):
            stmt = stmt.where(pred)
    grouped = stmt.with_only_columns(*_AGG).group_by(Finding.group_key)

    if with_facets:
        if query.assessed is True:
            grouped = grouped.having(func.count(Finding.investigation_id) > 0)
        elif query.assessed is False:
            grouped = grouped.having(func.count(Finding.investigation_id) == 0)
        if query.fully_assessed is True:
            grouped = grouped.having(func.count(Finding.investigation_id) == func.count())
        elif query.fully_assessed is False:
            grouped = grouped.having(func.count(Finding.investigation_id) < func.count())
        if query.has_fix is True:
            grouped = grouped.having(func.count(Finding.fixed_version) > 0)
        elif query.has_fix is False:
            grouped = grouped.having(func.count(Finding.fixed_version) == 0)
        if query.needs_attention is True:
            grouped = grouped.having(_needs_attention_having())
        elif query.needs_attention is False:
            grouped = grouped.having(~_needs_attention_having())
    return grouped


def _sort_columns(sub: Any, sort: str) -> list[Any]:
    if sort == "spread":
        return [-sub.c.instance_count, -sub.c.worst_rank, sub.c.group_key]
    if sort == "recent":
        return [
            func.coalesce(func.extract("epoch", sub.c.published_at), 0) * -1,
            sub.c.group_key,
        ]
    return [
        -sub.c.malicious,
        -sub.c.worst_rank,
        -sub.c.kev,
        -sub.c.severity_rank,
        -sub.c.cvss,
        -sub.c.epss,
        sub.c.group_key,
    ]


def _encode(values: list[Any]) -> str:
    payload = json.dumps([float(v) if isinstance(v, (int, float)) else str(v) for v in values])
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _decode(cursor: str, width: int) -> list[Any] | None:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        values = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return values if isinstance(values, list) and len(values) == width else None


def _facet_counts(session: Session, query: FindingQuery, *, with_facets: bool) -> dict[str, int]:
    sub = _grouped(query, with_facets=with_facets).subquery()
    row = session.execute(
        select(
            func.count().label("total"),
            func.count().filter(sub.c.investigated_count > 0).label("assessed"),
            func.count().filter(sub.c.investigated_count == 0).label("unassessed"),
            func.count().filter(sub.c.kev > 0).label("kev"),
            func.count().filter(sub.c.malicious > 0).label("malicious"),
            func.count().filter(sub.c.fixed_count > 0).label("has_fix"),
            func.count().filter(sub.c.fixed_count == 0).label("no_fix"),
            func.count().filter(sub.c.instance_count > 1).label("spread"),
            func.count()
            .filter((sub.c.worst_rank >= 2) | (sub.c.kev > 0) | (sub.c.malicious > 0))
            .label("needs_attention"),
            func.count()
            .filter(
                (sub.c.investigated_count == sub.c.instance_count)
                & ~((sub.c.worst_rank >= 2) | (sub.c.kev > 0) | (sub.c.malicious > 0))
            )
            .label("cleared"),
            func.count()
            .filter(
                (sub.c.investigated_count < sub.c.instance_count)
                & ~((sub.c.worst_rank >= 2) | (sub.c.kev > 0) | (sub.c.malicious > 0))
            )
            .label("waiting"),
            *[
                func.count().filter(sub.c[f"exposure_{value}"] > 0).label(f"exposure:{value}")
                for value in ("internet", "internal", "isolated", "unknown")
            ],
            *[
                func.count().filter(sub.c.worst_rank == rank).label(f"band:{name}")
                for rank, name in (
                    (4, "critical"), (3, "high"), (2, "medium"),
                    (1, "low"), (0, "informational"), (-1, "unassessed"),
                )
            ],
            func.coalesce(func.sum(sub.c.instance_count), 0).label("instances"),
            func.coalesce(func.sum(sub.c.investigated_count), 0).label("assessed_instances"),
        ).select_from(sub)
    ).one()
    return dict(row._mapping)


def query_findings(session: Session, query: FindingQuery) -> Page:
    limit = max(1, min(query.limit, MAX_LIMIT))
    sub = _grouped(query, with_facets=True).subquery()
    order = _sort_columns(sub, query.sort if query.sort in SORTS else "risk")

    stmt = select(sub).order_by(*order)
    if query.cursor:
        after = _decode(query.cursor, len(order))
        if after is not None:
            stmt = stmt.where(tuple_(*order) > tuple_(*[literal(v) for v in after]))

    rows = session.execute(stmt.limit(limit + 1)).all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    next_cursor = None
    if has_more and rows:
        tail = session.execute(
            select(*order).select_from(sub).where(sub.c.group_key == rows[-1].group_key)
        ).one()
        next_cursor = _encode(list(tail))

    groups = _hydrate(session, query, [r.group_key for r in rows], rows)

    totals = _facet_counts(session, query, with_facets=False)
    matching = _facet_counts(session, query, with_facets=True)

    suppressed = session.execute(
        select(func.count(func.distinct(Finding.group_key)))
        .select_from(Finding)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(
            _suppressed_exists(),
            Vulnerability.withdrawn_at.is_(None),
            Finding.state != "unmatched",
        )
    ).scalar_one()

    baselined = session.execute(
        select(func.count(func.distinct(Finding.group_key)))
        .select_from(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(~_is_new(), Vulnerability.withdrawn_at.is_(None), Finding.state != "unmatched")
    ).scalar_one()

    unbaselined = session.execute(
        select(func.count(func.distinct(Asset.id)))
        .select_from(Asset)
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Asset.baseline_at.is_(None), Asset.tombstoned_at.is_(None))
    ).scalar_one()

    facets = {
        name: {"total": totals.get(name, 0), "matching": matching.get(name, 0)}
        for name in (
            "assessed", "unassessed", "kev", "malicious", "has_fix", "no_fix", "spread",
            "needs_attention", "cleared", "waiting",
            "exposure:internet", "exposure:internal",
            "exposure:isolated", "exposure:unknown",
            "band:critical", "band:high", "band:medium", "band:low",
            "band:informational", "band:unassessed",
        )
    }

    return Page(
        groups=groups,
        next_cursor=next_cursor,
        group_count=totals["total"],
        matching_group_count=matching["total"],
        instance_count=matching["instances"],
        assessed_count=matching["assessed_instances"],
        suppressed_group_count=suppressed,
        baseline_group_count=baselined,
        unbaselined_asset_count=unbaselined,
        facets=facets,
    )


def _benchmark_due(finding: Finding, vulnerability: Vulnerability, asset: Asset) -> dict:
    if vulnerability.malicious:
        return {"due": None, "due_on_upgrade": False, "due_rule": None,
                "forensic_triage": True}
    d = deadline.deadline(
        exposure=asset.exposure, kev=vulnerability.kev,
        kev_date_added=vulnerability.kev_date_added, vector=vulnerability.cvss_vector,
        cisa_ssvc=vulnerability.ssvc_cisa, first_seen=finding.first_seen.date(),
        kev_due_date=vulnerability.kev_due_date,
    )
    return {"due": d.due, "due_on_upgrade": d.due is None, "due_rule": d.due_rule,
            "forensic_triage": d.forensic_triage}


def _hydrate(
    session: Session, query: FindingQuery, group_keys: list[str], rows: list[Any]
) -> list[dict[str, Any]]:
    if not group_keys:
        return []

    stmt = _base(query).join(Component, Component.id == Finding.component_id)
    for pred in _facet_predicates(query):
        stmt = stmt.where(pred)
    instance_rows = session.execute(
        stmt.with_only_columns(Finding, Vulnerability, Asset, Component)
        .where(Finding.group_key.in_(group_keys))
        .order_by(Finding.risk_score.desc().nullslast(), Asset.display_name)
    ).all()

    by_group: dict[str, list[dict[str, Any]]] = {key: [] for key in group_keys}
    advisory: dict[str, Vulnerability] = {}
    for finding, vulnerability, asset, component in instance_rows:
        advisory.setdefault(finding.group_key, vulnerability)
        by_group.setdefault(finding.group_key, []).append(
            {
                "finding_id": str(finding.id),
                "investigated": finding.risk_band is not None,
                "risk_band": finding.risk_band,
                "risk_score": finding.risk_score,
                "confidence": finding.confidence,
                "triage_disposition": finding.triage_disposition,
                "triage_reason": finding.triage_reason,
                "asset_id": str(asset.id),
                "asset": asset.display_name,
                "exposure": asset.exposure,
                "asset_kind": asset.kind,
                "tier": asset.tier,
                "component": f"{component.name} {component.version}",
                "ecosystem": component.ecosystem,
                "fixed_version": finding.fixed_version,
                "fix_channel": finding.fix_channel,
                "state": finding.state,
                "match_method": finding.match_method,
                "match_confidence": finding.match_confidence,
                "observed_at": asset.last_inventoried_at,
                "ssvc": ssvc.decide(
                    kev=vulnerability.kev, exploit_public=vulnerability.exploit_public,
                    vector=vulnerability.cvss_vector, tier=asset.tier,
                    criticality=asset.criticality, malicious=vulnerability.malicious,
                    cisa=vulnerability.ssvc_cisa,
                ).outcome,
                **_benchmark_due(finding, vulnerability, asset),
            }
        )

    band_of = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "informational"}
    out: list[dict[str, Any]] = []
    for row in rows:
        vulnerability = advisory.get(row.group_key)
        out.append(
            {
                "group_key": row.group_key,
                "vulnerability_id": row.group_key,
                "summary": vulnerability.summary if vulnerability else None,
                "cvss_score": vulnerability.cvss_score if vulnerability else None,
                "epss_score": vulnerability.epss_score if vulnerability else None,
                "epss_percentile": vulnerability.epss_percentile if vulnerability else None,
                "kev": bool(row.kev),
                "kev_due_date": vulnerability.kev_due_date if vulnerability else None,
                "malicious": bool(row.malicious),
                "kev_ransomware": bool(vulnerability.kev_ransomware) if vulnerability else False,
                "published_at": row.published_at,
                "worst_band": band_of.get(row.worst_rank),
                "worst_score": row.worst_score,
                "instance_count": row.instance_count,
                "investigated_count": row.investigated_count,
                "instances": by_group.get(row.group_key, []),
            }
        )
    return out
