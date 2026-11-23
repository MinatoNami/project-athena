"""Server-side querying for the findings list.

The list used to be assembled in Python: fetch `limit * 20` finding rows, group
them in memory, sort, keep the first `limit` groups. That worked only while the
whole estate fitted inside the slice. Worse, the row query carried no ORDER BY, so
once it did not fit, *which* findings came back was whatever the database happened
to return — a silent, non-deterministic truncation rather than a visible limit.

Everything that decides what appears therefore happens in SQL: filtering,
roll-up to the group, ordering, and the page boundary.

Two things are deliberate.

Grouping is by vulnerability, and a group takes the **worst** of its instances
rather than an average. Risk is scored per instance because the same flaw is
critical on an internet-facing host and informational on a laptop; averaging that
back together would hide exactly the instance worth looking at.

Facet counts come back as two numbers: how many groups exist at all, and how many
survive the filters currently applied. One number cannot answer both "what am I
looking at" and "what am I excluding", and this product is largely about never
letting a filtered view read as a complete one.
"""

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

# Assessed bands outrank unassessed: a measured band is a stronger claim than an
# advisory's opinion, in either direction. -1 keeps "never looked at" below
# "looked at and found harmless", which are different statements.
_BAND_RANK = case(
    (Finding.risk_band == "critical", 4),
    (Finding.risk_band == "high", 3),
    (Finding.risk_band == "medium", 2),
    (Finding.risk_band == "low", 1),
    (Finding.risk_band == "informational", 0),
    else_=-1,
)

# The advisory's own view, used only to break ties between unassessed groups.
# Distribution advisories usually carry a word rather than a vector, so the label is
# read when no score exists — without that the list ties at zero and degenerates to
# alphabetical order by CVE id.
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
    """Everything that can narrow the list. Empty means "the default view"."""

    # Structural: these define the population, not a user's filter, and facet
    # totals are counted against them.
    state: str | None = None
    asset_id: str | None = None
    include_no_fix: bool = False
    # Suppressed findings are excluded by default and counted separately — held
    # back, never hidden, the same treatment as findings with no published fix.
    include_suppressed: bool = False
    # Pre-existing findings are excluded by default and counted separately. A
    # baseline is a lens, not a dismissal: nothing is hidden and nothing needed a
    # reason, so unlike suppression it takes one parameter to see all of it again.
    include_baseline: bool = False

    # Facets.
    q: str | None = None
    assessed: bool | None = None
    kev: bool = False
    # OpenSSF malicious-packages records. A facet of its own because the response is
    # incident handling, not patching, and it is a different person's morning.
    malicious: bool = False
    exposure: str | None = None
    tier: str | None = None
    has_fix: bool | None = None
    min_band: str | None = None
    # The triage queue's population, named once here rather than reconstructed by
    # every caller: assessed at medium or above, or known-exploited whatever its
    # assessment. The second half matters — a known-exploited flaw nobody has looked
    # at is the strongest reason to look at something, and a queue defined purely on
    # measured band would rank it nowhere.
    # True: the triage queue. False: everything outside it — which is what "cleared"
    # and "waiting" mean on Today, so the three tabs partition the estate instead of
    # overlapping (a known-exploited critical was in both "needs you" and "cleared").
    needs_attention: bool | None = None

    sort: str = "risk"
    cursor: str | None = None
    limit: int = DEFAULT_LIMIT

    def facets_active(self) -> bool:
        return any(
            (
                self.q,
                self.assessed is not None,
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


# ── scoping ──────────────────────────────────────────────────────────────────


def _base(query: FindingQuery) -> Select:
    """The joined population, before any user facet is applied."""
    stmt = (
        select(Finding, Vulnerability, Asset)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .join(Asset, Asset.id == Finding.asset_id)
    )
    if query.state:
        stmt = stmt.where(Finding.state == query.state)
    elif not query.include_no_fix:
        # Default view is work that can actually be done. Findings with no published
        # fix are real, but they are not action — shown on request, counted always.
        stmt = stmt.where(Finding.state != "no_fix_available")
    if query.asset_id:
        stmt = stmt.where(Finding.asset_id == query.asset_id)
    # A withdrawn advisory is its publisher saying it was wrong — in May 2026 OSV
    # withdrew 157 malware reports that an automated detector had raised in error.
    # Correlation already stops creating findings from one; this stops the ones it
    # created earlier from going on ranking, which for a malware record meant a
    # retracted accusation holding the top of the queue at critical.
    stmt = stmt.where(Vulnerability.withdrawn_at.is_(None))
    if not query.include_suppressed:
        stmt = stmt.where(~_suppressed_exists())
    if not query.include_baseline:
        stmt = stmt.where(_is_new())
    return stmt


def _is_new() -> Any:
    """Not part of the backlog this asset was accepted with.

    The escape clause is the important half. A known-exploited flaw, or one measured
    at high or critical, is not "state I inherited and accepted" — it is an emergency
    that happens to be old, and a baseline that swallowed it would be doing exactly
    what the wall of red does, only quietly.
    """
    return or_(
        Asset.baseline_at.is_(None),
        Finding.first_seen > Asset.baseline_at,
        Vulnerability.kev.is_(True),
        Vulnerability.malicious.is_(True),
        _BAND_RANK >= 3,
    )


def _suppressed_exists() -> Any:
    """Does a live suppression cover this finding?

    Correlated on the finding rather than joined: a finding can be covered by more
    than one suppression — an exact one and a broader one — and a join would return
    it once per match, inflating every instance count that touched it.
    """
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
    """Expressed over the group, because either half can be true of any instance."""
    return or_(
        func.max(_BAND_RANK) >= 2,
        func.max(func.cast(Vulnerability.kev, Integer)) > 0,
        # Malware needs a person whether or not anything has assessed it yet.
        func.max(func.cast(Vulnerability.malicious, Integer)) > 0,
    )


# ── aggregation ──────────────────────────────────────────────────────────────

# `group_key` is the vulnerability id, so every finding in a group shares one
# advisory and max() over its columns is the value, not an approximation.
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
    # Exposure is a property of the instance, rolled up as "does any instance have
    # it". Counting it outside this aggregate meant it never saw the HAVING clauses,
    # so a group-level filter left the exposure counts untouched.
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

    # `assessed` and `has_fix` are properties of the GROUP, not of a row: a group
    # counts as assessed when any instance was investigated, and as fixable when any
    # instance has a published fix. They therefore belong in HAVING.
    if with_facets:
        if query.assessed is True:
            grouped = grouped.having(func.count(Finding.investigation_id) > 0)
        elif query.assessed is False:
            grouped = grouped.having(func.count(Finding.investigation_id) == 0)
        if query.has_fix is True:
            grouped = grouped.having(func.count(Finding.fixed_version) > 0)
        elif query.has_fix is False:
            grouped = grouped.having(func.count(Finding.fixed_version) == 0)
        if query.needs_attention is True:
            grouped = grouped.having(_needs_attention_having())
        elif query.needs_attention is False:
            grouped = grouped.having(~_needs_attention_having())
    return grouped


# ── ordering and the page boundary ───────────────────────────────────────────


def _sort_columns(sub: Any, sort: str) -> list[Any]:
    """Ordering expressed so every column ascends.

    Keyset pagination compares the sort tuple against the cursor with a single
    row-value comparison, which has no way to mix ASC and DESC. Negating the
    descending columns makes them all ascend, so one comparison is enough and the
    page boundary cannot drift from the ORDER BY.
    """
    if sort == "spread":
        return [-sub.c.instance_count, -sub.c.worst_rank, sub.c.group_key]
    if sort == "recent":
        # NULL published_at sorts last rather than first: an advisory with no date is
        # not a new one.
        return [
            func.coalesce(func.extract("epoch", sub.c.published_at), 0) * -1,
            sub.c.group_key,
        ]
    # Malware leads the risk order whatever its assessment: it is a compromise in
    # progress, and an unassessed one would otherwise rank below assessed lows.
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
    """A cursor that cannot be read is ignored, never fatal.

    It is an opaque token the client is not expected to construct, so a stale or
    mangled one should return the first page rather than an error page.
    """
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        values = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return values if isinstance(values, list) and len(values) == width else None


# ── facet counting ───────────────────────────────────────────────────────────


def _facet_counts(session: Session, query: FindingQuery, *, with_facets: bool) -> dict[str, int]:
    """Group counts per facet, in one pass.

    Counted over groups rather than findings, because a group is one decision — the
    number a person is choosing between.
    """
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
            # The other two Today tabs, disjoint from the queue and from each other.
            func.count()
            .filter(
                (sub.c.investigated_count > 0)
                & ~((sub.c.worst_rank >= 2) | (sub.c.kev > 0) | (sub.c.malicious > 0))
            )
            .label("cleared"),
            func.count()
            .filter(
                (sub.c.investigated_count == 0)
                & ~((sub.c.worst_rank >= 2) | (sub.c.kev > 0) | (sub.c.malicious > 0))
            )
            .label("waiting"),
            *[
                func.count().filter(sub.c[f"exposure_{value}"] > 0).label(f"exposure:{value}")
                for value in ("internet", "internal", "isolated", "unknown")
            ],
            # The worst band each group reached, counted across the estate. `-1` is
            # its own bucket rather than folded into `informational`: a group nothing
            # has assessed has no band, and charting it as the mildest one would be
            # the "unknown rendered as clean" this product exists to refuse.
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


# ── the query ────────────────────────────────────────────────────────────────


def query_findings(session: Session, query: FindingQuery) -> Page:
    limit = max(1, min(query.limit, MAX_LIMIT))
    sub = _grouped(query, with_facets=True).subquery()
    order = _sort_columns(sub, query.sort if query.sort in SORTS else "risk")

    stmt = select(sub).order_by(*order)
    if query.cursor:
        after = _decode(query.cursor, len(order))
        if after is not None:
            stmt = stmt.where(tuple_(*order) > tuple_(*[literal(v) for v in after]))

    # One extra row tells us whether another page exists without a second count.
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

    # Counted even when excluded. An operator must be able to see how much has been
    # dismissed without having to go looking for it.
    suppressed = session.execute(
        select(func.count(func.distinct(Finding.group_key)))
        .select_from(Finding)
        .where(_suppressed_exists())
    ).scalar_one()

    # Held back, never hidden: the size of the inherited backlog stays a number on
    # the page rather than something to go looking for.
    baselined = session.execute(
        select(func.count(func.distinct(Finding.group_key)))
        .select_from(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(~_is_new())
    ).scalar_one()

    # Assets carrying findings that nobody has drawn a line under yet. This is what
    # tells the UI whether offering a baseline would do anything.
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
        # Instance totals describe the whole matching set, not this page: they are the
        # denominator for "how much of what I am looking at has been assessed", and a
        # per-page denominator would answer a question nobody asked.
        instance_count=matching["instances"],
        assessed_count=matching["assessed_instances"],
        suppressed_group_count=suppressed,
        baseline_group_count=baselined,
        unbaselined_asset_count=unbaselined,
        facets=facets,
    )


def _benchmark_due(finding: Finding, vulnerability: Vulnerability, asset: Asset) -> dict:
    """The BOD 26-04 benchmark date for one instance, for the list's due column."""
    if vulnerability.malicious:
        # Outside the directive's model: malware is removed now, not on a timeline.
        return {"due": None, "due_on_upgrade": False, "forensic_triage": True}
    d = deadline.deadline(
        exposure=asset.exposure, kev=vulnerability.kev,
        kev_date_added=vulnerability.kev_date_added, vector=vulnerability.cvss_vector,
        cisa_ssvc=vulnerability.ssvc_cisa, first_seen=finding.first_seen.date(),
    )
    return {"due": d.due, "due_on_upgrade": d.days is None,
            "forensic_triage": d.forensic_triage}


def _hydrate(
    session: Session, query: FindingQuery, group_keys: list[str], rows: list[Any]
) -> list[dict[str, Any]]:
    """Fetch the instances for one page of groups, and only those.

    Instances are fetched under the same facet predicates that selected the groups —
    filtering to internet-facing assets and then listing every asset would answer a
    different question from the one asked.
    """
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
                # An investigated finding has a real band and a confidence behind it.
                # One that has not been looked at has neither, and must not borrow the
                # advisory's severity to look as though it had.
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
                # When the facts this rests on were last read (rule 2: freshness is
                # always visible). Inherited image scans count, as in coverage.
                "observed_at": asset.last_inventoried_at,
                # Computed per instance, like the score: the same flaw is "Act" on a
                # critical production host and "Track" on a laptop.
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
