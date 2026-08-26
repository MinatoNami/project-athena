"""Suppression: deciding a finding does not need attention, and recording why.

The distinction this module exists to hold is between *suppressing* and *hiding*.
Hiding removes something from view. Suppressing records that a person looked at it
and judged it did not need attention **given what was true at the time** — and keeps
that premise, so the judgement can be re-checked when the situation moves.

Without the premise, a one-line "accepted, not exposed" outlives the isolation it
depended on, and the finding stays invisible through exactly the change that made it
matter. Capturing it is what lets an isolated service becoming internet-facing, or a
flaw joining the known-exploited catalogue, put the finding back in front of someone
with a stated reason.

Nothing here deletes a finding. Suppressed findings are excluded from the default
list and counted separately, the same way findings with no published fix are: held
back, never hidden.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from athena.audit import record
from athena.db.models import Asset, Finding, Suppression, Vulnerability

log = structlog.get_logger(__name__)

REASON_CODES = {
    "not_applicable": "The flaw cannot apply to this asset",
    "compensating_control": "Something else already prevents exploitation",
    "accepted_risk": "Understood and accepted for now",
    "false_positive": "The match itself is wrong",
    "fix_scheduled": "A fix is already planned",
}

# Long enough that a reader six months later has something to work with.
MIN_REASON = 8

# Accepted risk is the one reason that is a decision rather than a fact, so it is the
# one that must be revisited. The others describe the world and are re-checked by the
# premise; this one describes an appetite, and appetites go stale silently.
REQUIRES_EXPIRY = {"accepted_risk"}


class SuppressionError(ValueError):
    """Rejected for a stated reason the caller should show the operator."""


# ── premise ──────────────────────────────────────────────────────────────────


def capture_premise(session: Session, finding: Finding) -> dict[str, Any]:
    """The facts a suppression is standing on.

    Deliberately narrow. Every entry here is something whose change would undermine
    a normal reason for dismissing a finding; anything broader would invalidate
    suppressions on churn nobody cares about, and a suppression that keeps
    resurfacing for no reason gets replaced by one with no expiry at all.
    """
    asset = session.get(Asset, finding.asset_id)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    return {
        "exposure": asset.exposure if asset else "unknown",
        "tier": asset.tier if asset else "unknown",
        "kev": bool(vulnerability and vulnerability.kev),
        "advisory_revision": vulnerability.revision if vulnerability else 0,
        "fix_available": bool(finding.fixed_version),
    }


def premise_broken(premise: dict[str, Any], current: dict[str, Any]) -> str | None:
    """What changed, phrased for the person who will read it on the finding.

    Only changes that argue *against* the suppression count. A service becoming more
    isolated, or a flaw dropping off the exploited catalogue, does not invalidate a
    decision to dismiss it — reinstating findings because the situation improved
    would train people to ignore the mechanism.
    """
    exposure_rank = {"isolated": 0, "internal": 1, "unknown": 2, "internet": 3}
    tier_rank = {"personal": 0, "development": 1, "staging": 2, "unknown": 3, "production": 4}

    if not premise:
        return None

    was, now = premise.get("exposure", "unknown"), current.get("exposure", "unknown")
    if exposure_rank.get(now, 2) > exposure_rank.get(was, 2):
        return f"the asset moved from {was} to {now} exposure"

    was, now = premise.get("tier", "unknown"), current.get("tier", "unknown")
    if tier_rank.get(now, 3) > tier_rank.get(was, 3):
        return f"the asset moved from {was} to {now}"

    if current.get("kev") and not premise.get("kev"):
        return "the flaw is now listed as actively exploited"

    if current.get("fix_available") and not premise.get("fix_available"):
        return "a fix has since been published"

    if current.get("advisory_revision", 0) > premise.get("advisory_revision", 0):
        return "the advisory has been revised since this was dismissed"

    return None


# ── matching ─────────────────────────────────────────────────────────────────


def active_predicate(now: datetime | None = None) -> Any:
    """Is this suppression still in force?

    Expiry is evaluated here rather than by a sweep, so an expired suppression stops
    applying the moment it expires instead of the next time something happens to run.
    """
    moment = now or datetime.now(UTC)
    return and_(
        Suppression.revoked_at.is_(None),
        Suppression.invalidated_at.is_(None),
        or_(Suppression.expires_at.is_(None), Suppression.expires_at > moment),
    )


def scope_matches_finding() -> Any:
    """A null column widens the scope: null asset means any asset."""
    return and_(
        Suppression.vulnerability_id == Finding.vulnerability_id,
        or_(Suppression.asset_id.is_(None), Suppression.asset_id == Finding.asset_id),
        or_(Suppression.component_id.is_(None), Suppression.component_id == Finding.component_id),
    )


# ── operations ───────────────────────────────────────────────────────────────


def create_suppression(
    session: Session,
    *,
    finding: Finding,
    reason_code: str,
    reason: str,
    scope: str = "finding",
    expires_at: datetime | None = None,
    actor: str,
) -> Suppression:
    """Suppress, from the finding a person was looking at when they decided."""
    if reason_code not in REASON_CODES:
        raise SuppressionError(
            f"Unknown reason {reason_code!r} — expected one of {', '.join(sorted(REASON_CODES))}"
        )
    if len((reason or "").strip()) < MIN_REASON:
        raise SuppressionError(
            "A reason of at least eight characters is required: this is what somebody "
            "reads when the finding resurfaces, and 'n/a' tells them nothing."
        )
    if reason_code in REQUIRES_EXPIRY and expires_at is None:
        raise SuppressionError(
            "Accepted risk needs an expiry. It is a decision about appetite rather "
            "than a fact about the world, and nothing else will ever prompt a review."
        )
    if expires_at is not None and expires_at <= datetime.now(UTC):
        raise SuppressionError("An expiry in the past would suppress nothing.")

    if scope == "finding":
        asset_id, component_id = finding.asset_id, finding.component_id
    elif scope == "asset":
        asset_id, component_id = finding.asset_id, None
    elif scope == "everywhere":
        asset_id, component_id = None, None
    else:
        raise SuppressionError(
            f"Unknown scope {scope!r} — expected finding, asset or everywhere"
        )

    existing = session.execute(
        select(Suppression).where(
            Suppression.vulnerability_id == finding.vulnerability_id,
            Suppression.asset_id.is_(None) if asset_id is None else Suppression.asset_id == asset_id,
            Suppression.component_id.is_(None)
            if component_id is None
            else Suppression.component_id == component_id,
            active_predicate(),
        )
    ).scalars().first()
    if existing is not None:
        raise SuppressionError("An active suppression already covers this scope.")

    suppression = Suppression(
        vulnerability_id=finding.vulnerability_id,
        asset_id=asset_id,
        component_id=component_id,
        created_from_finding_id=finding.id,
        reason_code=reason_code,
        reason=reason.strip(),
        premise=capture_premise(session, finding),
        created_by=actor,
        expires_at=expires_at,
    )
    session.add(suppression)
    session.flush()

    record(
        session,
        actor=actor,
        action="FINDING_SUPPRESSED",
        subject=f"suppression:{suppression.id}",
        detail={
            "vulnerability": finding.vulnerability_id,
            "scope": scope,
            "reason_code": reason_code,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "premise": suppression.premise,
        },
    )
    return suppression


def revoke_suppression(session: Session, *, suppression: Suppression, actor: str) -> Suppression:
    """Put the finding back deliberately. Revocation is kept, never deleted."""
    if suppression.revoked_at is not None:
        raise SuppressionError("This suppression has already been revoked.")
    suppression.revoked_at = datetime.now(UTC)
    suppression.revoked_by = actor
    record(
        session,
        actor=actor,
        action="SUPPRESSION_REVOKED",
        subject=f"suppression:{suppression.id}",
        detail={"vulnerability": suppression.vulnerability_id},
    )
    return suppression


def review_suppressions(session: Session) -> dict[str, Any]:
    """Re-check every live suppression against the world as it is now.

    Runs on a sweep rather than at query time because invalidation is an event worth
    recording — the operator should be able to see that a decision was overturned and
    why, not merely notice a finding reappearing.
    """
    live = session.execute(
        select(Suppression).where(
            Suppression.revoked_at.is_(None), Suppression.invalidated_at.is_(None)
        )
    ).scalars().all()

    invalidated = 0
    for suppression in live:
        findings = session.execute(
            select(Finding).where(
                Finding.vulnerability_id == suppression.vulnerability_id,
                *( [Finding.asset_id == suppression.asset_id] if suppression.asset_id else [] ),
                *(
                    [Finding.component_id == suppression.component_id]
                    if suppression.component_id
                    else []
                ),
            )
        ).scalars().all()
        if not findings:
            continue

        # The scope may cover many findings; the strongest argument against the
        # suppression wins, because one exposed asset is enough to undo it.
        broken: str | None = None
        for finding in findings:
            reason = premise_broken(suppression.premise, capture_premise(session, finding))
            if reason:
                broken = reason
                break
        if not broken:
            continue

        suppression.invalidated_at = datetime.now(UTC)
        suppression.invalidated_reason = broken
        invalidated += 1
        record(
            session,
            actor="system",
            action="SUPPRESSION_INVALIDATED",
            subject=f"suppression:{suppression.id}",
            detail={"vulnerability": suppression.vulnerability_id, "because": broken},
        )
        log.info(
            "suppression.invalidated",
            suppression=str(suppression.id),
            vulnerability=suppression.vulnerability_id,
            because=broken,
        )

    return {"reviewed": len(live), "invalidated": invalidated}
