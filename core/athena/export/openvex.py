"""OpenVEX: per-finding exploitability statements, for tools that consume them.

The status rules, in order:

1. A verified resolution is `fixed`.
2. A person's live suppression decides next, because it is the only thing in the
   system that is a human judgement about *this* finding:
   `not_applicable`, `compensating_control` and `false_positive` become
   `not_affected`; `accepted_risk` and `fix_scheduled` stay `affected`, with the
   decision as the action statement.
3. Malware is `affected`. Nothing short of a person can say otherwise.
4. An investigation that found it applicable is `affected`.
5. Everything else is `under_investigation` — including an automated verdict of
   "not applicable", which is reported in the notes and not asserted. A downstream
   scanner would silently drop the finding on the strength of a `not_affected`,
   which would make the model the authority on what other tools are allowed to see.

`not_affected` without a justification is permitted by the spec only with an impact
statement, so every human-sourced one carries the operator's own words, and the
justification enum is used only where the reason code actually means it.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena import __version__
from athena.db.models import (
    Asset,
    Component,
    Finding,
    InvestigationRecord,
    Suppression,
    Vulnerability,
)
from athena.export.cyclonedx import component_purl
from athena.remediation.source import image_name
from athena.suppression.service import active_predicate

CONTEXT = "https://openvex.dev/ns/v0.2.0"

NOT_AFFECTED_CODES = {"not_applicable", "compensating_control", "false_positive"}

# Only where the reason code *is* the justification. The rest carry an impact
# statement in the operator's words instead of a category we would be guessing at.
JUSTIFICATION = {"compensating_control": "inline_mitigations_already_exist"}


def product_id(asset: Asset) -> str:
    """The identifier a consuming scanner will match the product on.

    An image is a `pkg:oci` purl on its digest — what Trivy and Grype compare when
    they apply a VEX to an image scan. Anything else has no standard identifier
    Athena can vouch for, so it gets a URN that is honest about being Athena's own.
    """
    if asset.kind == "image":
        digest = asset.attributes.get("digest") or (
            asset.identity_key if asset.identity_key.startswith("sha256:") else None
        )
        name = image_name(asset)
        if digest and name:
            short = name.rsplit("/", 1)[-1]
            purl = f"pkg:oci/{quote(short, safe='')}@{quote(digest, safe='')}"
            if "/" in name:
                purl += f"?repository_url={quote(name, safe='')}"
            return purl
    if asset.kind == "repository":
        url = asset.attributes.get("url") or asset.attributes.get("clone_url")
        if url and (public := public_repository_url(url)):
            return public
    return f"urn:athena:asset:{asset.id}"


def public_repository_url(url: str) -> str | None:
    """A clone URL with nothing in it that is not the repository's address.

    The clone URL is stored as the operator gave it, and that is often
    `https://x-access-token:ghp_…@host/org/repo.git`. This document is built to leave
    Athena, so user info, query and fragment are dropped, and an scp-style
    `git@host:org/repo` becomes a URL an IRI consumer can read.
    """
    url = url.strip()
    scp = re.match(r"^[^@/]+@(?P<host>[^:/]+):(?P<path>.+)$", url)
    if scp and "://" not in url:
        return f"ssh://{scp.group('host')}/{scp.group('path').lstrip('/')}"
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    netloc = parts.hostname + (f":{port}" if port else "")
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _statement(
    *,
    finding: Finding,
    vulnerability: Vulnerability,
    asset: Asset,
    component: Component,
    suppression: Suppression | None,
    verdict: str | None,
    action: str | None,
) -> dict[str, Any]:
    subcomponent = component_purl(component)
    product: dict[str, Any] = {"@id": product_id(asset)}
    if subcomponent:
        product["subcomponents"] = [{"@id": subcomponent}]

    statement: dict[str, Any] = {
        "vulnerability": {
            "name": vulnerability.id,
            **({"aliases": sorted(vulnerability.aliases)} if vulnerability.aliases else {}),
        },
        "products": [product],
        "timestamp": (finding.state_changed_at or datetime.now(UTC)).isoformat(),
    }

    if finding.state == "resolved":
        statement["status"] = "fixed"
        statement["status_notes"] = "Resolution verified by Athena."
        return statement

    if suppression is not None:
        decided = (
            f"Decided by {suppression.created_by} on {suppression.created_at.date().isoformat()}"
        )
        if suppression.reason_code in NOT_AFFECTED_CODES:
            statement["status"] = "not_affected"
            if (justification := JUSTIFICATION.get(suppression.reason_code)) is not None:
                statement["justification"] = justification
            statement["impact_statement"] = suppression.reason
            statement["status_notes"] = f"{decided} ({suppression.reason_code})."
            return statement
        statement["status"] = "affected"
        until = (
            f" until {suppression.expires_at.date().isoformat()}" if suppression.expires_at else ""
        )
        statement["action_statement"] = (
            f"{suppression.reason_code.replace('_', ' ').capitalize()}{until}: {suppression.reason}"
        )
        statement["status_notes"] = f"{decided}."
        return statement

    if vulnerability.malicious:
        statement["status"] = "affected"
        statement["action_statement"] = action or (
            "Published malware: remove it and treat the asset as compromised."
        )
        return statement

    if verdict == "applicable":
        statement["status"] = "affected"
        statement["action_statement"] = action or (
            f"Upgrade {component.name} to {finding.fixed_version}."
            if finding.fixed_version
            else "No fixed version has been published yet."
        )
        return statement

    statement["status"] = "under_investigation"
    if verdict == "not_applicable":
        statement["status_notes"] = (
            "Athena's automated investigation concluded this does not apply. No "
            "person has confirmed that, so it is not asserted as not_affected."
        )
    elif verdict == "uncertain":
        statement["status_notes"] = "Investigated; the evidence was inconclusive."
    else:
        statement["status_notes"] = "Matched by version only; not yet investigated on this asset."
    return statement


def vex_document(
    session: Session,
    *,
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    author: str = "Athena",
) -> dict[str, Any]:
    """One OpenVEX document covering every finding in scope."""
    from athena.remediation import plan_for, source_for

    stmt = (
        select(Finding, Vulnerability, Asset, Component, InvestigationRecord.verdict)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Component, Component.id == Finding.component_id)
        .outerjoin(InvestigationRecord, InvestigationRecord.id == Finding.investigation_id)
        .where(Asset.tombstoned_at.is_(None))
        # A withdrawn advisory is its publisher retracting it, and the findings
        # queue already stops ranking one. Exporting it anyway would publish the
        # retraction's opposite — a withdrawn malware report still carries
        # `malicious`, so it would leave as `affected`, "treat the asset as
        # compromised", for other scanners to act on. It is left out, not marked
        # `not_affected`: that status belongs to a person's decision (rule 2).
        .where(Vulnerability.withdrawn_at.is_(None))
        .order_by(Finding.vulnerability_id, Asset.display_name, Component.name)
    )
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if vulnerability_id:
        stmt = stmt.where(Finding.vulnerability_id == vulnerability_id)
    rows = session.execute(stmt).all()

    # Live suppressions, most specific first, so a finding-scoped decision wins over
    # an estate-wide one for the same vulnerability.
    suppressions = (
        session.execute(
            select(Suppression)
            .where(active_predicate())
            .where(Suppression.vulnerability_id.in_({r[0].vulnerability_id for r in rows} or {""}))
        )
        .scalars()
        .all()
    )

    def suppression_for(finding: Finding) -> Suppression | None:
        matches = [
            s
            for s in suppressions
            if s.vulnerability_id == finding.vulnerability_id
            and (s.asset_id is None or s.asset_id == finding.asset_id)
            and (s.component_id is None or s.component_id == finding.component_id)
        ]
        matches.sort(key=lambda s: (s.asset_id is None, s.component_id is None))
        return matches[0] if matches else None

    statements = []
    for finding, vulnerability, asset, component, verdict in rows:
        action = None
        if verdict == "applicable" or vulnerability.malicious:
            action = plan_for(
                ecosystem=component.ecosystem,
                package=component.name,
                installed_version=component.version,
                fixed_version=finding.fixed_version,
                asset_kind=asset.kind,
                asset_name=asset.display_name,
                scope=None,
                fix_channel=finding.fix_channel,
                source=source_for(session, asset),
                malicious=vulnerability.malicious,
            ).summary
        statements.append(
            _statement(
                finding=finding,
                vulnerability=vulnerability,
                asset=asset,
                component=component,
                suppression=suppression_for(finding),
                verdict=verdict,
                action=action,
            )
        )

    return {
        "@context": CONTEXT,
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": author,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "version": 1,
        "tooling": f"athena/{__version__}",
        "statements": statements,
    }


__all__ = ["product_id", "public_repository_url", "vex_document"]
