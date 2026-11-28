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

JUSTIFICATION = {"compensating_control": "inline_mitigations_already_exist"}


def product_id(asset: Asset) -> str:
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
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    netloc = host + (f":{port}" if port else "")
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
    from athena.remediation import plan_for, source_for

    stmt = (
        select(Finding, Vulnerability, Asset, Component, InvestigationRecord.verdict)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .join(Asset, Asset.id == Finding.asset_id)
        .join(Component, Component.id == Finding.component_id)
        .outerjoin(InvestigationRecord, InvestigationRecord.id == Finding.investigation_id)
        .where(Asset.tombstoned_at.is_(None))
        .where(Vulnerability.withdrawn_at.is_(None))
        .where(Finding.state != "unmatched")
        .order_by(Finding.vulnerability_id, Asset.display_name, Component.name)
    )
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if vulnerability_id:
        stmt = stmt.where(Finding.vulnerability_id == vulnerability_id)
    rows = session.execute(stmt).all()

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
