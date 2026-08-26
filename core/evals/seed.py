"""Build and tear down the database fixture for one case.

Eval rows live in the same database as real ones, distinguished by an `EVAL-` prefix
on advisory ids and an `eval:` prefix on asset identity keys. Everything carrying
those markers is removed before and after a run, so an interrupted run cannot leave
fixtures behind to be mistaken for findings about real machines.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, text

from athena.db.base import session_scope
from athena.db.models import (
    AffectedRange,
    Asset,
    AssetComponent,
    AssetEdge,
    Component,
    Finding,
    InvestigationRecord,
    Vulnerability,
)
from athena.intel.authority import SOURCE_AUTHORITY, Authority
from athena.investigation.loop import context_fingerprint

# Which feed a range of this shape would really have come from. Getting this right
# matters: authority decides which range wins when several describe one package, and a
# fixture that lied about its provenance would exercise a path production never takes.
DEFAULT_SOURCE = {"deb": "ubuntu", "rpm": "redhat", "apk": "alpine"}

EVAL_ADVISORY_PREFIX = "EVAL-"
EVAL_IDENTITY_PREFIX = "eval:"
# Fixed sentinel: every eval-seeded AssetComponent traces to the same "scan run",
# which makes eval rows recognisable in the database without a join.
EVAL_SCAN_RUN = uuid.UUID("00000000-0000-0000-0000-00000000e7a1")


def _asset(session, case, *, kind: str, suffix: str, spec: dict[str, Any]) -> Asset:
    asset = Asset(
        kind=kind,
        identity_key=f"{EVAL_IDENTITY_PREFIX}{case.id}:{suffix}",
        display_name=spec.get("display_name", suffix),
        tier=spec.get("tier", "unknown"),
        exposure=spec.get("exposure", "unknown"),
        criticality=spec.get("criticality"),
        attributes=spec.get("attributes", {}),
        last_inventoried_at=datetime.now(UTC),
    )
    session.add(asset)
    return asset


def build(case) -> dict[str, Any]:
    """Create the rows one case needs. Returns the ids the harness reads back."""
    now = datetime.now(UTC)
    with session_scope() as session:
        host = _asset(session, case, kind=case.asset.get("kind", "host"),
                      suffix="asset", spec=case.asset)

        # Services are assets in their own right, linked to the host. The listening-
        # port tool reads them, so a case claiming network exposure must seed one —
        # otherwise the case would be asking the model to assert what it cannot see.
        for index, svc in enumerate(case.services):
            service = _asset(
                session, case, kind="service", suffix=f"svc{index}",
                spec={
                    "display_name": svc.get("name", f"service-{index}"),
                    "tier": case.asset.get("tier", "unknown"),
                    "exposure": svc.get("exposure", case.asset.get("exposure", "unknown")),
                    "attributes": {
                        "port": svc.get("port"),
                        "protocol": svc.get("protocol", "tcp"),
                        "address": svc.get("address"),
                        "process": svc.get("process"),
                        "process_known": bool(svc.get("process")),
                    },
                },
            )
            session.flush()
            session.add(AssetEdge(src_id=service.id, dst_id=host.id,
                                  relation="runs_on", observed_at=now))

        component = Component(
            ecosystem=case.component["ecosystem"],
            name=case.component["name"],
            version=case.component["version"],
            purl=f"pkg:{case.component['ecosystem']}/"
                 f"{case.component['name']}@{case.component['version']}",
        )
        session.add(component)
        session.flush()

        session.add(AssetComponent(
            asset_id=host.id, component_id=component.id,
            scope=case.component.get("scope", "os"),
            install_path=case.component.get("install_path"),
            is_running=case.component.get("is_running"),
            observed_at=now, scan_run_id=EVAL_SCAN_RUN,
        ))

        adv = case.advisory
        if not adv["id"].startswith(EVAL_ADVISORY_PREFIX):
            raise ValueError(f"{case.id}: advisory id must start with {EVAL_ADVISORY_PREFIX}")
        vulnerability = Vulnerability(
            id=adv["id"],
            summary=" ".join(adv.get("summary", "").split()),
            details=adv.get("details"),
            severity=adv.get("severity"),
            cvss_score=adv.get("cvss_score"),
            cvss_vector=adv.get("cvss_vector"),
            cwe=adv.get("cwe", []),
            epss_score=adv.get("epss"),
            kev=adv.get("kev", False),
            exploit_public=adv.get("exploit_public", False),
            published_at=now,
            content_hash=f"eval-{case.id}",
            revision=1,
        )
        session.add(vulnerability)
        session.flush()   # the range's foreign key needs the advisory to exist first
        ecosystem = case.component["ecosystem"]
        source = adv.get("source") or DEFAULT_SOURCE.get(ecosystem, "osv")
        session.add(AffectedRange(
            vulnerability_id=vulnerability.id,
            ecosystem=ecosystem,
            package=case.component["name"],
            introduced="0",
            fixed=case.fixed_version,
            source=source,
            authority=int(SOURCE_AUTHORITY.get(source, Authority.HEURISTIC)),
            distro=case.asset.get("attributes", {}).get("distro"),
            distro_release=case.asset.get("attributes", {}).get("distro_release"),
            channel="standard",
            source_record=vulnerability.id,
        ))

        finding = Finding(
            group_key=f"{vulnerability.id}:{case.component['name']}",
            vulnerability_id=vulnerability.id,
            asset_id=host.id,
            component_id=component.id,
            state="discovered",
            match_method="purl",
            match_confidence=1.0,
            fixed_version=case.fixed_version,
            fix_channel="standard",
            advisory_revision=1,
            first_seen=now,
            state_changed_at=now,
        )
        session.add(finding)
        session.flush()

        fingerprint = context_fingerprint({
            "vulnerability": vulnerability.id,
            "revision": 1,
            "purl": component.purl,
            "tier": host.tier,
            "exposure": host.exposure,
            "release": host.attributes.get("distro_release"),
            "fixed_in": case.fixed_version,
        })
        return {
            "finding_id": str(finding.id),
            "asset_id": str(host.id),
            "component_id": str(component.id),
            "vulnerability_id": vulnerability.id,
            "fingerprint": fingerprint,
        }


def clear() -> int:
    """Remove every eval row. Safe to call when none exist."""
    with session_scope() as session:
        vuln_ids = session.execute(
            select(Vulnerability.id).where(Vulnerability.id.like(f"{EVAL_ADVISORY_PREFIX}%"))
        ).scalars().all()
        asset_ids = session.execute(
            select(Asset.id).where(Asset.identity_key.like(f"{EVAL_IDENTITY_PREFIX}%"))
        ).scalars().all()

        if vuln_ids:
            session.execute(
                delete(InvestigationRecord)
                .where(InvestigationRecord.vulnerability_id.in_(vuln_ids))
            )
        if asset_ids:
            component_ids = session.execute(
                select(AssetComponent.component_id)
                .where(AssetComponent.asset_id.in_(asset_ids))
            ).scalars().all()
            session.execute(delete(Finding).where(Finding.asset_id.in_(asset_ids)))
            session.execute(
                delete(AssetEdge).where(
                    AssetEdge.src_id.in_(asset_ids) | AssetEdge.dst_id.in_(asset_ids)
                )
            )
            session.execute(
                delete(AssetComponent).where(AssetComponent.asset_id.in_(asset_ids))
            )
            session.execute(delete(Asset).where(Asset.id.in_(asset_ids)))
            if component_ids:
                session.execute(delete(Component).where(Component.id.in_(component_ids)))
        if vuln_ids:
            session.execute(
                delete(AffectedRange).where(AffectedRange.vulnerability_id.in_(vuln_ids))
            )
            session.execute(delete(Vulnerability).where(Vulnerability.id.in_(vuln_ids)))

        # Evidence rows reference findings that are gone; the audit chain is append-only
        # and is deliberately left intact — an eval run is a real thing that happened.
        session.execute(text(
            "DELETE FROM evidence WHERE finding_id NOT IN (SELECT id FROM finding)"
        ))
        return len(asset_ids) + len(vuln_ids)
