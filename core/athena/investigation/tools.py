from __future__ import annotations

from collections.abc import Callable
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from athena.db.models import (
    Asset,
    AssetComponent,
    AssetEdge,
    Component,
    Finding,
    Vulnerability,
)

log = structlog.get_logger(__name__)

MAX_ROWS = 50


class ToolError(RuntimeError):
    pass


def _asset(session: Session, asset_id: str) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise ToolError(f"No asset {asset_id}")
    return asset


def get_asset(session: Session, *, asset_id: str) -> dict[str, Any]:
    asset = _asset(session, asset_id)
    return {
        "display_name": asset.display_name,
        "kind": asset.kind,
        "tier": asset.tier,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "os": asset.attributes.get("os_version"),
        "distro": asset.attributes.get("distro"),
        "distro_release": asset.attributes.get("distro_release"),
        "last_inventoried_at": (
            asset.last_inventoried_at.isoformat() if asset.last_inventoried_at else None
        ),
        "never_inventoried": asset.last_inventoried_at is None,
    }


def list_listening_ports(session: Session, *, asset_id: str) -> dict[str, Any]:
    asset = _asset(session, asset_id)
    rows = session.execute(
        select(Asset)
        .join(AssetEdge, AssetEdge.src_id == Asset.id)
        .where(AssetEdge.dst_id == asset.id, Asset.kind == "service")
        .limit(MAX_ROWS)
    ).scalars().all()
    return {
        "count": len(rows),
        "services": [
            {
                "name": s.display_name,
                "port": s.attributes.get("port"),
                "protocol": s.attributes.get("protocol"),
                "address": s.attributes.get("address"),
                "exposure": s.exposure,
                "process": s.attributes.get("process"),
                "process_known": s.attributes.get("process_known", False),
            }
            for s in rows
        ],
    }


def get_component(session: Session, *, component_id: str) -> dict[str, Any]:
    component = session.get(Component, component_id)
    if component is None:
        raise ToolError(f"No component {component_id}")
    scopes = session.execute(
        select(AssetComponent.scope, AssetComponent.is_running, AssetComponent.install_path)
        .where(AssetComponent.component_id == component.id)
        .limit(MAX_ROWS)
    ).all()
    return {
        "name": component.name,
        "version": component.version,
        "ecosystem": component.ecosystem,
        "purl": component.purl,
        "installations": [
            {"scope": s, "is_running": r, "path": p} for s, r, p in scopes
        ],
    }


def get_advisory(session: Session, *, vulnerability_id: str) -> dict[str, Any]:
    vulnerability = session.get(Vulnerability, vulnerability_id)
    if vulnerability is None:
        raise ToolError(f"No advisory {vulnerability_id}")
    return {
        "id": vulnerability.id,
        "aliases": vulnerability.aliases[:10],
        "summary": vulnerability.summary,
        "details": (vulnerability.details or "")[:4000],
        "cvss_vector": vulnerability.cvss_vector,
        "cvss_score": vulnerability.cvss_score,
        "severity": vulnerability.severity,
        "cwe": vulnerability.cwe,
        "known_exploited": vulnerability.kev,
        **({"malicious_package": True} if vulnerability.malicious else {}),
        "epss": vulnerability.epss_score,
        "published_at": (
            vulnerability.published_at.isoformat() if vulnerability.published_at else None
        ),
    }


def count_affected_assets(session: Session, *, vulnerability_id: str) -> dict[str, Any]:
    rows = session.execute(
        text(
            "SELECT a.tier, count(*) AS n FROM finding f "
            "  JOIN asset a ON a.id = f.asset_id "
            " WHERE f.vulnerability_id = :v AND f.state <> 'unmatched' GROUP BY a.tier"
        ),
        {"v": vulnerability_id},
    ).all()
    return {"by_tier": {tier: n for tier, n in rows}, "total": sum(n for _, n in rows)}


def get_related_findings(session: Session, *, asset_id: str) -> dict[str, Any]:
    rows = session.execute(
        select(Finding.vulnerability_id, Finding.state, Finding.risk_band)
        .where(Finding.asset_id == asset_id)
        .limit(MAX_ROWS)
    ).all()
    return {
        "count": len(rows),
        "findings": [{"id": v, "state": s, "band": b} for v, s, b in rows],
    }


TOOLS: dict[str, Callable[..., dict[str, Any]]] = {
    "get_asset": get_asset,
    "list_listening_ports": list_listening_ports,
    "get_component": get_component,
    "get_advisory": get_advisory,
    "count_affected_assets": count_affected_assets,
    "get_related_findings": get_related_findings,
}

TOOL_DESCRIPTIONS = {
    "get_asset": "Facts about the asset: tier, exposure, OS, and how recently it was inventoried.",
    "list_listening_ports": "Services listening on the asset, with bind addresses.",
    "get_component": "The installed package: version, ecosystem, install paths, running state.",
    "get_advisory": "The published advisory text, CVSS, CWE, exploitation status.",
    "count_affected_assets": "How many assets carry this vulnerability, by tier.",
    "get_related_findings": "Other findings on the same asset.",
}


def call_tool(session: Session, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    tool = TOOLS.get(name)
    if tool is None:
        raise ToolError(
            f"No such tool {name!r}. Available: {', '.join(sorted(TOOLS))}. "
            "This registry contains no tool that changes anything."
        )
    try:
        return tool(session, **arguments)
    except ToolError:
        raise
    except TypeError as exc:
        raise ToolError(f"{name}: wrong arguments ({exc})") from exc
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"{name} failed: {type(exc).__name__}: {exc}") from exc
