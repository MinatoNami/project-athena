from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena import __version__
from athena.db.models import Asset, AssetComponent, Component, ScanRun
from athena.inventory.purl import build_purl, parse_purl

SPEC_VERSION = "1.6"

_ASSET_TYPE = {
    "image": "container",
    "container": "container",
    "host": "operating-system",
    "repository": "application",
    "service": "application",
    "network_host": "device",
}


def component_purl(component: Component) -> str | None:
    if component.purl and parse_purl(component.purl):
        return component.purl
    if component.ecosystem == "generic":
        return None
    try:
        return build_purl(component.ecosystem, component.name, component.version)
    except Exception:  # noqa: BLE001
        return None


CODE_SCAN_KINDS = ("secret", "misconfiguration")
HOST_PACKAGES_TOOL = "athena-node/list_packages"


def _inventory_runs(asset: Asset) -> list[Any]:
    conditions: list[Any] = [ScanRun.kind.notin_(CODE_SCAN_KINDS)]
    if asset.kind == "host":
        conditions.append(ScanRun.tool == HOST_PACKAGES_TOOL)
    return conditions


def sbom_for(session: Session, asset: Asset) -> dict[str, Any]:
    rows = session.execute(
        select(Component, AssetComponent)
        .join(AssetComponent, AssetComponent.component_id == Component.id)
        .where(AssetComponent.asset_id == asset.id)
        .order_by(Component.ecosystem, Component.name, Component.version)
    ).all()

    last_scan = (
        session.execute(
            select(ScanRun)
            .where(ScanRun.asset_id == asset.id, *_inventory_runs(asset))
            .order_by(ScanRun.started_at.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )

    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    for component, link in rows:
        ref = str(component.id)
        if ref in seen:
            continue
        seen.add(ref)
        entry: dict[str, Any] = {
            "type": "operating-system" if component.ecosystem == "linux-kernel" else "library",
            "bom-ref": ref,
            "name": component.name,
            "version": component.version,
            "scope": "required",
            "properties": [
                {"name": "athena:ecosystem", "value": component.ecosystem},
                {"name": "athena:scope", "value": link.scope},
            ],
        }
        if (purl := component_purl(component)) is not None:
            entry["purl"] = purl
        if component.cpe:
            entry["cpe"] = component.cpe
        if link.install_path:
            entry["properties"].append({"name": "athena:install_path", "value": link.install_path})
        components.append(entry)

    properties = [
        {"name": "athena:asset_id", "value": str(asset.id)},
        {"name": "athena:asset_kind", "value": asset.kind},
        {"name": "athena:tier", "value": asset.tier},
    ]
    if last_scan is not None:
        properties += [
            {"name": "athena:scan_run", "value": str(last_scan.id)},
            {"name": "athena:scan_status", "value": last_scan.status},
            {"name": "athena:scan_tool", "value": last_scan.tool},
        ]
        if last_scan.status != "succeeded":
            properties.append(
                {
                    "name": "athena:completeness",
                    "value": (
                        f"the most recent scan was {last_scan.status}; this list may be incomplete"
                    ),
                }
            )
    else:
        properties.append(
            {"name": "athena:completeness", "value": "never scanned: no components observed"}
        )

    tools: list[dict[str, Any]] = [
        {"type": "application", "name": "athena", "version": __version__},
    ]
    if last_scan is not None and last_scan.tool:
        tools.append(
            {
                "type": "application",
                "name": last_scan.tool,
                "version": last_scan.tool_version or "unknown",
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "tools": {"components": tools},
            "component": {
                "type": _ASSET_TYPE.get(asset.kind, "application"),
                "bom-ref": f"asset:{asset.id}",
                "name": asset.display_name,
            },
            "properties": properties,
        },
        "components": components,
    }
