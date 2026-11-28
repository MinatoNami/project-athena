from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select

from athena.audit import record
from athena.db.base import session_scope
from athena.db.models import Asset, AssetEdge, Node, NodeTask
from athena.inventory.classify import derive
from athena.inventory.identity import AssetKind, IdentityError, identity_for
from athena.inventory.purl import build_purl
from athena.inventory.service import (
    ObservedComponent,
    finish_scan,
    link,
    record_components,
    register_asset,
    start_scan,
)
from athena.queue import enqueue, publish
from athena.queue.registry import handler
from athena.remediation import link_image_source

log = structlog.get_logger(__name__)

PACKAGE_ECOSYSTEM = {"deb": "deb", "rpm": "rpm", "apk": "apk"}


@handler("ingest.node_observation")
def ingest(payload: dict[str, Any]) -> dict[str, Any]:
    task_id = payload["task_id"]

    with session_scope() as session:
        task = session.get(NodeTask, task_id)
        if task is None or not task.succeeded or not task.result:
            return {"status": "skipped", "reason": "no usable result"}

        node = session.get(Node, task.node_id)
        if node is None or node.asset_id is None:
            return {"status": "skipped", "reason": "node has no asset"}

        asset = session.get(Asset, node.asset_id)
        if asset is None:
            return {"status": "skipped", "reason": "asset missing"}

        capability = task.result.get("capability") or task.capability
        data = task.result.get("data")

        run = start_scan(
            session,
            asset=asset,
            kind="host",
            tool=f"athena-node/{capability}",
            tool_version=node.agent_version,
        )
        try:
            stats = _apply(session, asset=asset, run=run, capability=capability, data=data)
        except Exception as exc:  # noqa: BLE001
            finish_scan(session, run, status="failed", error=f"{type(exc).__name__}: {exc}")
            log.warning("node.ingest_failed", capability=capability, error=str(exc))
            return {"status": "failed", "capability": capability}

        finish_scan(session, run, status="succeeded", stats=stats)
        task.scan_run_id = run.id

        record(
            session,
            actor=f"node:{node.id}",
            action="HOST_OBSERVED",
            subject=f"asset:{asset.id}",
            detail={"capability": capability, **stats},
        )
        publish(session, topic="assets", subject_id=str(asset.id))
        if capability == "list_packages":
            enqueue(
                session,
                kind="correlate.asset",
                key=f"{asset.id}:node-packages",
                payload={"asset_id": str(asset.id)},
                priority=4,
            )

    log.info("node.ingested", capability=capability, asset=str(node.asset_id), **stats)
    return {"status": "succeeded", "capability": capability, **stats}


def _apply(session, *, asset: Asset, run, capability: str, data: Any) -> dict[str, Any]:
    stats = _dispatch(session, asset=asset, run=run, capability=capability, data=data)

    if capability in ("list_ports", "inspect_docker"):
        stats = {**stats, "derived": derive(session)}
    return stats


def _dispatch(session, *, asset: Asset, run, capability: str, data: Any) -> dict[str, Any]:
    match capability:
        case "get_system_info":
            return _system_info(session, asset=asset, data=data)
        case "list_packages":
            return _packages(session, asset=asset, run=run, data=data)
        case "list_ports":
            return _ports(session, asset=asset, data=data)
        case "list_processes":
            return {"processes": len(data or [])}
        case "list_services":
            running = sum(1 for s in data or [] if s.get("active") == "active")
            return {"services": len(data or []), "services_active": running}
        case "inspect_docker":
            return _docker(session, asset=asset, data=data)
    return {"ignored": capability}


def _distro_release(data: dict) -> tuple[str | None, str | None]:
    import re

    distro = (data.get("os_id") or "").strip().lower() or None
    release = (data.get("os_version_id") or "").strip() or None

    pretty = (data.get("os_version") or "").strip()
    if distro is None and pretty:
        first = pretty.split()[0].lower()
        distro = first or None
    if release is None and pretty:
        match = re.search(r"(\d+\.\d+)", pretty)
        release = match.group(1) if match else None
    return distro, release


def _system_info(session, *, asset: Asset, data: dict) -> dict[str, Any]:
    data = data or {}
    distro, release = _distro_release(data)
    asset.attributes = {
        **asset.attributes,
        "os": data.get("os"),
        "os_version": data.get("os_version"),
        "distro": distro,
        "distro_release": release,
        "kernel": data.get("kernel"),
        "arch": data.get("arch"),
        "hostname": data.get("hostname"),
    }
    if data.get("hostname"):
        asset.display_name = data["hostname"]
    return {
        "os": data.get("os_version") or data.get("os") or "unknown",
        "distro_release": release or "unknown",
    }


def _packages(session, *, asset: Asset, run, data: list) -> dict[str, Any]:
    components: list[ObservedComponent] = []
    for pkg in data or []:
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        ecosystem = PACKAGE_ECOSYSTEM.get(pkg.get("source", ""), "generic")
        qualifiers = {k: v for k, v in (("arch", pkg.get("arch")),) if v}
        components.append(
            ObservedComponent(
                ecosystem=ecosystem,
                name=name,
                version=version,
                scope="os",
                purl=build_purl(ecosystem, name, version, qualifiers=qualifiers),
            )
        )
    count = record_components(session, asset=asset, run=run, components=components)
    return {"packages": count}


def _process_name(raw: str | None) -> str | None:
    if not raw:
        return None
    import re

    match = re.search(r'\(\("([^"]+)"', raw)
    if match:
        return match.group(1)
    return raw if raw.replace("-", "").replace("_", "").isalnum() else None


def _ports(session, *, asset: Asset, data: list) -> dict[str, Any]:
    exposed = 0
    seen: set[str] = set()
    for entry in data or []:
        port, protocol = entry.get("port"), entry.get("protocol", "tcp")
        if not port:
            continue
        address = entry.get("address", "")
        loopback = address.startswith("127.") or address in ("::1", "[::1]")
        exposure = "isolated" if loopback else "internal"
        if not loopback:
            exposed += 1

        try:
            key = identity_for(
                AssetKind.SERVICE,
                host_key=asset.identity_key,
                protocol=protocol.replace("tcp6", "tcp").replace("udp6", "udp"),
                port=int(port),
            )
        except (IdentityError, ValueError):
            continue

        process = _process_name(entry.get("process"))
        service, _ = register_asset(
            session,
            kind=AssetKind.SERVICE,
            identity_key=key,
            display_name=(
                f"{process} {protocol}/{port}"
                if process
                else f"{protocol}/{port} on {address or '*'}"
            ),
            attributes={
                "address": address,
                "protocol": protocol,
                "port": port,
                "process": process,
                "process_known": process is not None,
            },
        )
        service.exposure = exposure
        service.last_inventoried_at = datetime.now(UTC)
        link(session, src=service, dst=asset, relation="runs_on")
        seen.add(key)

    retired = _retire_unseen_services(session, asset=asset, seen=seen, reported=len(data or []))
    return {
        "listening_ports": len(data or []),
        "non_loopback": exposed,
        "retired": retired,
    }


def _retire_unseen_services(session, *, asset: Asset, seen: set[str], reported: int) -> int:
    if not reported:
        log.warning("node.empty_port_report", asset=str(asset.id))
        return 0

    now = datetime.now(UTC)
    rows = session.execute(
        select(Asset)
        .join(AssetEdge, AssetEdge.src_id == Asset.id)
        .where(
            AssetEdge.dst_id == asset.id,
            AssetEdge.relation == "runs_on",
            Asset.kind == AssetKind.SERVICE,
            Asset.tombstoned_at.is_(None),
        )
    ).scalars().all()

    retired = 0
    for service in rows:
        if service.identity_key in seen:
            continue
        service.tombstoned_at = now
        retired += 1
    if retired:
        log.info("node.services_retired", asset=str(asset.id), retired=retired,
                 still_listening=len(seen))
    return retired


_IMAGE_ID = re.compile(r"^[0-9a-f]{12}$|^[0-9a-f]{64}$")


def _normalise_image_ref(ref: str) -> str:
    ref = (ref or "").strip()
    if not ref or ":" in ref or "@" in ref or _IMAGE_ID.match(ref):
        return ref
    return f"{ref}:latest"


def _docker(session, *, asset: Asset, data: dict) -> dict[str, Any]:
    data = data or {}
    images_by_ref: dict[str, Asset] = {}
    images_by_id: dict[str, Asset] = {}

    for image in data.get("images") or []:
        digest = image.get("digest")
        if not digest:
            continue
        try:
            key = identity_for(AssetKind.IMAGE, digest=digest)
        except IdentityError:
            continue
        repo, tag = image.get("repository", "<none>"), image.get("tag", "<none>")
        image_id = (image.get("id") or "").strip().lower()
        image_asset, _ = register_asset(
            session,
            kind=AssetKind.IMAGE,
            identity_key=key,
            display_name=f"{repo}:{tag}",
            attributes={"repository": repo, "tag": tag, "digest": digest},
        )
        link_image_source(session, image_asset)
        images_by_ref[f"{repo}:{tag}"] = image_asset
        if image_id:
            images_by_id[image_id] = image_asset

    containers = 0
    for container in data.get("containers") or []:
        cid = container.get("id")
        if not cid:
            continue
        key = identity_for(AssetKind.CONTAINER, host_key=asset.identity_key, container_id=cid)
        container_asset, _ = register_asset(
            session,
            kind=AssetKind.CONTAINER,
            identity_key=key,
            display_name=container.get("name") or cid[:12],
            attributes={
                "image": container.get("image"),
                "state": container.get("state"),
                **(
                    {"published_ports": container["ports"]}
                    if "ports" in container
                    else {}
                ),
            },
        )
        containers += 1
        link(session, src=container_asset, dst=asset, relation="runs_on")

        raw_ref = (container.get("image") or "").strip()
        image_asset = images_by_ref.get(_normalise_image_ref(raw_ref))
        if image_asset is None and _IMAGE_ID.match(raw_ref):
            image_asset = images_by_id.get(raw_ref.lower())
        if image_asset is not None:
            link(
                session, src=container_asset, dst=image_asset,
                relation="built_from", confidence=0.8,
            )

    return {"images": len(images_by_ref), "containers": containers}
