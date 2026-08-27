"""Turn node observations into inventory.

Each capability result becomes facts about the host asset, with the scan run that
produced them attached. A capability that failed leaves the asset stale rather than
appearing clean, exactly as a failed repository scan does.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select

from athena.audit import record
from athena.db.base import session_scope
from athena.db.models import Asset, AssetEdge, Node, NodeTask
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
from athena.queue import publish
from athena.queue.registry import handler

log = structlog.get_logger(__name__)

# Package sources the node reports, mapped to component ecosystems.
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
        except Exception as exc:  # noqa: BLE001 - record the failure rather than lose it
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

    log.info("node.ingested", capability=capability, asset=str(node.asset_id), **stats)
    return {"status": "succeeded", "capability": capability, **stats}


def _apply(session, *, asset: Asset, run, capability: str, data: Any) -> dict[str, Any]:
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
    """(distro, release) from os-release, e.g. ("ubuntu", "24.04").

    Correlation needs this: a fix in Ubuntu 22.04 says nothing about 24.04, and
    comparing across releases makes a vulnerable host look patched.
    """
    import re

    distro = (data.get("os_id") or "").strip().lower() or None
    release = (data.get("os_version_id") or "").strip() or None

    # Agents predating os_id/os_version_id report only the pretty name. Deriving
    # both from it keeps an older agent fully correlatable rather than leaving the
    # distribution unknown, which would silently disable distro-specific matching.
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
    """Pull the process name out of ss's users field.

    ss renders it as users:(("sshd",pid=123,fd=3)); storing that verbatim made a
    service asset's name unreadable. Returns None when the agent could not see the
    owner, which is normal for an unprivileged agent and is recorded rather than
    guessed at.
    """
    if not raw:
        return None
    import re

    match = re.search(r'\(\("([^"]+)"', raw)
    if match:
        return match.group(1)
    return raw if raw.replace("-", "").replace("_", "").isalnum() else None


def _ports(session, *, asset: Asset, data: list) -> dict[str, Any]:
    """Register listening services as their own assets.

    The bind address is kept rather than collapsed: 127.0.0.1:6379 and 0.0.0.0:6379
    are entirely different exposure facts, and flattening them would turn a loopback
    service into a false internet exposure — or hide a real one.
    """
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
            # The bind address is part of the name because it is the exposure fact:
            # 0.0.0.0:6379 and 127.0.0.1:6379 are very different things to see in a
            # list. The process name is included when the agent could see it — an
            # unprivileged agent cannot read other users' socket owners.
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
    """Tombstone services on this host that the node no longer reports.

    The agent sends its whole listening set each time, so anything absent from it has
    gone. Without this every socket that ever existed stays in the inventory forever:
    on the development host 190 of 227 services were ephemeral high ports observed
    once, six days earlier, and never again — permanently stale, permanently dragging
    coverage down, and growing with every collection.

    Nothing is deleted. Tombstoned assets leave the active inventory, and observing
    one again clears the tombstone, so a service that is briefly down comes back
    rather than vanishing for good.
    """
    if not reported:
        # An empty report is far more likely to be a collection that failed than a
        # host with nothing listening at all, and acting on it would retire the
        # entire inventory of that host in one pass.
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


# A 12- or 64-character hex string is an image ID, not a repository name.
_IMAGE_ID = re.compile(r"^[0-9a-f]{12}$|^[0-9a-f]{64}$")


def _normalise_image_ref(ref: str) -> str:
    """Apply Docker's own default-tag rule so a bare name matches its image.

    `docker ps` prints whatever the container was created with, so a container
    started from `hello-world` reports exactly that, while the image is inventoried
    as `hello-world:latest`. Docker resolves the two to the same thing and so should
    this; without it the container looks like it came from nowhere and its packages
    go uncounted.

    An image ID is left alone. Appending a tag to one would invent a repository that
    does not exist, and a container reporting an ID genuinely has no tagged image to
    point at — the agent would need to report the image digest to resolve those, and
    it does not collect one.
    """
    ref = (ref or "").strip()
    if not ref or ":" in ref or "@" in ref or _IMAGE_ID.match(ref):
        return ref
    return f"{ref}:latest"


def _docker(session, *, asset: Asset, data: dict) -> dict[str, Any]:
    data = data or {}
    images_by_ref: dict[str, Asset] = {}

    for image in data.get("images") or []:
        digest = image.get("digest")
        if not digest:
            continue
        try:
            key = identity_for(AssetKind.IMAGE, digest=digest)
        except IdentityError:
            continue
        repo, tag = image.get("repository", "<none>"), image.get("tag", "<none>")
        image_asset, _ = register_asset(
            session,
            kind=AssetKind.IMAGE,
            identity_key=key,
            display_name=f"{repo}:{tag}",
            attributes={"repository": repo, "tag": tag, "digest": digest},
        )
        images_by_ref[f"{repo}:{tag}"] = image_asset

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
            attributes={"image": container.get("image"), "state": container.get("state")},
        )
        containers += 1
        link(session, src=container_asset, dst=asset, relation="runs_on")

        # repository → image → container → host becomes traversable here. The image
        # link is by reference because the runtime reports a tag; where the tag has
        # moved, provenance is genuinely unknown rather than assumed.
        image_asset = images_by_ref.get(_normalise_image_ref(container.get("image", "")))
        if image_asset is not None:
            link(
                session, src=container_asset, dst=image_asset,
                relation="built_from", confidence=0.8,
            )

    return {"images": len(images_by_ref), "containers": containers}
