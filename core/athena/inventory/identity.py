from __future__ import annotations

import re
from enum import StrEnum
from urllib.parse import urlsplit


class AssetKind(StrEnum):
    HOST = "host"
    REPOSITORY = "repository"
    IMAGE = "image"
    CONTAINER = "container"
    SERVICE = "service"
    NETWORK_HOST = "network_host"


class IdentityError(ValueError):
    pass


_SCP_LIKE = re.compile(r"^(?P<user>[^@/]+)@(?P<host>[^:/]+):(?P<path>.+)$")


def normalise_repository_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise IdentityError("Empty repository URL")

    if (m := _SCP_LIKE.match(url)) and "://" not in url:
        host, path = m.group("host"), m.group("path")
    else:
        parts = urlsplit(url if "://" in url else f"https://{url}")
        host, path = parts.hostname or "", parts.path

    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not host or not path:
        raise IdentityError(f"Cannot derive a repository identity from {url!r}")
    return f"{host.lower()}/{path.lower()}"


def host_identity(
    *, machine_id: str | None = None, hardware_uuid: str | None = None, node_key: str | None = None
) -> str:
    if machine_id:
        return f"machine-id:{machine_id.strip().lower()}"
    if hardware_uuid:
        return f"hw-uuid:{hardware_uuid.strip().lower()}"
    if node_key:
        return f"node-key:{node_key.strip()}"
    raise IdentityError("A host needs a machine-id, hardware UUID, or node key")


def image_identity(digest: str) -> str:
    digest = digest.strip().lower()
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise IdentityError(f"Expected a sha256 image digest, got {digest!r}")
    return digest


def container_identity(host_key: str, container_id: str) -> str:
    return f"{host_key}/{container_id.strip()[:12]}"


def service_identity(host_key: str, protocol: str, port: int) -> str:
    return f"{host_key}/{protocol.lower()}/{port}"


def network_host_identity(*, mac: str | None = None, fingerprint: str | None = None) -> str:
    if mac:
        return f"mac:{mac.strip().lower().replace('-', ':')}"
    if fingerprint:
        return f"fingerprint:{fingerprint.strip()}"
    raise IdentityError("A network host needs a MAC address or a fingerprint")


def identity_for(kind: AssetKind | str, **kwargs) -> str:
    match AssetKind(kind):
        case AssetKind.REPOSITORY:
            return normalise_repository_url(kwargs["url"])
        case AssetKind.HOST:
            return host_identity(**kwargs)
        case AssetKind.IMAGE:
            return image_identity(kwargs["digest"])
        case AssetKind.CONTAINER:
            return container_identity(kwargs["host_key"], kwargs["container_id"])
        case AssetKind.SERVICE:
            return service_identity(kwargs["host_key"], kwargs["protocol"], kwargs["port"])
        case AssetKind.NETWORK_HOST:
            return network_host_identity(**kwargs)
    raise IdentityError(f"Unsupported asset kind {kind!r}")
