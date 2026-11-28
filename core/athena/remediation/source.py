from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.db.models import Asset, AssetEdge
from athena.inventory.identity import AssetKind
from athena.inventory.service import link

_COMMIT_LIKE = re.compile(r"^[0-9a-f]{7,40}$")

RELATION = "built_from"


@dataclass(frozen=True)
class SourceRef:
    repository: str
    clone_url: str | None
    default_branch: str | None
    commit_hint: str | None = None
    scanned_commit: str | None = None


def image_name(asset: Asset) -> str | None:
    if asset.kind != AssetKind.IMAGE:
        return None
    recorded = asset.attributes.get("repository")
    if recorded and recorded != "<none>":
        return recorded
    name = asset.display_name
    for sep in ("@", ":"):
        if sep in name:
            name = name.rsplit(sep, 1)[0]
    return name or None


def commit_hint(asset: Asset) -> str | None:
    tag = asset.attributes.get("tag") or ""
    if not tag and ":" in asset.display_name:
        tag = asset.display_name.rsplit(":", 1)[1]
    if not tag or tag == "<none>":
        return None
    candidate = tag.rsplit("-", 1)[-1].lower()
    return candidate if _COMMIT_LIKE.match(candidate) else None


def _builds(repo: Asset) -> list[str]:
    declared = repo.attributes.get("builds") or []
    return [str(n).strip() for n in declared if str(n).strip()]


def link_built_images(session: Session, repo: Asset) -> int:
    names = _builds(repo)
    if not names:
        return 0
    images = session.execute(
        select(Asset).where(Asset.kind == AssetKind.IMAGE, Asset.tombstoned_at.is_(None))
    ).scalars().all()
    linked = 0
    for image in images:
        if image_name(image) in names:
            link(session, src=image, dst=repo, relation=RELATION)
            linked += 1
    return linked


def link_image_source(session: Session, image: Asset) -> Asset | None:
    name = image_name(image)
    if not name:
        return None
    repos = session.execute(
        select(Asset).where(Asset.kind == AssetKind.REPOSITORY, Asset.tombstoned_at.is_(None))
    ).scalars().all()
    for repo in repos:
        if name in _builds(repo):
            link(session, src=image, dst=repo, relation=RELATION)
            return repo
    return None


def source_for(session: Session, asset: Asset) -> SourceRef | None:
    if asset.kind == AssetKind.REPOSITORY:
        return SourceRef(
            repository=asset.display_name,
            clone_url=asset.attributes.get("clone_url") or asset.attributes.get("url"),
            default_branch=asset.attributes.get("default_branch"),
            scanned_commit=asset.attributes.get("last_commit"),
        )
    if asset.kind != AssetKind.IMAGE:
        return None
    repo = session.execute(
        select(Asset)
        .join(AssetEdge, AssetEdge.dst_id == Asset.id)
        .where(
            AssetEdge.src_id == asset.id,
            AssetEdge.relation == RELATION,
            Asset.kind == AssetKind.REPOSITORY,
        )
    ).scalars().first()
    if repo is None:
        return None
    return SourceRef(
        repository=repo.display_name,
        clone_url=repo.attributes.get("clone_url") or repo.attributes.get("url"),
        default_branch=repo.attributes.get("default_branch"),
        commit_hint=commit_hint(asset),
        scanned_commit=repo.attributes.get("last_commit"),
    )
