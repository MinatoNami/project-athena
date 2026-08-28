"""Which repository builds an image.

An image finding names a package and a fixed version, and the change that installs
it is not made on the image at all — it is made in a manifest, in source, and the
image is rebuilt. Without knowing which repository that is, every image finding ends
at the same dead end: "upgrade this, somewhere".

The mapping cannot be discovered. Nothing in an image reliably records the source
that produced it, so an operator states it once, on the repository, and everything
else follows from that. Two moments matter and both are covered here: repositories
registered after their images exist, and the new tag that appears tomorrow.

Matching is exact on the image name. A near-miss silently linking nothing is worse
than a mismatch reported at the point of entry, so registration returns the count and
the operator sees immediately whether they named the image the way the runtime does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.db.models import Asset, AssetEdge
from athena.inventory.identity import AssetKind
from athena.inventory.service import link

# A tag, or the last segment of one, that is all hex and the length of an abbreviated
# commit. Build pipelines stamp images this way and it is the only trace of the
# commit that produced the image — but it is a convention, not a record, so nothing
# here treats it as established.
_COMMIT_LIKE = re.compile(r"^[0-9a-f]{7,40}$")

# The relation an image bears to its source. Same word as container → image: in both
# cases the destination is what the source was made from.
RELATION = "built_from"


@dataclass(frozen=True)
class SourceRef:
    """Where an asset's source lives, and how sure we are which revision."""

    repository: str
    clone_url: str | None
    default_branch: str | None
    # The commit the image's tag suggests, where the tag looks like one. Inferred
    # from a naming convention and verified by nothing.
    commit_hint: str | None = None
    # The commit the last scan of that repository actually saw. Recorded, not guessed.
    scanned_commit: str | None = None


def image_name(asset: Asset) -> str | None:
    """The image's name without its tag or digest.

    Read from what the runtime reported where possible. The display name is a
    fallback for images registered before that attribute was recorded.
    """
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
    """The commit an image's tag implies, if it implies one.

    `app:a1b2c3d` and `app:20260827T042902Z-cfbe483` both carry what is almost
    certainly a commit. Almost is the operative word — callers must present this as
    an inference from the tag, never as the commit the image was built from.
    """
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
    """Link every existing image this repository declares it builds.

    Runs when a repository is registered, which is normally after its images have
    been observed for weeks.
    """
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
    """Link one newly-observed image to the repository that claims to build it.

    Runs on ingest, so a tag pushed after the repository was registered is linked
    without anybody revisiting the registration.
    """
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
    """The source repository behind an asset, or None if none is known.

    A repository is its own source. An image has one only if somebody said so.
    """
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
