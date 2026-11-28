from __future__ import annotations

from athena.inventory.identity import AssetKind
from athena.inventory.service import register_asset
from athena.remediation import (
    link_built_images,
    link_image_source,
    source_for,
)


def _image(session, *, repo: str, tag: str, digest: str):
    asset, _ = register_asset(
        session,
        kind=AssetKind.IMAGE,
        identity_key=f"sha256:{digest}",
        display_name=f"{repo}:{tag}",
        attributes={"repository": repo, "tag": tag},
    )
    return asset


def _repo(session, *, name: str, builds: list[str], commit: str | None = None):
    attrs = {"clone_url": f"https://example.invalid/{name}.git", "builds": builds}
    if commit:
        attrs["last_commit"] = commit
    asset, _ = register_asset(
        session,
        kind=AssetKind.REPOSITORY,
        identity_key=f"example.invalid/{name}",
        display_name=name,
        attributes=attrs,
    )
    return asset


def test_registering_a_repository_reaches_images_already_observed(session):
    old = _image(session, repo="lumaindex-frontend", tag="20260819T081826Z-aa38942",
                 digest="aa" * 32)
    session.flush()
    repo = _repo(session, name="lumaindex", builds=["lumaindex-frontend"])

    assert link_built_images(session, repo) == 1
    assert source_for(session, old).repository == "lumaindex"


def test_a_tag_pushed_after_registration_links_itself(session):
    _repo(session, name="lumaindex", builds=["lumaindex-frontend"])
    session.flush()
    fresh = _image(session, repo="lumaindex-frontend", tag="20260828T101500Z-9f3c1de",
                   digest="bb" * 32)

    assert link_image_source(session, fresh) is not None
    assert source_for(session, fresh).repository == "lumaindex"


def test_a_name_the_runtime_does_not_use_links_nothing(session):
    _image(session, repo="lumaindex-frontend", tag="latest", digest="cc" * 32)
    session.flush()
    repo = _repo(session, name="lumaindex", builds=["lumaindex/frontend"])

    assert link_built_images(session, repo) == 0


def test_an_unlinked_image_has_no_source_rather_than_a_guessed_one(session):
    orphan = _image(session, repo="postgres", tag="16-alpine", digest="dd" * 32)
    session.flush()
    assert source_for(session, orphan) is None


def test_the_commit_a_tag_implies_travels_with_the_source(session):
    image = _image(session, repo="alena-gateway-status", tag="bd44cd5", digest="ee" * 32)
    session.flush()
    repo = _repo(session, name="gateway", builds=["alena-gateway-status"],
                 commit="bd44cd51f0a9e7b3")
    link_built_images(session, repo)

    ref = source_for(session, image)
    assert ref.commit_hint == "bd44cd5"
    assert ref.scanned_commit == "bd44cd51f0a9e7b3"


def test_a_repository_is_its_own_source(session):
    repo = _repo(session, name="project-athena", builds=[])
    session.flush()
    ref = source_for(session, repo)
    assert ref.repository == "project-athena"
    assert ref.commit_hint is None
