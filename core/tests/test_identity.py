"""Asset identity.

Identity errors are the most expensive kind in this system: everything downstream
inherits them, and a wrong merge cannot be undone.
"""

from __future__ import annotations

import pytest

from athena.inventory.identity import (
    AssetKind,
    IdentityError,
    identity_for,
    image_identity,
    normalise_repository_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/Org/Repo.git",
        "https://github.com/org/repo",
        "git@github.com:Org/Repo.git",
        "ssh://git@github.com/org/repo.git",
        "github.com/org/repo",
        "  https://github.com/org/repo/  ",
    ],
)
def test_repository_urls_that_mean_the_same_repo_agree(url: str) -> None:
    assert normalise_repository_url(url) == "github.com/org/repo"


def test_credentials_in_a_url_are_not_part_of_identity() -> None:
    """A token embedded in a remote must never end up stored as an identity key."""
    key = normalise_repository_url("https://user:ghp_secrettoken@github.com/org/repo.git")
    assert key == "github.com/org/repo"
    assert "ghp_secrettoken" not in key


def test_different_repositories_do_not_collide() -> None:
    assert normalise_repository_url("https://github.com/org/repo") != normalise_repository_url(
        "https://gitlab.com/org/repo"
    )


def test_image_identity_requires_a_digest_not_a_tag() -> None:
    digest = "sha256:" + "a" * 64
    assert image_identity(digest.upper()) == digest
    for not_a_digest in ("latest", "python:3.12", "sha256:short"):
        with pytest.raises(IdentityError):
            image_identity(not_a_digest)


def test_host_identity_prefers_the_most_durable_signal() -> None:
    both = identity_for(AssetKind.HOST, machine_id="abc", hardware_uuid="def", node_key="k")
    assert both == "machine-id:abc"
    assert identity_for(AssetKind.HOST, hardware_uuid="DEF") == "hw-uuid:def"
    assert identity_for(AssetKind.HOST, node_key="k") == "node-key:k"


def test_a_host_with_no_durable_signal_is_an_error_not_a_guess() -> None:
    with pytest.raises(IdentityError):
        identity_for(AssetKind.HOST)
