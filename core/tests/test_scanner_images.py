from __future__ import annotations

import re

import pytest

from athena.config import Settings, get_settings
from athena.scanners import git, syft
from athena.scanners.sandbox import SandboxResult

IMAGE_SETTINGS = sorted(name for name in Settings.model_fields if name.endswith("_image"))
PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_-]*:(?P<tag>[A-Za-z0-9._-]+)@sha256:[0-9a-f]{64}$")


def test_every_scanner_image_is_a_setting():
    assert {"gitleaks_image", "trivy_image", "syft_image", "git_image"} <= set(IMAGE_SETTINGS)


@pytest.mark.parametrize("name", IMAGE_SETTINGS)
def test_scanner_image_is_pinned_by_version_and_digest(name):
    image = Settings.model_fields[name].default
    assert "@sha256:" in image
    pinned = PINNED_IMAGE.fullmatch(image)
    assert pinned, image
    assert pinned["tag"] != "latest"


@pytest.mark.parametrize("name", IMAGE_SETTINGS)
def test_blank_scanner_image_means_the_pinned_default(name, monkeypatch):
    monkeypatch.setenv(f"ATHENA_{name.upper()}", "  ")
    assert getattr(Settings(), name) == Settings.model_fields[name].default


@pytest.fixture
def sandboxed_images(monkeypatch):
    images: list[str] = []

    def capture(spec):
        images.append(spec.image)
        return SandboxResult(exit_code=0, stdout="{}", stderr="")

    for module in (git, syft):
        monkeypatch.setattr(module, "run_sandboxed", capture)
    return images


def test_git_sandboxes_run_the_pinned_git_image(sandboxed_images):
    checkout, _ = git.clone("https://example.com/acme/app.git", work_volume="athena-work")
    git.remove_checkout(checkout, work_volume="athena-work")
    assert sandboxed_images == [get_settings().git_image] * 3


def test_syft_sandboxes_run_the_pinned_syft_image(sandboxed_images, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "work_dir", str(tmp_path), raising=False)
    syft.scan_directory("checkout-0123456789ab", work_volume="athena-work")
    syft.scan_image("ghcr.io/acme/api:1.0")
    assert sandboxed_images == [get_settings().syft_image] * 2
