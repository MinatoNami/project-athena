"""Syft adapter: filesystem or image → components.

Syft is the fact-establishing tool; this module only translates its output into
Athena's model. Tool name and version travel with the result so every component can
answer "how do you know that, and with what".
"""

from __future__ import annotations

import pathlib
import re
import shutil
import uuid

import structlog

from athena.config import get_settings
from athena.inventory.purl import parse_purl
from athena.inventory.service import ObservedComponent
from athena.scanners.sandbox import Mount, SandboxResult, SandboxSpec, run_sandboxed

log = structlog.get_logger(__name__)

SYFT_IMAGE = "anchore/syft:latest"
SYFT_TIMEOUT = 600

# Syft package types → Athena ecosystems. Anything unmapped is kept as `generic`
# rather than dropped: an unrecognised component is still a component, and silently
# discarding it would overstate coverage.
ECOSYSTEM = {
    "python": "pypi", "npm": "npm", "go-module": "golang", "gem": "gem",
    "java-archive": "maven", "jenkins-plugin": "maven", "rust-crate": "cargo",
    "deb": "deb", "rpm": "rpm", "apk": "apk", "dotnet": "nuget",
    "php-composer": "composer", "hex": "hex", "conan": "conan", "swift": "swift",
    "dart-pub": "pub", "cocoapods": "cocoapods", "github-action": "github",
    "github-action-workflow": "github", "binary": "generic", "conda": "conda",
    "linux-kernel": "generic", "wordpress-plugin": "generic",
}

# Only `dependency-of` carries dependency direction. `contains` relates a source or
# package to its file locations, so treating it as a dependency edge marks every
# artifact transitive — including the ones declared in the manifest.
_DEPENDENCY_RELATION = "dependency-of"


def scan_directory(path_in_volume: str, *, work_volume: str) -> tuple[SandboxResult, str | None]:
    """Run Syft over a checkout, with no network."""
    result = run_sandboxed(
        SandboxSpec(
            image=SYFT_IMAGE,
            command=["scan", f"dir:/scan/{path_in_volume}", "-o", "syft-json", "-q"],
            mounts=[Mount(volume=work_volume, target="/scan", read_only=True)],
            network="none",
            timeout=SYFT_TIMEOUT,
        )
    )
    version = None
    if result.ok:
        try:
            version = (result.json().get("descriptor") or {}).get("version")
        except Exception:  # noqa: BLE001 - version is a nicety, not a requirement
            version = None
    return result, version


# Image scratch lives on disk, not in the sandbox's tmpfs.
#
# Syft exports the whole image before reading it, so scratch has to be at least as
# large as the image. A tmpfs is RAM, and RAM is counted against the container's
# memory limit — so a 4g tmpfs under a 1g limit was not 4g of scratch at all, it was
# an OOM kill at the one-gigabyte mark, arriving as a bare "exit 137" with nothing on
# stderr. Raising the limit to match only moves the wall: a 13 GB image would need
# 13 GB of RAM on a host that has 15.
#
# Disk has none of that coupling, and the work volume already exists for exactly this
# kind of thing. The tmpfs stays small for anything that still writes to /tmp.
IMAGE_TMPFS = "256m"
IMAGE_SCRATCH_ROOT = "/scratch"
SCRATCH = "/tmp"  # noqa: S108


def scan_image(reference: str) -> tuple[SandboxResult, str | None]:
    """Run Syft against an image, reading it from the local daemon.

    Deliberately `docker:` and not `registry:`. Most images on a host are built
    locally and exist in no registry at all — every scan of one failed trying to pull
    it. The daemon is reached through the read-only proxy, so this needs no socket
    access and cannot create anything.

    Scratch is a directory of its own on the work volume, removed afterwards. Syft
    fails outright if it cannot create a cache, and the sandbox root is read-only by
    design, so it needs somewhere to write; disk rather than tmpfs because the export
    is the size of the image.

    The directory is made here rather than inside the sandbox. The scanner image's
    entrypoint is syft itself, so a shell command passed to it arrives as an argument
    to syft — which reads it as a config path and exits. The worker already has the
    volume mounted and runs as the same uid the sandbox does, so it can simply
    create the directory.
    """
    settings = get_settings()
    scratch = f"imagescan-{uuid.uuid4().hex[:12]}"
    local_path = pathlib.Path(settings.work_dir) / scratch
    sandbox_path = f"{IMAGE_SCRATCH_ROOT}/{scratch}"

    local_path.mkdir(parents=True, exist_ok=True)
    try:
        result = run_sandboxed(
            SandboxSpec(
                image=SYFT_IMAGE,
                command=["scan", f"docker:{reference}", "-o", "syft-json", "-q"],
                mounts=[
                    Mount(
                        volume=settings.work_volume,
                        target=IMAGE_SCRATCH_ROOT,
                        read_only=False,
                    )
                ],
                network=settings.sandbox_network,
                timeout=SYFT_TIMEOUT,
                memory=settings.image_scan_memory,
                tmpfs_size=IMAGE_TMPFS,
                env={
                    "DOCKER_HOST": settings.docker_proxy_host,
                    "HOME": sandbox_path,
                    "XDG_CACHE_HOME": sandbox_path,
                    "TMPDIR": sandbox_path,
                },
            )
        )
    finally:
        remove_scratch(scratch, work_dir=settings.work_dir)
    version = None
    if result.ok:
        try:
            version = (result.json().get("descriptor") or {}).get("version")
        except Exception:  # noqa: BLE001 - version is a nicety, not a requirement
            version = None
    return result, version


def parse(document: dict) -> tuple[list[ObservedComponent], list[str], list[str]]:
    """Translate a Syft document. Returns (components, warnings, notes).

    The distinction matters for how the scan is recorded:

    * A **warning** is a gap in what we know — an artifact we could not pin down well
      enough to correlate later. It makes the scan partial, so the asset stays stale.
    * A **note** is something we recorded fully but do not fully understand, such as
      an ecosystem Athena has no advisory source for. That is a known limitation, not
      an incomplete scan, and must not leave the asset permanently stale.
    """
    artifacts = document.get("artifacts") or []
    warnings: list[str] = []
    notes: list[str] = []

    direct = _direct_artifact_ids(document)
    components: list[ObservedComponent] = []
    if direct is None:
        notes.append(
            "no dependency relationships in the SBOM; direct and transitive "
            "components cannot be distinguished"
        )

    for artifact in artifacts:
        name = (artifact.get("name") or "").strip()
        version = (artifact.get("version") or "").strip()
        if not name:
            warnings.append("artifact with no name")
            continue
        if not version:
            # A component with no version cannot be matched against an advisory range,
            # so recording it as if it were usable would be misleading.
            warnings.append(f"{name}: no version resolved")
            continue

        syft_type = (artifact.get("type") or "").lower()
        ecosystem = ECOSYSTEM.get(syft_type)
        if ecosystem is None:
            ecosystem = "generic"
            notes.append(f"unmapped package type {syft_type!r} (e.g. {name})")

        purl = artifact.get("purl") or None
        if purl and not parse_purl(purl):
            purl = None

        locations = artifact.get("locations") or []
        install_path = locations[0].get("path") if locations else None

        components.append(
            ObservedComponent(
                ecosystem=ecosystem,
                name=name,
                version=version,
                scope=_scope_for(artifact.get("id"), direct),
                purl=purl,
                cpe=_first_cpe(artifact),
                install_path=install_path,
            )
        )

    return components, warnings, notes


def _first_cpe(artifact: dict) -> str | None:
    """Syft has emitted `cpes` as bare strings and as objects across versions.

    Accept both rather than assuming, and return None for anything unrecognised —
    a malformed CPE is worse than no CPE, because correlation would trust it.
    """
    for entry in artifact.get("cpes") or []:
        if isinstance(entry, str) and entry.startswith("cpe:"):
            return entry
        if isinstance(entry, dict):
            value = entry.get("cpe")
            if isinstance(value, str) and value.startswith("cpe:"):
                return value
    return None


def _scope_for(artifact_id: str | None, direct: set[str] | None) -> str:
    """direct | transitive | unknown.

    `unknown` is deliberate. The distinction drives remediation — a transitive
    vulnerability usually cannot be fixed where it was found — so guessing is worse
    than admitting the SBOM does not say.
    """
    if direct is None:
        return "unknown"
    return "direct" if artifact_id in direct else "transitive"


def _direct_artifact_ids(document: dict) -> set[str] | None:
    """Artifacts nothing else depends on — i.e. declared rather than pulled in.

    Returns None when the SBOM carries no dependency relationships at all, so the
    caller can record `unknown` instead of inventing an answer.
    """
    all_ids = {a.get("id") for a in document.get("artifacts") or [] if a.get("id")}
    relationships = [
        r for r in document.get("artifactRelationships") or []
        if (r.get("type") or "") == _DEPENDENCY_RELATION
    ]
    if not relationships:
        return None

    depended_upon = {r["child"] for r in relationships if r.get("child")}
    return all_ids - depended_upon


def remove_scratch(scratch: str, *, work_dir: str) -> None:
    """Delete one image-scan scratch directory.

    Never fatal: a leaked directory costs disk, while raising here would turn a
    successful scan into a failed one after the work was already done. The name is
    checked against the pattern this module generates, because this deletes a tree
    and that is not something to point at an arbitrary string.
    """
    if not re.fullmatch(r"imagescan-[0-9a-f]{12}", scratch):
        log.warning("imagescan.refused_removal", scratch=scratch)
        return
    try:
        shutil.rmtree(pathlib.Path(work_dir) / scratch, ignore_errors=True)
    except OSError as exc:  # noqa: BLE001 - cleanup must never fail a good scan
        log.warning("imagescan.scratch_not_removed", scratch=scratch, error=str(exc))
