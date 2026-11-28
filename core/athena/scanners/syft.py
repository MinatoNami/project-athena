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

ECOSYSTEM = {
    "python": "pypi", "npm": "npm", "go-module": "golang", "gem": "gem",
    "java-archive": "maven", "jenkins-plugin": "maven", "rust-crate": "cargo",
    "deb": "deb", "rpm": "rpm", "apk": "apk", "dotnet": "nuget",
    "php-composer": "composer", "hex": "hex", "conan": "conan", "swift": "swift",
    "dart-pub": "pub", "cocoapods": "cocoapods", "github-action": "github",
    "github-action-workflow": "github", "binary": "generic", "conda": "conda",
    "linux-kernel": "generic", "wordpress-plugin": "generic",
}

_DEPENDENCY_RELATION = "dependency-of"


def scan_directory(path_in_volume: str, *, work_volume: str) -> tuple[SandboxResult, str | None]:
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
        except Exception:  # noqa: BLE001
            version = None
    return result, version


IMAGE_TMPFS = "256m"
IMAGE_SCRATCH_ROOT = "/scratch"
SCRATCH = "/tmp"  # noqa: S108


def scan_image(reference: str) -> tuple[SandboxResult, str | None]:
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
        except Exception:  # noqa: BLE001
            version = None
    return result, version


def parse(document: dict) -> tuple[list[ObservedComponent], list[str], list[str]]:
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
    for entry in artifact.get("cpes") or []:
        if isinstance(entry, str) and entry.startswith("cpe:"):
            return entry
        if isinstance(entry, dict):
            value = entry.get("cpe")
            if isinstance(value, str) and value.startswith("cpe:"):
                return value
    return None


def _scope_for(artifact_id: str | None, direct: set[str] | None) -> str:
    if direct is None:
        return "unknown"
    return "direct" if artifact_id in direct else "transitive"


def _direct_artifact_ids(document: dict) -> set[str] | None:
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
    if not re.fullmatch(r"imagescan-[0-9a-f]{12}", scratch):
        log.warning("imagescan.refused_removal", scratch=scratch)
        return
    try:
        shutil.rmtree(pathlib.Path(work_dir) / scratch, ignore_errors=True)
    except OSError as exc:  # noqa: BLE001
        log.warning("imagescan.scratch_not_removed", scratch=scratch, error=str(exc))
