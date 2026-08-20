"""Syft adapter: filesystem or image → components.

Syft is the fact-establishing tool; this module only translates its output into
Athena's model. Tool name and version travel with the result so every component can
answer "how do you know that, and with what".
"""

from __future__ import annotations

import structlog

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


def scan_image(reference: str) -> tuple[SandboxResult, str | None]:
    """Run Syft against an image reference.

    Needs network to pull the image, unlike a directory scan. That is the only
    reason this differs from scan_directory, and it is why the reference is passed
    as a fixed argument rather than interpolated into a shell.
    """
    result = run_sandboxed(
        SandboxSpec(
            image=SYFT_IMAGE,
            command=["scan", f"registry:{reference}", "-o", "syft-json", "-q"],
            network="bridge",
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
