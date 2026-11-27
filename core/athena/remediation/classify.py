from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from athena.remediation.source import SourceRef

DISTRO_ECOSYSTEMS = {"deb", "rpm", "apk"}

DISTRO_COMMAND = {
    "deb": "apt-get install --only-upgrade {name}={version}",
    "rpm": "dnf upgrade-minimal {name}-{version}",
    "apk": "apk upgrade {name}",
}


class RemediationClass(StrEnum):
    OS_PACKAGE = "os_package"
    BASE_IMAGE = "base_image"
    DEPENDENCY = "dependency"
    TRANSITIVE = "transitive"
    NO_FIX = "no_fix"
    ENTITLEMENT = "entitlement"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class RemediationPlan:
    klass: RemediationClass
    summary: str
    command: str | None = None
    change_at: str = ""
    blocked_by: str | None = None
    unknowns: list[str] = field(default_factory=list)
    actionable: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "class": str(self.klass),
            "summary": self.summary,
            "command": self.command,
            "change_at": self.change_at,
            "blocked_by": self.blocked_by,
            "unknowns": self.unknowns,
            "actionable": self.actionable,
        }


def plan_for(
    *,
    ecosystem: str,
    package: str,
    installed_version: str,
    fixed_version: str | None,
    asset_kind: str,
    asset_name: str,
    scope: str | None,
    fix_channel: str | None,
    source: SourceRef | None = None,
    malicious: bool = False,
) -> RemediationPlan:
    ecosystem = (ecosystem or "").lower()

    if malicious:
        return _malware_plan(
            ecosystem=ecosystem, package=package, installed_version=installed_version,
            asset_kind=asset_kind, asset_name=asset_name, source=source,
        )

    if not fixed_version:
        return RemediationPlan(
            klass=RemediationClass.NO_FIX,
            summary=f"No fixed version of {package} has been published yet.",
            change_at=asset_name,
            actionable=False,
            blocked_by="the maintainers have not published a fix",
            unknowns=["When a fix will be available"],
        )

    if fix_channel and fix_channel != "standard":
        return RemediationPlan(
            klass=RemediationClass.ENTITLEMENT,
            summary=(
                f"{package} {fixed_version} is published, but only through the "
                f"{fix_channel.upper()} channel."
            ),
            change_at=asset_name,
            actionable=False,
            blocked_by=f"the fix requires a subscription to {fix_channel.upper()}",
            unknowns=["Whether this host carries that entitlement"],
        )

    if ecosystem in DISTRO_ECOSYSTEMS:
        return _distro_plan(
            ecosystem=ecosystem, package=package, fixed_version=fixed_version,
            asset_kind=asset_kind, asset_name=asset_name, source=source,
        )

    if scope == "transitive":
        return RemediationPlan(
            klass=RemediationClass.TRANSITIVE,
            summary=(
                f"{package} {installed_version} is pulled in by another dependency, "
                f"not declared directly. {fixed_version} fixes it."
            ),
            change_at=f"whatever depends on {package}, in the source of {asset_name}",
            actionable=False,
            blocked_by="the package that requires this one has to move first",
            unknowns=[
                f"Which dependency requires {package} — the inventory records that "
                "this is transitive but not what pulls it in",
                "Whether a parent release exists that requires the fixed version",
            ],
        )

    change_at, unknowns = _change_site(
        asset_kind=asset_kind, asset_name=asset_name, artefact="manifest", source=source
    )
    return RemediationPlan(
        klass=RemediationClass.DEPENDENCY,
        summary=f"Upgrade {package} from {installed_version} to {fixed_version}.",
        command=_manifest_command(ecosystem, package, fixed_version),
        change_at=change_at,
        unknowns=unknowns,
    )


def _malware_plan(
    *, ecosystem: str, package: str, installed_version: str, asset_kind: str,
    asset_name: str, source: SourceRef | None,
) -> RemediationPlan:
    if asset_kind == "image":
        change_at, site_unknowns = _change_site(
            asset_kind=asset_kind, asset_name=asset_name, artefact="manifest", source=source
        )
    else:
        change_at, site_unknowns = asset_name, []
    return RemediationPlan(
        klass=RemediationClass.MALICIOUS,
        summary=(
            f"{package} {installed_version} is published malware, not a vulnerable "
            f"release. Remove it, then treat {asset_name} — and anything that "
            "installed it — as compromised: rotate every credential the install "
            "could read, and rebuild from a known-good state."
        ),
        change_at=change_at,
        unknowns=[
            *site_unknowns,
            "Whether the package's install-time code ran here, and as which user",
            "Which credentials were readable when it did — environment, dotfiles, "
            "CI secrets, cloud metadata",
            f"Which dependency, if any, pulled {package} in",
        ],
    )


def _change_site(
    *, asset_kind: str, asset_name: str, artefact: str, source: SourceRef | None
) -> tuple[str, list[str]]:
    if asset_kind != "image":
        return asset_name, []

    if source is None:
        return (
            f"wherever {asset_name} is built or pulled from",
            [
                f"Whether {asset_name} is an image you build or one you pull — no "
                "source is registered for it, so the change cannot be located "
                "automatically"
            ],
        )

    site = f"the {artefact} in {source.repository}"
    hint, scanned = source.commit_hint, source.scanned_commit

    if hint and scanned and scanned.startswith(hint):
        return f"{site}, at commit {hint}", []
    if hint:
        return site, [
            f"Whether the source has moved since {asset_name} was built — its tag "
            f"implies commit {hint}, which is a build convention rather than "
            f"anything {asset_name} records"
        ]
    return site, [f"Which commit {asset_name} was built from — its tag does not say"]


def _distro_plan(
    *, ecosystem: str, package: str, fixed_version: str, asset_kind: str, asset_name: str,
    source: SourceRef | None = None,
) -> RemediationPlan:
    if asset_kind == "image":
        change_at, unknowns = _change_site(
            asset_kind=asset_kind, asset_name=asset_name, artefact="Dockerfile", source=source
        )
        return RemediationPlan(
            klass=RemediationClass.BASE_IMAGE,
            summary=(
                f"{package} comes from a layer of {asset_name}, not from anything "
                f"installed at runtime. Rebuild on a base that carries {fixed_version}."
            ),
            change_at=change_at,
            actionable=False,
            blocked_by="the image has to be rebuilt; patching a running container does not persist",
            unknowns=[
                *unknowns,
                f"Which base image {asset_name} is built from",
                "Whether a rebuilt base already carries the fix",
            ],
        )

    command = DISTRO_COMMAND.get(ecosystem, "").format(name=package, version=fixed_version)
    return RemediationPlan(
        klass=RemediationClass.OS_PACKAGE,
        summary=f"Upgrade {package} to {fixed_version} with the package manager.",
        command=command or None,
        change_at=asset_name,
    )


def _manifest_command(ecosystem: str, package: str, version: str) -> str | None:
    return {
        "npm": f"npm install {package}@{version}",
        "pypi": f"pip install '{package}=={version}'",
        "golang": f"go get {package}@v{version}",
        "gem": f"bundle update {package} --conservative",
        "cargo": f"cargo update -p {package} --precise {version}",
        "maven": None,
        "nuget": f"dotnet add package {package} --version {version}",
    }.get(ecosystem)
