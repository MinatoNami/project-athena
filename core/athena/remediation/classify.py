"""What kind of remediation a finding needs, and what that implies.

Nothing here changes anything. It answers a question that has to be settled before a
patch can be prepared at all: *what sort of problem is this?* An npm package pinned
in a manifest, a Python library pulled in by something else, a distribution package
on a host, and a package baked into a base image all have a fixed version — and four
entirely different routes to installing it. Treating them alike is how a tool comes
to recommend `pip install` for something that arrived in the base layer.

Two rules run through this module.

A plan says what it could not determine. A transitive dependency's parent is not
recorded anywhere in the inventory, so a plan that named one would be inventing it —
and "upgrade the thing that depends on this" is not actionable without knowing what
that thing is. The milestone asks for exactly this case to be reported rather than
silently skipped.

A fix existing is not the same as a fix being available to you. A version behind a
paid entitlement is a real fix that this operator may have no way to install, and
presenting it as ordinary work would send somebody to run a command that cannot
succeed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# Ecosystems whose packages are installed by a distribution's package manager rather
# than by an application's manifest.
DISTRO_ECOSYSTEMS = {"deb", "rpm", "apk"}

# The package manager that owns each, for the concrete command.
DISTRO_COMMAND = {
    "deb": "apt-get install --only-upgrade {name}={version}",
    "rpm": "dnf upgrade-minimal {name}-{version}",
    "apk": "apk upgrade {name}",
}


class RemediationClass(StrEnum):
    """Why these are separate: each implies a different place to make the change."""

    OS_PACKAGE = "os_package"      # a host's package manager
    BASE_IMAGE = "base_image"      # rebuild on a newer base; the host cannot patch it
    DEPENDENCY = "dependency"      # a manifest the operator controls
    TRANSITIVE = "transitive"      # something else's manifest
    NO_FIX = "no_fix"              # nothing published yet
    ENTITLEMENT = "entitlement"    # a fix exists, behind a subscription
    UNKNOWN = "unknown"            # not enough recorded to say


@dataclass
class RemediationPlan:
    klass: RemediationClass
    # What to do, phrased for somebody who has to act on it.
    summary: str
    # The concrete command, where one exists and is safe to state. None is a real
    # answer: for a transitive dependency there is no command to give.
    command: str | None = None
    # Where the change has to be made — not always the asset the finding is on.
    change_at: str = ""
    # What stops this being actionable now, if anything.
    blocked_by: str | None = None
    # Stated rather than left implicit. Everything this plan could not establish.
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
) -> RemediationPlan:
    """Classify one finding and describe the route to fixing it.

    Order matters. Whether a fix exists, and whether this operator can obtain it, are
    settled before what kind of package it is — a perfect upgrade path to a version
    nobody can install is not a plan.
    """
    ecosystem = (ecosystem or "").lower()

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
            blocked_by=f"the fix requires a {fix_channel.upper()} subscription",
            unknowns=["Whether this host carries that entitlement"],
        )

    if ecosystem in DISTRO_ECOSYSTEMS:
        return _distro_plan(
            ecosystem=ecosystem, package=package, fixed_version=fixed_version,
            asset_kind=asset_kind, asset_name=asset_name,
        )

    if scope == "transitive":
        return RemediationPlan(
            klass=RemediationClass.TRANSITIVE,
            summary=(
                f"{package} {installed_version} is pulled in by another dependency, "
                f"not declared directly. {fixed_version} fixes it."
            ),
            # Deliberately no command. Upgrading it directly would either be undone
            # by the next resolve or break the parent that pinned it.
            change_at=f"whatever depends on {package}, in the source of {asset_name}",
            actionable=False,
            blocked_by="the package that requires this one has to move first",
            unknowns=[
                f"Which dependency requires {package} — the inventory records that "
                "this is transitive but not what pulls it in",
                "Whether a parent release exists that requires the fixed version",
            ],
        )

    return RemediationPlan(
        klass=RemediationClass.DEPENDENCY,
        summary=f"Upgrade {package} from {installed_version} to {fixed_version}.",
        command=_manifest_command(ecosystem, package, fixed_version),
        change_at=(
            f"the manifest that builds {asset_name}"
            if asset_kind == "image"
            else asset_name
        ),
        unknowns=(
            [
                f"Which repository builds {asset_name} — no source is registered "
                "for it, so the change cannot be located automatically"
            ]
            if asset_kind == "image"
            else []
        ),
    )


def _distro_plan(
    *, ecosystem: str, package: str, fixed_version: str, asset_kind: str, asset_name: str
) -> RemediationPlan:
    """A distribution package. Where it lives decides who can fix it.

    The same package on a host and inside an image are different problems. On a host
    the package manager installs the fix. Inside an image it came from a layer, and
    running the package manager in the container fixes nothing that survives a
    restart — the image has to be rebuilt.
    """
    if asset_kind == "image":
        return RemediationPlan(
            klass=RemediationClass.BASE_IMAGE,
            summary=(
                f"{package} comes from a layer of {asset_name}, not from anything "
                f"installed at runtime. Rebuild on a base that carries {fixed_version}."
            ),
            # No command on purpose: upgrading inside a running container is undone by
            # the next restart, and offering the command invites exactly that.
            change_at=f"the Dockerfile behind {asset_name}",
            actionable=False,
            blocked_by="the image has to be rebuilt; patching a running container does not persist",
            unknowns=[
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
    """The command that pins the fixed version, where the ecosystem has one.

    Returned as guidance, not as something to run unattended: it changes a manifest,
    and what that does to the rest of the dependency graph is not known here.
    """
    return {
        "npm": f"npm install {package}@{version}",
        "pypi": f"pip install '{package}=={version}'",
        "golang": f"go get {package}@v{version}",
        "gem": f"bundle update {package} --conservative",
        "cargo": f"cargo update -p {package} --precise {version}",
        "maven": None,      # editing a POM is not a one-liner worth pretending it is
        "nuget": f"dotnet add package {package} --version {version}",
    }.get(ecosystem)
