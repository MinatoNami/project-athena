"""What a checkout declares, as a check on what the scanner found.

Syft catalogued this repository and reported 754 npm packages and nothing else. The
scan was recorded as succeeded with no warnings, and the asset showed as fully
inventoried — while `core/pyproject.toml`, declaring eleven runtime dependencies, had
never been read. Nothing in the pipeline could notice, because every check operated on
what the SBOM contained rather than on what it should have contained.

This reads the manifests in the tree and asks a question the SBOM cannot answer about
itself: something here declares dependencies in an ecosystem the scan reported nothing
for. That is a gap in what is known, not a known limitation, so it makes the scan
partial and the asset stays stale — which is the truth.

Manifests are counted, not trusted for versions. `fastapi>=0.115` is not a version and
recording it as one would put an unmatched range into correlation. The declaration is
evidence that something is there, and that is all it is used for.
"""

from __future__ import annotations

import json
import pathlib
import re
import tomllib
from dataclasses import dataclass

import structlog

log = structlog.get_logger(__name__)

# Directories that hold somebody else's manifests. A `package.json` inside
# node_modules describes a dependency, not a declaration by this repository, and
# walking them turns a check into a crawl.
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "vendor", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".output", ".nuxt", "target", ".tox",
}

# Bounded deliberately: this is a cross-check, not an inventory, and a repository
# with thousands of manifests is not one where reading all of them changes the answer.
MAX_FILES = 400
MAX_BYTES = 2_000_000

_REQ_LINE = re.compile(r"^\s*[A-Za-z0-9._-]+\s*(?:[<>=!~\[]|$)")


@dataclass(frozen=True)
class Declaration:
    """A manifest that names dependencies, and how many it names."""

    path: str
    ecosystem: str
    declared: int


def declarations(root: pathlib.Path) -> list[Declaration]:
    """Every manifest in the tree that declares at least one dependency.

    A manifest declaring nothing is not evidence of anything. This repository's
    `node/go.mod` names a module and a Go version and requires no third-party
    package at all — syft reporting no Go components for it is correct, and treating
    the file's presence as a gap would manufacture a permanent false alarm.
    """
    found: list[Declaration] = []
    seen = 0
    for path in _walk(root):
        seen += 1
        if seen > MAX_FILES:
            log.warning("manifests.truncated", root=str(root), limit=MAX_FILES)
            break
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        ecosystem, count = _declared(path.name, text)
        if ecosystem and count:
            found.append(
                Declaration(
                    path=str(path.relative_to(root)), ecosystem=ecosystem, declared=count
                )
            )
    return found


def gaps(declared: list[Declaration], ecosystems: set[str]) -> list[str]:
    """Ecosystems declared in the tree that the SBOM reported nothing for.

    Phrased so that whoever reads it knows both what is missing and what would close
    it. A gap nobody can act on reads as noise and gets ignored, which costs more
    than not reporting it.
    """
    out: list[str] = []
    for ecosystem in sorted({d.ecosystem for d in declared} - ecosystems):
        files = [d for d in declared if d.ecosystem == ecosystem]
        total = sum(d.declared for d in files)
        where = ", ".join(sorted(d.path for d in files)[:3])
        out.append(
            f"{total} {ecosystem} dependenc{'y' if total == 1 else 'ies'} are declared "
            f"in {where} but the scan found no {ecosystem} components. "
            + _remedy(ecosystem)
        )
    return out


def _remedy(ecosystem: str) -> str:
    """Why the scanner could not see it, where that is known."""
    if ecosystem == "pypi":
        return (
            "Declared ranges are not versions, so nothing here can be matched against "
            "an advisory; a lock file (requirements.txt, poetry.lock or uv.lock) "
            "committed alongside would make them resolvable. Until then these packages "
            "are only visible where they are installed, such as in a built image."
        )
    return "The scanner may not read this manifest format from source."


def _walk(root: pathlib.Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.name in _HANDLERS or _REQUIREMENTS.match(path.name):
            yield path


def _declared(name: str, text: str) -> tuple[str | None, int]:
    if _REQUIREMENTS.match(name):
        return "pypi", _count_requirements(text)
    handler = _HANDLERS.get(name)
    return handler(text) if handler else (None, 0)


def _count_requirements(text: str) -> int:
    return sum(
        1
        for line in text.splitlines()
        if _REQ_LINE.match(line) and not line.lstrip().startswith(("#", "-"))
    )


def _pyproject(text: str) -> tuple[str, int]:
    """setuptools and poetry layouts both, since either may be what a repo uses."""
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return "pypi", 0
    project = doc.get("project") or {}
    count = len(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        count += len(extra or [])
    poetry = ((doc.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    # `python` is the interpreter constraint, not a package.
    count += len([k for k in poetry if k != "python"])
    return "pypi", count


def _package_json(text: str) -> tuple[str, int]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return "npm", 0
    return "npm", sum(
        len(doc.get(k) or {}) for k in ("dependencies", "devDependencies", "peerDependencies")
    )


def _go_mod(text: str) -> tuple[str, int]:
    """Counts `require` entries only. A module that requires nothing declares nothing."""
    count, in_block = 0, False
    for raw in text.splitlines():
        line = raw.strip()
        if in_block:
            if line == ")":
                in_block = False
            elif line and not line.startswith("//"):
                count += 1
        elif line.startswith("require ("):
            in_block = True
        elif line.startswith("require "):
            count += 1
    return "golang", count


def _gemfile(text: str) -> tuple[str, int]:
    return "gem", len(re.findall(r"^\s*gem\s+['\"]", text, re.MULTILINE))


def _cargo(text: str) -> tuple[str, int]:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return "cargo", 0
    return "cargo", len(doc.get("dependencies") or {}) + len(
        (doc.get("dev-dependencies") or {})
    )


_REQUIREMENTS = re.compile(r"^requirements.*\.txt$")

_HANDLERS = {
    "pyproject.toml": _pyproject,
    "setup.py": lambda t: ("pypi", len(re.findall(r"['\"][A-Za-z0-9._-]+\s*[<>=~]", t))),
    "package.json": _package_json,
    "go.mod": _go_mod,
    "Gemfile": _gemfile,
    "Cargo.toml": _cargo,
}
