from __future__ import annotations

import hashlib
import os
import pathlib
import re
from dataclasses import dataclass, field

from athena.codefindings.model import CodeObservation

KIND = "startup-hook"
TOOL = "athena-pth"
TOOL_VERSION = "1"
RULE_ID = "pth-executable-import"
SEVERITY = "high"
TITLE = "A .pth file runs code at every Python start-up"

EVIDENCE_LIMIT = 200
MAX_BYTES = 1_000_000
MAX_FILES = 2_000
SKIP_DIRS = {".git"}

BENIGN_SHA256 = {
    "2638ce9e2500e572a5e0de7faed6661eb569d1b696fcba07b0dd223da5f5d224": (
        "setuptools distutils-precedence.pth, setuptools 60 to 84"
    ),
}

_EDITABLE_FILE = re.compile(r"__editable__\.[^/]+\.pth")
_EDITABLE_FINDER = re.compile(r"import (__editable___\w+_finder); \1\.install\(\)")


@dataclass(frozen=True)
class ExecutableLine:
    number: int
    text: str


@dataclass
class HookScan:
    observations: list[CodeObservation] = field(default_factory=list)
    files: int = 0
    allowlisted: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    truncated: bool = False


def _decode(content: bytes) -> str:
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("latin-1")


def executable_lines(content: bytes) -> list[ExecutableLine]:
    out: list[ExecutableLine] = []
    for number, line in enumerate(_decode(content).splitlines(), start=1):
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith(("import ", "import\t")):
            out.append(ExecutableLine(number=number, text=line))
    return out


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def benign_reason(name: str, content: bytes) -> str | None:
    if reason := BENIGN_SHA256.get(sha256(content)):
        return reason
    if _EDITABLE_FILE.fullmatch(name):
        lines = [line for line in _decode(content).splitlines() if line.strip()]
        if len(lines) == 1 and _EDITABLE_FINDER.fullmatch(lines[0].strip()):
            return "setuptools editable-install finder hook"
    return None


def _evidence(text: str) -> dict[str, object]:
    printable = text.encode("unicode_escape").decode("ascii")
    return {
        "line_text": printable[:EVIDENCE_LIMIT],
        "line_truncated": len(printable) > EVIDENCE_LIMIT,
    }


def observations_for(path: str, content: bytes) -> list[CodeObservation]:
    file_digest = sha256(content)
    out: list[CodeObservation] = []
    for hit in executable_lines(content):
        out.append(
            CodeObservation(
                kind=KIND,
                rule_id=RULE_ID,
                title=TITLE,
                severity=SEVERITY,
                path=path,
                line=hit.number,
                fingerprint=sha256(f"{KIND}:{path}:{hit.text}".encode("utf-8", "replace")),
                detail={**_evidence(hit.text), "file_sha256": file_digest},
            )
        )
    return out


def _pth_files(root: pathlib.Path):
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(".pth"):
                yield pathlib.Path(directory) / name


def scan_tree(root: pathlib.Path) -> HookScan:
    result = HookScan()
    for path in _pth_files(root):
        relative = path.relative_to(root).as_posix()
        if result.files >= MAX_FILES:
            result.truncated = True
            break
        result.files += 1
        try:
            if path.is_symlink() or not path.is_file():
                result.unread.append(relative)
                continue
            with path.open("rb") as handle:
                content = handle.read(MAX_BYTES + 1)
        except OSError:
            result.unread.append(relative)
            continue
        if len(content) > MAX_BYTES:
            result.unread.append(relative)
            continue
        if benign_reason(path.name, content):
            result.allowlisted.append(relative)
            continue
        result.observations.extend(observations_for(relative, content))
    return result
