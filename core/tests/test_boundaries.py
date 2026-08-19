"""Privilege-boundary tests.

Technical Design §1: the executor must have no path to the AI layer, and the
investigation layer must have no path to execution. A boundary that depends on
developer discipline is not a boundary, so it is asserted here and in CI.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
INVESTIGATION = REPO / "core" / "athena" / "investigation"

FORBIDDEN = [
    # (package root, module prefix it must never import, why)
    (REPO / "executor", "athena.llm", "the executor must not be able to reach the AI layer"),
    (REPO / "executor", "athena.investigation", "the executor must not reason"),
    (INVESTIGATION, "athena.execution", "investigation must not execute"),
    (INVESTIGATION, "athena.executor", "investigation must not execute"),
]


def _imported_modules(path: pathlib.Path) -> set[str]:
    modules: set[str] = set()
    for py in path.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                modules.add(node.module)
    return modules


@pytest.mark.parametrize(("root", "forbidden", "why"), FORBIDDEN)
def test_forbidden_import(root: pathlib.Path, forbidden: str, why: str) -> None:
    if not root.exists():
        pytest.skip(f"{root.name} does not exist yet")
    offenders = {
        m for m in _imported_modules(root)
        if m == forbidden or m.startswith(forbidden + ".")
    }
    assert not offenders, f"{root.name} imports {offenders}: {why}"


def test_executor_declares_no_model_dependency() -> None:
    """The separation is only real if the executor image cannot install a model client."""
    text = (REPO / "executor" / "pyproject.toml").read_text(encoding="utf-8").lower()
    for banned in ("anthropic", "openai", "litellm", "langchain", "athena-core"):
        assert banned not in text.split("[tool.")[0], f"executor must not depend on {banned}"
