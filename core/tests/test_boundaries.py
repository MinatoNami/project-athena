from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
INVESTIGATION = REPO / "core" / "athena" / "investigation"
EXECUTOR_PACKAGE = REPO / "executor" / "athena_executor"
EXECUTOR_ACTIONS = EXECUTOR_PACKAGE / "actions"

SHELL_ALLOWED_ACTION_MODULES: frozenset[str] = frozenset()

SHELL_MODULES = {"subprocess", "pty", "pexpect", "sh", "plumbum", "asyncio.subprocess"}
ASYNCIO_SHELL_CALLS = {"create_subprocess_exec", "create_subprocess_shell"}

FORBIDDEN = [
    (EXECUTOR_PACKAGE, "athena", "the executor must not import core"),
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
            elif _is_dynamic_import(node):
                modules.add(node.args[0].value)
    return modules


def _is_dynamic_import(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call) or not node.args:
        return False
    first = node.args[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return False
    func = node.func
    return (isinstance(func, ast.Name) and func.id == "__import__") or (
        isinstance(func, ast.Attribute) and func.attr == "import_module"
    )


def _is_os_exec(name: str) -> bool:
    return name in {"system", "popen", "fork", "forkpty"} or name.startswith(
        ("exec", "spawn", "posix_spawn")
    )


def _shell_reach(source: str) -> set[str]:
    tree = ast.parse(source)
    found: set[str] = set()
    aliases = {"os": "os", "asyncio": "asyncio"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in SHELL_MODULES or alias.name.split(".")[0] in SHELL_MODULES:
                    found.add(alias.name)
                if alias.name in ("os", "asyncio"):
                    aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module in SHELL_MODULES or node.module.split(".")[0] in SHELL_MODULES:
                found.add(node.module)
            for alias in node.names:
                if node.module == "os" and _is_os_exec(alias.name):
                    found.add(f"os.{alias.name}")
                if node.module == "asyncio" and alias.name in ASYNCIO_SHELL_CALLS | {"subprocess"}:
                    found.add(f"asyncio.{alias.name}")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = aliases.get(node.value.id)
            if module == "os" and _is_os_exec(node.attr):
                found.add(f"os.{node.attr}")
            if module == "asyncio" and node.attr in ASYNCIO_SHELL_CALLS | {"subprocess"}:
                found.add(f"asyncio.{node.attr}")
        elif _is_dynamic_import(node) and node.args[0].value.split(".")[0] in SHELL_MODULES:
            found.add(node.args[0].value)
    return found


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
    text = (REPO / "executor" / "pyproject.toml").read_text(encoding="utf-8").lower()
    for banned in ("anthropic", "openai", "litellm", "langchain", "athena-core"):
        assert banned not in text.split("[tool.")[0], f"executor must not depend on {banned}"


def _action_modules() -> dict[str, pathlib.Path]:
    return {
        ".".join(py.relative_to(EXECUTOR_PACKAGE.parent).with_suffix("").parts): py
        for py in EXECUTOR_ACTIONS.rglob("*.py")
    }


def test_executor_action_modules_exist() -> None:
    assert "athena_executor.actions.noop" in _action_modules()


@pytest.mark.parametrize("module", sorted(_action_modules()))
def test_action_modules_have_no_shell(module: str) -> None:
    if module in SHELL_ALLOWED_ACTION_MODULES:
        pytest.skip(f"{module} is allowlisted for a shell")
    source = _action_modules()[module].read_text(encoding="utf-8")
    reach = _shell_reach(source)
    assert not reach, (
        f"{module} reaches a shell through {sorted(reach)}; an action gets one only by being"
        " named in SHELL_ALLOWED_ACTION_MODULES"
    )


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess",
        "import subprocess as sp",
        "from subprocess import run",
        "import pty",
        "import os\nos.system('id')",
        "import os as o\no.popen('id')",
        "from os import execv",
        "import os\nos.posix_spawn('/bin/sh', [], {})",
        "import asyncio\nasyncio.create_subprocess_shell('id')",
        "from asyncio import create_subprocess_exec",
        "from asyncio.subprocess import PIPE",
        "import importlib\nimportlib.import_module('subprocess')",
        "__import__('subprocess')",
    ],
)
def test_shell_detector_catches_the_usual_routes(source: str) -> None:
    assert _shell_reach(source)


def test_shell_detector_allows_harmless_os_use() -> None:
    assert not _shell_reach("import os\nos.path.join('a', 'b')\nos.environ.get('X')")


def test_dynamic_imports_count_as_imports(tmp_path: pathlib.Path) -> None:
    (tmp_path / "m.py").write_text("import importlib\nimportlib.import_module('athena.llm')")
    assert "athena.llm" in _imported_modules(tmp_path)
