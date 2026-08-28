"""Cross-checking a scan against what the tree declares.

The defect this exists for: syft catalogued this repository, reported 754 npm packages
and nothing else, and the scan was recorded as succeeded with no warnings. Eleven
Python dependencies in `core/pyproject.toml` had never been read, and no check could
notice, because every check asked whether what the SBOM contained was sound rather
than whether it contained everything.
"""

from __future__ import annotations

import pathlib

import pytest

from athena.scanners.manifests import Declaration, declarations, gaps


@pytest.fixture
def tree(tmp_path: pathlib.Path) -> pathlib.Path:
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "pyproject.toml").write_text(
        '[project]\nname = "athena"\ndependencies = ["fastapi>=0.115", "sqlalchemy>=2.0"]\n'
        '[project.optional-dependencies]\ndev = ["pytest>=8.3"]\n'
    )
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(
        '{"dependencies": {"nuxt": "^4.0.0"}, "devDependencies": {"eslint": "^9"}}'
    )
    return tmp_path


def test_a_declared_ecosystem_the_scan_never_saw_is_a_gap(tree):
    """The whole point. Nothing about the SBOM itself reveals this."""
    found = declarations(tree)
    reported = gaps(found, {"npm"})
    assert len(reported) == 1
    assert "3 pypi dependencies are declared" in reported[0]
    assert "core/pyproject.toml" in reported[0]


def test_a_gap_says_what_would_close_it(tree):
    """A gap nobody can act on reads as noise and gets ignored, which costs more
    than not reporting it at all."""
    reported = gaps(declarations(tree), {"npm"})
    assert "lock file" in reported[0]
    assert "built image" in reported[0]


def test_nothing_is_reported_when_the_scan_covered_everything(tree):
    assert gaps(declarations(tree), {"npm", "pypi"}) == []


def test_a_manifest_that_declares_nothing_is_not_a_gap(tmp_path):
    """This repository's Go agent requires no third-party package at all. Syft
    reporting no Go components for it is correct, and treating the file's presence as
    a gap would manufacture a permanent false alarm on a scan that was complete."""
    (tmp_path / "go.mod").write_text(
        "module github.com/example/agent\n\ngo 1.23\n"
    )
    assert declarations(tmp_path) == []
    assert gaps(declarations(tmp_path), {"npm"}) == []


def test_a_go_module_that_does_require_things_is_counted(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module x\n\ngo 1.23\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\t// a comment\n"
        "\tgithub.com/c/d v0.1.0\n)\n"
    )
    assert declarations(tmp_path) == [Declaration("go.mod", "golang", 2)]


def test_vendored_manifests_are_somebody_elses_declarations(tmp_path):
    """A package.json inside node_modules describes a dependency, not a declaration
    by this repository — and walking them turns a check into a crawl."""
    nested = tmp_path / "node_modules" / "left-pad"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"dependencies": {"x": "1"}}')
    assert declarations(tmp_path) == []


def test_declared_ranges_are_never_mistaken_for_versions(tree):
    """`fastapi>=0.115` is not a version. The declaration is evidence that something
    is there and nothing more — recording it as a component would put an unmatchable
    range into correlation."""
    found = declarations(tree)
    assert all(isinstance(d.declared, int) for d in found)
    assert not any(hasattr(d, "version") for d in found)


def test_requirements_files_are_read_as_pypi(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment\n\nfastapi==0.115.0\nhttpx>=0.28\n-r other.txt\n"
    )
    assert declarations(tmp_path) == [Declaration("requirements.txt", "pypi", 2)]


def test_a_poetry_layout_is_read_too(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\npython = "^3.12"\nrequests = "^2.31"\n'
    )
    assert declarations(tmp_path) == [Declaration("pyproject.toml", "pypi", 1)]


def test_unparseable_manifests_do_not_break_the_scan(tmp_path):
    """A malformed file is not a reason to fail a scan that otherwise succeeded."""
    (tmp_path / "pyproject.toml").write_text("[project\nthis is not toml")
    (tmp_path / "package.json").write_text("{not json")
    assert declarations(tmp_path) == []
