from __future__ import annotations

import contextlib
import hashlib
import types
import uuid

import pytest
from sqlalchemy import select

from athena.scanners import startup_hooks
from athena.scanners.sandbox import SandboxError

DISTUTILS_PRECEDENCE = (
    b"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') "
    b"== 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"
)
EDITABLE_FINDER = (
    b"import __editable___demo_pkg_0_1_0_finder; __editable___demo_pkg_0_1_0_finder.install()"
)
MALICIOUS = b"/opt/app/lib\nimport base64, subprocess; exec(base64.b64decode('cHJpbnQoMSk='))\n"


def _lines(content: bytes) -> list[tuple[int, str]]:
    return [(hit.number, hit.text) for hit in startup_hooks.executable_lines(content)]


def test_an_import_line_is_executable():
    assert _lines(b"import os; os.system('id')\n") == [(1, "import os; os.system('id')")]


def test_a_tab_after_import_is_executable_too():
    assert _lines(b"import\tos\n") == [(1, "import\tos")]


def test_path_lines_only_extend_sys_path():
    assert _lines(b"/opt/app/lib\nsrc\n../vendor\nimportlib_stuff\n") == []


def test_comment_and_blank_lines_are_skipped_as_site_skips_them():
    assert _lines(b"# import os\n\n   \n\t\nimport sys\n") == [(5, "import sys")]


def test_an_indented_import_is_a_path_not_code():
    assert _lines(b" import os\n\timport os\n") == []


def test_a_byte_order_mark_does_not_hide_an_import():
    assert _lines(b"\xef\xbb\xbfimport os\n") == [(1, "import os")]


def test_every_line_break_python_splits_on_is_honoured():
    assert _lines(b"/opt/lib\rimport a\r\nimport b\x0cimport c") == [
        (2, "import a"),
        (3, "import b"),
        (4, "import c"),
    ]


def test_setuptools_distutils_precedence_is_allowlisted_by_its_hash():
    assert hashlib.sha256(DISTUTILS_PRECEDENCE).hexdigest() in startup_hooks.BENIGN_SHA256
    assert startup_hooks.benign_reason("distutils-precedence.pth", DISTUTILS_PRECEDENCE)


def test_an_edited_distutils_precedence_is_not_allowlisted():
    tampered = DISTUTILS_PRECEDENCE.replace(b"add_shim()", b"add_shim(); import evil")
    assert startup_hooks.benign_reason("distutils-precedence.pth", tampered) is None


def test_an_editable_finder_hook_is_allowlisted_only_in_its_own_shape():
    assert startup_hooks.benign_reason("__editable__.demo_pkg-0.1.0.pth", EDITABLE_FINDER)
    assert startup_hooks.benign_reason("other.pth", EDITABLE_FINDER) is None
    extra = EDITABLE_FINDER + b"\nimport os"
    assert startup_hooks.benign_reason("__editable__.demo_pkg-0.1.0.pth", extra) is None
    mismatched = b"import __editable___a_finder; __editable___b_finder.install()"
    assert startup_hooks.benign_reason("__editable__.a-1.pth", mismatched) is None


def test_a_malicious_hook_becomes_a_high_observation_with_its_line_as_data():
    found = startup_hooks.observations_for("pkg/agent_framework.pth", MALICIOUS)
    assert len(found) == 1
    obs = found[0]
    assert obs.kind == "startup-hook" and obs.severity == "high"
    assert obs.rule_id == "pth-executable-import"
    assert obs.path == "pkg/agent_framework.pth" and obs.line == 2
    assert obs.detail["line_text"].startswith("import base64, subprocess; exec(")
    assert obs.detail["file_sha256"] == hashlib.sha256(MALICIOUS).hexdigest()
    assert "base64" not in obs.title


def test_a_long_or_unprintable_line_is_stored_escaped_and_truncated():
    content = b"import os; '\x1b[2J\xe2\x80\xae" + b"x" * 500 + b"'\n"
    obs = startup_hooks.observations_for("a.pth", content)[0]
    assert len(obs.detail["line_text"]) == startup_hooks.EVIDENCE_LIMIT
    assert obs.detail["line_truncated"] is True
    assert "\x1b" not in obs.detail["line_text"] and "\\x1b" in obs.detail["line_text"]
    assert "‮" not in obs.detail["line_text"]


def test_identity_survives_lines_moving_within_the_file():
    before = startup_hooks.observations_for("a.pth", b"import os\n")[0]
    after = startup_hooks.observations_for("a.pth", b"/lib\n\nimport os\n")[0]
    assert before.fingerprint == after.fingerprint and after.line == 3


def test_a_tree_walk_finds_hooks_skips_allowlisted_and_never_follows_links(tmp_path):
    site = tmp_path / ".venv" / "lib" / "site-packages"
    site.mkdir(parents=True)
    (site / "distutils-precedence.pth").write_bytes(DISTUTILS_PRECEDENCE)
    (site / "__editable__.demo_pkg-0.1.0.pth").write_bytes(EDITABLE_FINDER)
    (site / "evil.pth").write_bytes(MALICIOUS)
    (site / "paths.pth").write_bytes(b"/opt/app\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.pth").write_bytes(b"import os\n")
    outside = tmp_path.parent / f"outside-{uuid.uuid4().hex}.pth"
    outside.write_bytes(b"import os\n")
    (tmp_path / "linked.pth").symlink_to(outside)

    found = startup_hooks.scan_tree(tmp_path)

    assert [o.path for o in found.observations] == [".venv/lib/site-packages/evil.pth"]
    assert sorted(found.allowlisted) == [
        ".venv/lib/site-packages/__editable__.demo_pkg-0.1.0.pth",
        ".venv/lib/site-packages/distutils-precedence.pth",
    ]
    assert found.unread == ["linked.pth"]
    assert found.files == 5


def test_an_oversized_pth_is_unread_rather_than_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(startup_hooks, "MAX_BYTES", 10)
    (tmp_path / "big.pth").write_bytes(b"/" * 11)
    found = startup_hooks.scan_tree(tmp_path)
    assert found.unread == ["big.pth"] and found.observations == []


@pytest.fixture
def checkout(tmp_path, session, monkeypatch):
    import athena.workers.repository as repository
    from athena.db.models import Asset

    asset = Asset(
        kind="repository",
        identity_key=f"github.com/acme/{uuid.uuid4()}",
        display_name="acme/api",
        tier="production",
        exposure="internal",
    )
    session.add(asset)
    session.flush()

    @contextlib.contextmanager
    def scope():
        yield session
        session.flush()

    def no_sandbox(*_a, **_k):
        raise SandboxError("no sandbox in tests")

    monkeypatch.setattr(repository, "session_scope", scope)
    monkeypatch.setattr(repository, "publish", lambda *_a, **_k: None)
    monkeypatch.setattr(repository.secrets, "scan", no_sandbox)
    monkeypatch.setattr(repository.misconfig, "scan", no_sandbox)
    monkeypatch.setattr(
        repository,
        "get_settings",
        lambda: types.SimpleNamespace(
            work_dir=str(tmp_path),
            gitleaks_image="ghcr.io/gitleaks/gitleaks:v8.30.1",
            trivy_image="aquasec/trivy:0.69.0",
        ),
    )
    tree = tmp_path / "checkout-0123456789ab"
    tree.mkdir()
    return repository, asset, tree


def _hook_findings(session, asset):
    from athena.db.models import CodeFinding

    return (
        session.execute(
            select(CodeFinding).where(
                CodeFinding.asset_id == asset.id, CodeFinding.kind == "startup-hook"
            )
        )
        .scalars()
        .all()
    )


def _latest_run(session, asset):
    from athena.db.models import ScanRun

    return (
        session.execute(
            select(ScanRun)
            .where(ScanRun.asset_id == asset.id, ScanRun.kind == "startup-hook")
            .order_by(ScanRun.finished_at.desc())
        )
        .scalars()
        .first()
    )


@pytest.mark.usefixtures("engine")
def test_a_repository_scan_records_a_hook_then_resolves_it_once_gone(session, checkout):
    repository, asset, tree = checkout
    (tree / "agent_framework.pth").write_bytes(MALICIOUS)

    repository._scan_code(str(asset.id), tree.name, work_volume="unused", commit="ab" * 20)

    [finding] = _hook_findings(session, asset)
    assert finding.severity == "high" and finding.tool == "athena-pth"
    assert finding.path == "agent_framework.pth" and finding.line == 2
    assert finding.resolved_at is None
    assert _latest_run(session, asset).status == "succeeded"

    (tree / "agent_framework.pth").unlink()
    repository._scan_code(str(asset.id), tree.name, work_volume="unused", commit="cd" * 20)

    [finding] = _hook_findings(session, asset)
    assert finding.resolved_at is not None


@pytest.mark.usefixtures("engine")
def test_an_unreadable_hook_keeps_the_finding_open(session, checkout):
    repository, asset, tree = checkout
    (tree / "agent_framework.pth").write_bytes(MALICIOUS)
    repository._scan_code(str(asset.id), tree.name, work_volume="unused", commit="ab" * 20)

    (tree / "agent_framework.pth").unlink()
    outside = tree.parent / "elsewhere.pth"
    outside.write_bytes(MALICIOUS)
    (tree / "agent_framework.pth").symlink_to(outside)
    repository._scan_code(str(asset.id), tree.name, work_volume="unused", commit="cd" * 20)

    [finding] = _hook_findings(session, asset)
    assert finding.resolved_at is None
    assert _latest_run(session, asset).status == "partial"
