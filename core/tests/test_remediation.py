"""Remediation classification.

The property under test is that each class points at the place the change actually
has to be made. An npm package in a manifest, a Python library pulled in by something
else, a distribution package on a host, and the same package baked into an image all
have a fixed version and four different routes to installing it — and a plan that
sends somebody to the wrong one is worse than no plan, because they will try it.
"""

from __future__ import annotations

import pytest

from athena.remediation import RemediationClass, plan_for


def _plan(**kw):
    base = dict(
        ecosystem="pypi", package="pillow", installed_version="10.2.0",
        fixed_version="10.3.0", asset_kind="image", asset_name="app:1",
        scope="direct", fix_channel="standard",
    )
    return plan_for(**{**base, **kw})


# ── what is even possible comes first ────────────────────────────────────────


def test_no_published_fix_outranks_everything_else():
    """A perfect upgrade path to a version nobody can install is not a plan."""
    p = _plan(fixed_version=None, ecosystem="deb", asset_kind="host")
    assert p.klass is RemediationClass.NO_FIX
    assert not p.actionable
    assert p.command is None


def test_an_entitlement_gated_fix_is_not_ordinary_work():
    """It is a real fix this operator may have no way to install. Presenting it as
    routine sends somebody to run a command that cannot succeed."""
    p = _plan(ecosystem="deb", asset_kind="host", fix_channel="esm")
    assert p.klass is RemediationClass.ENTITLEMENT
    assert not p.actionable
    assert "ESM" in p.blocked_by


# ── the same package, different places ───────────────────────────────────────


def test_a_distro_package_on_a_host_gets_a_command():
    p = _plan(ecosystem="deb", package="nginx", installed_version="1.24.0",
              fixed_version="1.24.0-2ubuntu7.1", asset_kind="host", asset_name="edge",
              scope="os")
    assert p.klass is RemediationClass.OS_PACKAGE
    assert "apt-get" in p.command
    assert p.change_at == "edge"


def test_the_same_package_inside_an_image_is_a_rebuild_not_a_command():
    """Running the package manager in a container fixes nothing that survives a
    restart, so offering the command would invite exactly that mistake."""
    p = _plan(ecosystem="deb", package="nginx", installed_version="1.24.0",
              fixed_version="1.24.0-2ubuntu7.1", asset_kind="image", asset_name="web:1",
              scope="os")
    assert p.klass is RemediationClass.BASE_IMAGE
    assert p.command is None
    assert "rebuilt" in p.blocked_by
    assert "Dockerfile" in p.change_at


# ── transitive dependencies ──────────────────────────────────────────────────


def test_a_transitive_dependency_is_reported_not_skipped():
    """The milestone asks for this case specifically: a transitive vulnerability with
    no parent upgrade must be reported as such rather than quietly dropped."""
    p = _plan(scope="transitive")
    assert p.klass is RemediationClass.TRANSITIVE
    assert not p.actionable
    assert p.unknowns, "it must say what it could not work out"


def test_a_transitive_plan_does_not_invent_the_parent():
    """The inventory records that a package is transitive but not what pulls it in.
    Naming a parent would be fabricating it, and 'upgrade the thing that depends on
    this' is not actionable without knowing what that thing is."""
    p = _plan(scope="transitive", package="urllib3")
    assert p.command is None
    assert any("which dependency requires" in u.lower() for u in p.unknowns)


# ── direct dependencies ──────────────────────────────────────────────────────


def test_a_direct_dependency_gets_the_pinning_command():
    p = _plan(ecosystem="npm", package="tar", installed_version="7.5.11",
              fixed_version="7.5.12", scope="direct")
    assert p.klass is RemediationClass.DEPENDENCY
    assert p.command == "npm install tar@7.5.12"


def test_an_image_dependency_admits_it_cannot_find_the_source():
    """The change belongs in whatever repository builds the image, and no repository
    is registered for it — so the plan says so rather than implying the change can be
    made on the image."""
    p = _plan(asset_kind="image", asset_name="app:2026.3")
    assert "manifest that builds" in p.change_at
    assert any("no source is registered" in u for u in p.unknowns)


def test_an_ecosystem_with_no_safe_one_liner_offers_none():
    """Editing a POM is not a one-liner, and pretending otherwise produces a command
    that does not work."""
    p = _plan(ecosystem="maven", package="log4j", fixed_version="2.17.1")
    assert p.command is None


def test_every_class_is_reachable():
    """A classifier with an unreachable branch is a branch nobody has tested."""
    seen = {
        _plan(fixed_version=None).klass,
        _plan(fix_channel="esm").klass,
        _plan(ecosystem="deb", asset_kind="host", scope="os").klass,
        _plan(ecosystem="deb", asset_kind="image", scope="os").klass,
        _plan(scope="transitive").klass,
        _plan(scope="direct").klass,
    }
    assert seen == {
        RemediationClass.NO_FIX, RemediationClass.ENTITLEMENT,
        RemediationClass.OS_PACKAGE, RemediationClass.BASE_IMAGE,
        RemediationClass.TRANSITIVE, RemediationClass.DEPENDENCY,
    }
