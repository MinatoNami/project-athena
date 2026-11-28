from __future__ import annotations

from athena.remediation import RemediationClass, plan_for


def _plan(**kw):
    base = dict(
        ecosystem="pypi", package="pillow", installed_version="10.2.0",
        fixed_version="10.3.0", asset_kind="image", asset_name="app:1",
        scope="direct", fix_channel="standard",
    )
    return plan_for(**{**base, **kw})


def test_no_published_fix_outranks_everything_else():
    p = _plan(fixed_version=None, ecosystem="deb", asset_kind="host")
    assert p.klass is RemediationClass.NO_FIX
    assert not p.actionable
    assert p.command is None


def test_an_entitlement_gated_fix_is_not_ordinary_work():
    p = _plan(ecosystem="deb", asset_kind="host", fix_channel="esm")
    assert p.klass is RemediationClass.ENTITLEMENT
    assert not p.actionable
    assert "ESM" in p.blocked_by


def test_a_distro_package_on_a_host_gets_a_command():
    p = _plan(ecosystem="deb", package="nginx", installed_version="1.24.0",
              fixed_version="1.24.0-2ubuntu7.1", asset_kind="host", asset_name="edge",
              scope="os")
    assert p.klass is RemediationClass.OS_PACKAGE
    assert "apt-get" in p.command
    assert p.change_at == "edge"


def test_the_same_package_inside_an_image_is_a_rebuild_not_a_command():
    p = _plan(ecosystem="deb", package="nginx", installed_version="1.24.0",
              fixed_version="1.24.0-2ubuntu7.1", asset_kind="image", asset_name="web:1",
              scope="os")
    assert p.klass is RemediationClass.BASE_IMAGE
    assert p.command is None
    assert "rebuilt" in p.blocked_by


def test_a_transitive_dependency_is_reported_not_skipped():
    p = _plan(scope="transitive")
    assert p.klass is RemediationClass.TRANSITIVE
    assert not p.actionable
    assert p.unknowns, "it must say what it could not work out"


def test_a_transitive_plan_does_not_invent_the_parent():
    p = _plan(scope="transitive", package="urllib3")
    assert p.command is None
    assert any("which dependency requires" in u.lower() for u in p.unknowns)


def test_a_direct_dependency_gets_the_pinning_command():
    p = _plan(ecosystem="npm", package="tar", installed_version="7.5.11",
              fixed_version="7.5.12", scope="direct")
    assert p.klass is RemediationClass.DEPENDENCY
    assert p.command == "npm install tar@7.5.12"


def test_an_image_dependency_admits_it_cannot_find_the_source():
    p = _plan(asset_kind="image", asset_name="app:2026.3")
    assert p.change_at == "wherever app:2026.3 is built or pulled from"
    assert any("no source is registered" in u for u in p.unknowns)


def test_an_ecosystem_with_no_safe_one_liner_offers_none():
    p = _plan(ecosystem="maven", package="log4j", fixed_version="2.17.1")
    assert p.command is None


def test_every_class_is_reachable():
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


def _source(**kw):
    from athena.remediation import SourceRef

    base = dict(
        repository="project-athena",
        clone_url="https://github.com/example/project-athena.git",
        default_branch="main",
    )
    return SourceRef(**{**base, **kw})


def test_a_registered_source_turns_a_dead_end_into_a_file_to_edit():
    without = _plan(ecosystem="npm", package="tar")
    with_source = _plan(ecosystem="npm", package="tar", source=_source())

    assert "no source is registered" in " ".join(without.unknowns)
    assert with_source.change_at == "the manifest in project-athena"
    assert not any("no source is registered" in u for u in with_source.unknowns)


def test_a_base_image_rebuild_is_located_the_same_way():
    p = _plan(ecosystem="deb", package="zlib1g", source=_source())
    assert p.klass is RemediationClass.BASE_IMAGE
    assert p.change_at == "the Dockerfile in project-athena"
    assert p.command is None


def test_a_tag_that_looks_like_a_commit_is_not_treated_as_one():
    p = _plan(ecosystem="npm", source=_source(commit_hint="cfbe483"))
    assert p.change_at == "the manifest in project-athena"
    assert any("build convention" in u and "cfbe483" in u for u in p.unknowns)


def test_a_tag_matching_a_real_commit_stops_being_a_guess():
    p = _plan(
        ecosystem="npm",
        source=_source(commit_hint="cfbe483", scanned_commit="cfbe483d9a71c0ff1e2b"),
    )
    assert p.change_at == "the manifest in project-athena, at commit cfbe483"
    assert p.unknowns == []


def test_a_tag_that_says_nothing_admits_the_revision_is_unknown():
    p = _plan(ecosystem="npm", asset_name="app:latest", source=_source())
    assert any("does not say" in u for u in p.unknowns)


def test_a_host_finding_is_unaffected_by_source_registration():
    p = _plan(ecosystem="deb", asset_kind="host", asset_name="node-1", source=_source())
    assert p.klass is RemediationClass.OS_PACKAGE
    assert p.change_at == "node-1"
    assert p.unknowns == []


def test_an_unsourced_image_is_not_assumed_to_be_one_you_build():
    p = _plan(ecosystem="apk", package="curl", asset_name="caddy:2-alpine")
    assert p.klass is RemediationClass.BASE_IMAGE
    assert "Dockerfile" not in p.change_at
    assert any("build or one you pull" in u for u in p.unknowns)


def test_the_entitlement_channel_reads_as_english():
    p = _plan(ecosystem="deb", asset_kind="host", fix_channel="esm")
    assert "subscription to ESM" in (p.blocked_by or "")
