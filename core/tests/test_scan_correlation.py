from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from athena.db.models import Asset, Job, Node, NodeTask
from athena.inventory.service import ObservedComponent
from athena.workers import node_ingest, repository

pytestmark = pytest.mark.usefixtures("engine")


def _share(session, monkeypatch, module) -> None:
    @contextmanager
    def same_session():
        yield session
        session.flush()

    monkeypatch.setattr(module, "session_scope", same_session)


def _pending_correlations(session, asset: Asset) -> list[Job]:
    return (
        session.query(Job)
        .filter(
            Job.kind == "correlate.asset",
            Job.finished_at.is_(None),
            Job.payload["asset_id"].astext == str(asset.id),
        )
        .all()
    )


def _component() -> ObservedComponent:
    return ObservedComponent(ecosystem="npm", name=f"left-{uuid.uuid4().hex[:8]}", version="1.0.0")


@pytest.fixture
def scanned_repository(session, monkeypatch):
    _share(session, monkeypatch, repository)
    monkeypatch.setattr(
        repository,
        "get_settings",
        lambda: SimpleNamespace(
            work_volume="athena-work", work_dir="/nonexistent", code_scans_enabled=False
        ),
    )
    monkeypatch.setattr(repository, "clone", lambda url, **_: ("checkout-1", "a" * 40))
    monkeypatch.setattr(repository, "remove_checkout", lambda *_, **__: None)
    monkeypatch.setattr(
        repository.syft,
        "scan_directory",
        lambda *_, **__: (SimpleNamespace(ok=True, json=lambda: {}), "1.0.0"),
    )
    monkeypatch.setattr(repository.syft, "parse", lambda _: ([_component()], [], []))
    monkeypatch.setattr(repository.manifests, "declarations", lambda _: [])
    monkeypatch.setattr(repository.manifests, "gaps", lambda *_: [])

    asset = Asset(
        kind="repository",
        identity_key=f"r-{uuid.uuid4().hex}",
        display_name="acme/api",
        attributes={"clone_url": "https://example.invalid/acme/api.git"},
    )
    session.add(asset)
    session.flush()
    return asset


def test_a_repository_scan_queues_one_correlation_of_its_asset(session, scanned_repository):
    result = repository.scan_repository({"asset_id": str(scanned_repository.id)})

    assert result["status"] == "succeeded"
    jobs = _pending_correlations(session, scanned_repository)
    assert len(jobs) == 1
    assert jobs[0].key == f"{scanned_repository.id}:repository-scan"
    assert jobs[0].priority == 4


def test_a_repeated_repository_scan_does_not_queue_a_second_correlation(
    session, scanned_repository
):
    repository.scan_repository({"asset_id": str(scanned_repository.id)})
    repository.scan_repository({"asset_id": str(scanned_repository.id)})

    assert len(_pending_correlations(session, scanned_repository)) == 1


def test_a_partial_repository_scan_still_queues_a_correlation(
    session, monkeypatch, scanned_repository
):
    monkeypatch.setattr(repository.syft, "parse", lambda _: ([_component()], ["unresolved"], []))

    result = repository.scan_repository({"asset_id": str(scanned_repository.id)})

    assert result["status"] == "partial"
    assert len(_pending_correlations(session, scanned_repository)) == 1


def _node_task(session, capability: str, data) -> tuple[Asset, NodeTask]:
    asset = Asset(kind="host", identity_key=f"h-{uuid.uuid4().hex}", display_name="build-01")
    session.add(asset)
    session.flush()
    node = Node(
        asset_id=asset.id,
        display_name="build-01",
        public_key=uuid.uuid4().bytes,
        agent_version="0.1.0",
    )
    session.add(node)
    session.flush()
    task = NodeTask(
        node_id=node.id,
        capability=capability,
        args={},
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        nonce=uuid.uuid4().hex,
        completed_at=datetime.now(UTC),
        succeeded=True,
        result={"capability": capability, "data": data},
    )
    session.add(task)
    session.flush()
    return asset, task


PACKAGES = [{"name": "openssl", "version": "3.0.13-1", "source": "deb", "arch": "amd64"}]


def test_a_package_ingest_queues_one_correlation_of_its_asset(session, monkeypatch):
    _share(session, monkeypatch, node_ingest)
    asset, task = _node_task(session, "list_packages", PACKAGES)

    result = node_ingest.ingest({"task_id": str(task.id)})

    assert result["status"] == "succeeded"
    jobs = _pending_correlations(session, asset)
    assert len(jobs) == 1
    assert jobs[0].key == f"{asset.id}:node-packages"
    assert jobs[0].priority == 4


def test_a_repeated_package_ingest_does_not_queue_a_second_correlation(session, monkeypatch):
    _share(session, monkeypatch, node_ingest)
    asset, task = _node_task(session, "list_packages", PACKAGES)

    node_ingest.ingest({"task_id": str(task.id)})
    node_ingest.ingest({"task_id": str(task.id)})

    assert len(_pending_correlations(session, asset)) == 1


def test_an_observation_without_components_queues_no_correlation(session, monkeypatch):
    _share(session, monkeypatch, node_ingest)
    asset, task = _node_task(session, "list_processes", [{"pid": 1}])

    node_ingest.ingest({"task_id": str(task.id)})

    assert _pending_correlations(session, asset) == []
