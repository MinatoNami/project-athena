from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from athena_executor.actions.base import Action, ActionRequest
from athena_executor.actions.noop import NoopAction
from athena_executor.canonical import canonical_json
from athena_executor.grants import GrantVerifier, VerifiedGrant, key_fingerprint
from athena_executor.registry import ActionRegistry, UnknownAction, default_registry
from athena_executor.runner import Runner, RunStatus, plan_digest

NOW = datetime(2026, 11, 28, 12, 0, tzinfo=UTC)


class Recording(Action):
    name = "recording"

    def __init__(
        self,
        *,
        plan_output: Any = None,
        verify_returns: Any = True,
        fail_in: str | None = None,
    ) -> None:
        self.calls: list[str] = []
        self.plan_output = {"steps": ["touch"]} if plan_output is None else plan_output
        self.verify_returns = verify_returns
        self.fail_in = fail_in

    def _step(self, step: str) -> None:
        self.calls.append(step)
        if self.fail_in == step:
            raise RuntimeError(f"{step} broke")

    def plan(self, request: ActionRequest) -> Any:
        self._step("plan")
        return self.plan_output

    def apply(self, request: ActionRequest, plan: Any) -> Any:
        self._step("apply")
        return {"applied": True}

    def verify(self, request: ActionRequest, plan: Any, applied: Any) -> bool:
        self._step("verify")
        return self.verify_returns

    def rollback(self, request: ActionRequest, plan: Any, applied: Any) -> None:
        self._step("rollback")


def grant(action: str = "recording", dry_run_hash: str | None = None) -> VerifiedGrant:
    payload = {"action": action, "target": "asset:1", "parameters": {}}
    return VerifiedGrant(
        action=action,
        target="asset:1",
        parameters={},
        dry_run_hash=dry_run_hash or plan_digest({"steps": ["touch"]}),
        key_id="k",
        nonce="n",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        payload=payload,
    )


def run_with(recording: Recording, **grant_overrides):
    return Runner(ActionRegistry([recording])).run(grant(**grant_overrides))


def test_steps_run_plan_then_apply_then_verify():
    action = Recording()
    result = run_with(action)
    assert action.calls == ["plan", "apply", "verify"]
    assert result.status is RunStatus.VERIFIED
    assert result.steps == ("plan", "apply", "verify")


def test_rollback_runs_when_verify_fails():
    action = Recording(verify_returns=False)
    result = run_with(action)
    assert action.calls == ["plan", "apply", "verify", "rollback"]
    assert result.status is RunStatus.ROLLED_BACK


def test_rollback_runs_when_verify_raises():
    action = Recording(fail_in="verify")
    result = run_with(action)
    assert action.calls == ["plan", "apply", "verify", "rollback"]
    assert result.status is RunStatus.ROLLED_BACK


@pytest.mark.parametrize("answer", ["yes", 1, None])
def test_only_a_true_verify_counts_as_passed(answer):
    action = Recording(verify_returns=answer)
    assert run_with(action).status is RunStatus.ROLLED_BACK


def test_rollback_never_runs_after_a_failed_apply():
    action = Recording(fail_in="apply")
    result = run_with(action)
    assert action.calls == ["plan", "apply"]
    assert result.status is RunStatus.APPLY_FAILED


def test_a_failing_rollback_is_reported():
    action = Recording(verify_returns=False, fail_in="rollback")
    result = run_with(action)
    assert result.status is RunStatus.ROLLBACK_FAILED


def test_a_plan_that_differs_from_the_approved_dry_run_refuses_apply():
    action = Recording(plan_output={"steps": ["touch", "and something else"]})
    result = run_with(action)
    assert action.calls == ["plan"]
    assert result.status is RunStatus.REFUSED
    assert "dry run" in result.reason


def test_a_forged_hash_refuses_apply():
    action = Recording()
    result = run_with(action, dry_run_hash="f" * 64)
    assert action.calls == ["plan"]
    assert result.status is RunStatus.REFUSED


def test_a_plan_exception_refuses_apply():
    action = Recording(fail_in="plan")
    result = run_with(action)
    assert action.calls == ["plan"]
    assert result.status is RunStatus.REFUSED


def test_a_plan_that_is_not_canonical_json_refuses_apply():
    action = Recording(plan_output={"when": datetime(2026, 11, 28, tzinfo=UTC)})
    result = run_with(action)
    assert action.calls == ["plan"]
    assert result.status is RunStatus.REFUSED


def test_an_unknown_action_is_refused():
    action = Recording()
    result = run_with(action, action="rm")
    assert action.calls == []
    assert result.status is RunStatus.REFUSED


def test_the_runner_takes_only_admitted_grants():
    with pytest.raises(TypeError):
        Runner(default_registry()).run({"action": "noop"})


def test_the_registry_refuses_duplicates_and_unknown_names():
    registry = default_registry()
    assert registry.names() == frozenset({"noop"})
    with pytest.raises(ValueError, match="already"):
        registry.register(NoopAction())
    with pytest.raises(UnknownAction):
        registry.get("shell")


def test_plan_digest_ignores_key_order():
    assert plan_digest({"a": 1, "b": [1, 2]}) == plan_digest({"b": [1, 2], "a": 1})


def test_noop_round_trip_from_dry_run_to_verified():
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    runner = Runner(default_registry())

    dry_run = runner.dry_run("noop", ActionRequest(target="node:7"))
    payload = {
        "action": "noop",
        "target": "node:7",
        "parameters": {},
        "approver": "user:1",
        "change_record_id": "change:1",
        "dry_run_hash": dry_run.digest,
        "key_id": key_fingerprint(public),
        "nonce": "round-trip",
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
    }
    signature = signer.sign(canonical_json(payload))

    verifier = GrantVerifier(public, clock=lambda: NOW + timedelta(seconds=1))
    result = runner.run(verifier.admit(payload, signature))

    assert dry_run.plan == {"action": "noop", "target": "node:7", "changes": []}
    assert result.status is RunStatus.VERIFIED
    assert result.plan_digest == dry_run.digest
    assert result.steps == ("plan", "apply", "verify")
