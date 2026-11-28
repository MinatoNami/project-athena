from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from athena_executor.actions.base import ActionRequest
from athena_executor.canonical import sha256_hex
from athena_executor.grants import VerifiedGrant
from athena_executor.registry import ActionRegistry, UnknownAction


class RunStatus(StrEnum):
    REFUSED = "refused"
    VERIFIED = "verified"
    ROLLED_BACK = "rolled_back"
    APPLY_FAILED = "apply_failed"
    ROLLBACK_FAILED = "rollback_failed"


@dataclass(frozen=True)
class RunResult:
    status: RunStatus
    action: str
    steps: tuple[str, ...]
    plan_digest: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class DryRun:
    action: str
    plan: Any
    digest: str


def plan_digest(plan: Any) -> str:
    return sha256_hex(plan)


class Runner:
    def __init__(self, registry: ActionRegistry) -> None:
        self._registry = registry

    def dry_run(self, action_name: str, request: ActionRequest) -> DryRun:
        plan = self._registry.get(action_name).plan(request)
        return DryRun(action=action_name, plan=plan, digest=plan_digest(plan))

    def run(self, grant: VerifiedGrant) -> RunResult:
        if not isinstance(grant, VerifiedGrant):
            raise TypeError("the runner only accepts a grant the verifier admitted")

        steps: list[str] = []
        digest: str | None = None

        def result(status: RunStatus, reason: str | None = None) -> RunResult:
            return RunResult(status, grant.action, tuple(steps), digest, reason)

        try:
            action = self._registry.get(grant.action)
        except UnknownAction:
            return result(RunStatus.REFUSED, f"no action named {grant.action} is registered")

        request = ActionRequest(target=grant.target, parameters=grant.parameters)

        steps.append("plan")
        try:
            plan = action.plan(request)
            digest = plan_digest(plan)
        except Exception as exc:
            return result(RunStatus.REFUSED, f"plan failed: {type(exc).__name__}")

        if not hmac.compare_digest(digest.encode(), grant.dry_run_hash.encode()):
            return result(RunStatus.REFUSED, "plan does not match the approved dry run")

        steps.append("apply")
        try:
            applied = action.apply(request, plan)
        except Exception as exc:
            return result(RunStatus.APPLY_FAILED, f"apply failed: {type(exc).__name__}")

        steps.append("verify")
        try:
            verified = action.verify(request, plan, applied) is True
        except Exception:
            verified = False
        if verified:
            return result(RunStatus.VERIFIED)

        steps.append("rollback")
        try:
            action.rollback(request, plan, applied)
        except Exception as exc:
            return result(RunStatus.ROLLBACK_FAILED, f"rollback failed: {type(exc).__name__}")
        return result(RunStatus.ROLLED_BACK, "verify failed")
