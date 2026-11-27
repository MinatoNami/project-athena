from __future__ import annotations

from typing import Any

from athena_executor.actions.base import Action, ActionRequest


class NoopAction(Action):
    name = "noop"

    def plan(self, request: ActionRequest) -> dict[str, Any]:
        return {"action": self.name, "target": request.target, "changes": []}

    def apply(self, request: ActionRequest, plan: Any) -> dict[str, Any]:
        return {"changed": 0}

    def verify(self, request: ActionRequest, plan: Any, applied: Any) -> bool:
        return applied == {"changed": 0}

    def rollback(self, request: ActionRequest, plan: Any, applied: Any) -> None:
        return None
