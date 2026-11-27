from __future__ import annotations

from collections.abc import Iterable

from athena_executor.actions.base import Action
from athena_executor.actions.noop import NoopAction


class UnknownAction(LookupError):
    pass


class ActionRegistry:
    def __init__(self, actions: Iterable[Action] = ()) -> None:
        self._actions: dict[str, Action] = {}
        for action in actions:
            self.register(action)

    def register(self, action: Action) -> None:
        name = getattr(action, "name", None)
        if not isinstance(name, str) or not name:
            raise ValueError("an action needs a non-empty name")
        if name in self._actions:
            raise ValueError(f"action {name} is already registered")
        self._actions[name] = action

    def get(self, name: str) -> Action:
        try:
            return self._actions[name]
        except KeyError:
            raise UnknownAction(name) from None

    def names(self) -> frozenset[str]:
        return frozenset(self._actions)


def default_registry() -> ActionRegistry:
    return ActionRegistry([NoopAction()])
