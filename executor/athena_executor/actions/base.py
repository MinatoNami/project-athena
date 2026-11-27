from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar


@dataclass(frozen=True)
class ActionRequest:
    target: str
    parameters: Mapping[str, Any] = field(default_factory=dict)


class Action(ABC):
    name: ClassVar[str]

    @abstractmethod
    def plan(self, request: ActionRequest) -> Any: ...

    @abstractmethod
    def apply(self, request: ActionRequest, plan: Any) -> Any: ...

    @abstractmethod
    def verify(self, request: ActionRequest, plan: Any, applied: Any) -> bool: ...

    @abstractmethod
    def rollback(self, request: ActionRequest, plan: Any, applied: Any) -> None: ...
