from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .base import ModuleResult, SecurityModule


@dataclass
class DiscordSecurityToolkit:
    """Runs configured security modules over a single payload."""

    modules: list[SecurityModule] = field(default_factory=list)

    def run(self, payload: dict[str, object]) -> list[ModuleResult]:
        return [module.analyze(payload) for module in self.modules]

    @classmethod
    def from_modules(cls, modules: Iterable[SecurityModule]) -> "DiscordSecurityToolkit":
        return cls(modules=list(modules))
