from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ModuleResult:
    module_name: str
    risk_score: int
    findings: list[str]
    metadata: dict[str, Any]


class SecurityModule(ABC):
    """Common base class for all offline security modules."""

    name: str

    @abstractmethod
    def analyze(self, payload: dict[str, Any]) -> ModuleResult:
        """Analyze payload and return a risk report."""

