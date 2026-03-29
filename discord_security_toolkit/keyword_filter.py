from __future__ import annotations

from dataclasses import dataclass, field

from .base import ModuleResult, SecurityModule


@dataclass
class KeywordFilterModule(SecurityModule):
    """Detect potentially dangerous words in message content.

    This module uses local keyword matching only and never calls external APIs.
    """

    blocked_keywords: set[str] = field(
        default_factory=lambda: {
            "token grabber",
            "nitro generator",
            "free nitro",
            "discord exploit",
            "malware",
        }
    )
    name: str = "keyword_filter"

    def analyze(self, payload: dict[str, object]) -> ModuleResult:
        content = str(payload.get("content", "")).lower()
        matches = sorted(k for k in self.blocked_keywords if k in content)
        risk_score = min(100, len(matches) * 25)

        findings = [f"Detected blocked keyword: {keyword}" for keyword in matches]
        if not findings:
            findings = ["No blocked keywords detected."]

        return ModuleResult(
            module_name=self.name,
            risk_score=risk_score,
            findings=findings,
            metadata={"match_count": len(matches)},
        )
