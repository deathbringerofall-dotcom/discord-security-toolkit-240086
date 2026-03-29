from __future__ import annotations

import re
from dataclasses import dataclass

from .base import ModuleResult, SecurityModule

WEBHOOK_PATTERN = re.compile(
    r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+",
    flags=re.IGNORECASE,
)


@dataclass
class WebhookGuardModule(SecurityModule):
    """Detect exposed Discord webhook URLs in local text payloads."""

    name: str = "webhook_guard"

    def analyze(self, payload: dict[str, object]) -> ModuleResult:
        content = str(payload.get("content", ""))
        matches = WEBHOOK_PATTERN.findall(content)

        risk_score = min(100, len(matches) * 50)
        findings = (
            ["Potential Discord webhook URL exposure detected."] * len(matches)
            if matches
            else ["No webhook URLs detected."]
        )

        return ModuleResult(
            module_name=self.name,
            risk_score=risk_score,
            findings=findings,
            metadata={"webhook_exposures": len(matches)},
        )
