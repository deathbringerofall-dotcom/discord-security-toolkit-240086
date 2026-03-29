from __future__ import annotations

import re
from dataclasses import dataclass, field

from .base import ModuleResult, SecurityModule

URL_PATTERN = re.compile(r"https?://[^\s]+", flags=re.IGNORECASE)


@dataclass
class SuspiciousLinkScannerModule(SecurityModule):
    """Scan URLs with local heuristics (no API calls required)."""

    trusted_domains: set[str] = field(
        default_factory=lambda: {"discord.com", "discord.gg", "github.com", "python.org"}
    )
    name: str = "suspicious_link_scanner"

    def analyze(self, payload: dict[str, object]) -> ModuleResult:
        content = str(payload.get("content", ""))
        urls = URL_PATTERN.findall(content)

        suspicious: list[str] = []
        for url in urls:
            domain = self._extract_domain(url)
            if domain not in self.trusted_domains or self._looks_obfuscated(url):
                suspicious.append(url)

        risk_score = min(100, len(suspicious) * 30)
        findings = (
            [f"Suspicious URL detected: {url}" for url in suspicious]
            if suspicious
            else ["No suspicious URLs detected."]
        )

        return ModuleResult(
            module_name=self.name,
            risk_score=risk_score,
            findings=findings,
            metadata={"url_count": len(urls), "suspicious_count": len(suspicious)},
        )

    @staticmethod
    def _extract_domain(url: str) -> str:
        stripped = url.split("//", 1)[-1].split("/", 1)[0].lower()
        return stripped[4:] if stripped.startswith("www.") else stripped

    @staticmethod
    def _looks_obfuscated(url: str) -> bool:
        indicators = ["@", "%", "--", "xn--"]
        return any(token in url.lower() for token in indicators)
