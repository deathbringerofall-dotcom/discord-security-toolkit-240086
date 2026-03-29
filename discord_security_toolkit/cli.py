from __future__ import annotations

import argparse
import json

from . import (
    KeywordFilterModule,
    PermissionAuditModule,
    SuspiciousLinkScannerModule,
    WebhookGuardModule,
)
from .toolkit import DiscordSecurityToolkit


def build_toolkit() -> DiscordSecurityToolkit:
    return DiscordSecurityToolkit.from_modules(
        [
            KeywordFilterModule(),
            SuspiciousLinkScannerModule(),
            PermissionAuditModule(),
            WebhookGuardModule(),
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Offline Discord security toolkit (no API keys required)."
    )
    parser.add_argument(
        "--payload",
        required=True,
        help="JSON payload containing fields like 'content' and 'roles'.",
    )
    args = parser.parse_args()

    payload = json.loads(args.payload)
    toolkit = build_toolkit()
    results = toolkit.run(payload)

    serializable = [
        {
            "module": result.module_name,
            "risk_score": result.risk_score,
            "findings": result.findings,
            "metadata": result.metadata,
        }
        for result in results
    ]
    print(json.dumps(serializable, indent=2))


if __name__ == "__main__":
    main()
