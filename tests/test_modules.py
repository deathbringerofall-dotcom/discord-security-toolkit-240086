from discord_security_toolkit import (
    KeywordFilterModule,
    PermissionAuditModule,
    SuspiciousLinkScannerModule,
    WebhookGuardModule,
)
from discord_security_toolkit.toolkit import DiscordSecurityToolkit


def test_keyword_filter_detects_blocked_keywords() -> None:
    result = KeywordFilterModule().analyze({"content": "Get FREE NITRO now"})
    assert result.risk_score > 0
    assert any("free nitro" in finding.lower() for finding in result.findings)


def test_suspicious_link_scanner_flags_untrusted_domain() -> None:
    result = SuspiciousLinkScannerModule().analyze(
        {"content": "check https://evil.example/login"}
    )
    assert result.metadata["suspicious_count"] == 1


def test_permission_audit_detects_elevated_role() -> None:
    result = PermissionAuditModule().analyze(
        {"roles": [{"name": "Admin", "permissions": ["administrator"]}]}
    )
    assert result.risk_score >= 20


def test_webhook_guard_finds_exposed_webhook() -> None:
    result = WebhookGuardModule().analyze(
        {
            "content": "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOp"
        }
    )
    assert result.metadata["webhook_exposures"] == 1


def test_toolkit_runs_all_modules() -> None:
    toolkit = DiscordSecurityToolkit.from_modules(
        [
            KeywordFilterModule(),
            SuspiciousLinkScannerModule(),
            PermissionAuditModule(),
            WebhookGuardModule(),
        ]
    )
    results = toolkit.run({"content": "hello"})
    assert len(results) == 4
