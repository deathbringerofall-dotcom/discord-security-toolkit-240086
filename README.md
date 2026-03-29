# discord-security-toolkit-240086

Offline Discord security modules with custom code that works **without API keys**.

## Included modules

- `KeywordFilterModule`: flags risky phrases such as `free nitro`.
- `SuspiciousLinkScannerModule`: scans links with local heuristics.
- `PermissionAuditModule`: audits risky role permissions.
- `WebhookGuardModule`: detects exposed Discord webhook URLs.

All modules use local logic only and make no external API calls.

## Quick start

```bash
python -m discord_security_toolkit.cli --payload '{"content":"free nitro https://bad.example/phish","roles":[{"name":"Mod","permissions":["ban_members"]}]}'
```

The output is a JSON list with module risk scores and findings.
