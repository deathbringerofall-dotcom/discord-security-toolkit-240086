from __future__ import annotations

from dataclasses import dataclass, field

from .base import ModuleResult, SecurityModule


@dataclass
class PermissionAuditModule(SecurityModule):
    """Audit risky permission sets from local role data."""

    risky_permissions: set[str] = field(
        default_factory=lambda: {
            "administrator",
            "manage_guild",
            "ban_members",
            "kick_members",
            "manage_webhooks",
        }
    )
    name: str = "permission_audit"

    def analyze(self, payload: dict[str, object]) -> ModuleResult:
        roles = payload.get("roles", [])
        risky_roles: list[str] = []

        for role in roles if isinstance(roles, list) else []:
            role_name = str(role.get("name", "unknown"))
            permissions = {str(p).lower() for p in role.get("permissions", [])}
            if permissions & self.risky_permissions:
                risky_roles.append(role_name)

        risk_score = min(100, len(risky_roles) * 20)
        findings = (
            [f"Role has elevated permissions: {name}" for name in risky_roles]
            if risky_roles
            else ["No elevated role permissions detected."]
        )

        return ModuleResult(
            module_name=self.name,
            risk_score=risk_score,
            findings=findings,
            metadata={"risky_roles": risky_roles},
        )
