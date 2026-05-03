"""Shared tenant context resolution for SG account configs.

This module is intentionally read-only/foundation-only. It does not enable
multi-tenant deployment by itself; it only provides one canonical way to answer:
which tenant does this config path represent, and what registry metadata applies?
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class TenantRegistryLoadResult:
    tenants: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class TenantContext:
    account_id: Optional[str]
    tenant: str
    layout: str
    display_name: str = "—"
    status: str = "unknown"
    owner_team: str = "—"
    github_reviewers: list[str] = field(default_factory=list)
    slack_channel: str = "—"
    allowed_accounts: list[str] = field(default_factory=list)
    account_allowed: bool = True
    registry_found: bool = False
    tenant_found: bool = False
    registry_error: Optional[str] = None


def load_tenant_registry(repo_root: Path) -> TenantRegistryLoadResult:
    """Load registry/tenants.yaml with structural validation."""
    registry_path = repo_root / "registry" / "tenants.yaml"
    if not registry_path.exists():
        return TenantRegistryLoadResult()

    try:
        with open(registry_path, "r") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return TenantRegistryLoadResult(error="registry/tenants.yaml must be a mapping/object")
        tenants = data.get("tenants")
        if tenants is None:
            return TenantRegistryLoadResult(error="registry/tenants.yaml missing required top-level 'tenants' mapping")
        if not isinstance(tenants, dict):
            return TenantRegistryLoadResult(error="registry/tenants.yaml 'tenants' must be a mapping/object")
        return TenantRegistryLoadResult(tenants=tenants)
    except yaml.YAMLError as e:
        return TenantRegistryLoadResult(error=f"Invalid YAML syntax in registry/tenants.yaml: {e}")
    except Exception as e:
        return TenantRegistryLoadResult(error=f"Failed to read registry/tenants.yaml: {e}")


def derive_account_and_tenant(config_path: Path, repo_root: Path) -> tuple[Optional[str], str, str]:
    """Derive account and tenant from a config file or containing directory.

    Supported shapes:
      accounts/<account-id>/security-groups.yaml -> default tenant, legacy layout
      accounts/<account-id>/<tenant>/security-groups.yaml -> path tenant, tenant layout
    """
    path = Path(config_path)
    root = Path(repo_root)
    if path.name != "security-groups.yaml":
        path = path / "security-groups.yaml"

    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        rel = path

    parts = rel.parts
    if len(parts) >= 3 and parts[0] == "accounts" and parts[2] == "security-groups.yaml":
        return parts[1], "default", "legacy"
    if len(parts) >= 4 and parts[0] == "accounts" and parts[3] == "security-groups.yaml":
        return parts[1], parts[2], "tenant"

    return None, "default", "unknown"


def resolve_tenant_context(config_path: Path, repo_root: Path) -> TenantContext:
    """Resolve tenant context and registry metadata for a config path."""
    root = Path(repo_root)
    account_id, tenant_slug, layout = derive_account_and_tenant(config_path, root)
    registry = load_tenant_registry(root)

    context = TenantContext(
        account_id=account_id,
        tenant=tenant_slug,
        layout=layout,
        registry_found=bool(registry.tenants),
        registry_error=registry.error,
    )

    if registry.error or not registry.tenants:
        return context

    tenant = registry.tenants.get(tenant_slug)
    if not isinstance(tenant, dict):
        return context

    allowed_accounts = [str(a) for a in tenant.get("allowed_accounts", []) or []]
    account_allowed = not allowed_accounts or not account_id or str(account_id) in allowed_accounts

    context.tenant_found = True
    context.display_name = tenant.get("display_name") or tenant_slug
    context.status = tenant.get("status") or "unknown"
    context.owner_team = tenant.get("owner_team") or "—"
    context.github_reviewers = tenant.get("github_reviewers", []) or []
    context.slack_channel = tenant.get("slack_channel") or "—"
    context.allowed_accounts = allowed_accounts
    context.account_allowed = account_allowed
    return context
