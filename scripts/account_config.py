"""Account security group config loading.

The loader keeps Terraform-facing config shape stable while allowing the codebase
to understand both today's legacy account layout and the future tenant-split
layout.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from tenant_context import resolve_tenant_context


ACCOUNT_METADATA_KEYS = ["account_id", "environment", "carid", "default_region", "regions", "tags"]


@dataclass
class AccountConfigSource:
    path: Path
    tenant: str
    layout: str
    data: dict[str, Any]


@dataclass
class AccountConfigLoadResult:
    account_id: str
    layout: str
    config: dict[str, Any] = field(default_factory=dict)
    sources: list[AccountConfigSource] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _read_yaml(path: Path) -> tuple[dict[str, Any], Optional[str]]:
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return {}, f"{path} must be a mapping/object"
        return data, None
    except yaml.YAMLError as e:
        return {}, f"Invalid YAML syntax in {path}: {e}"
    except Exception as e:
        return {}, f"Failed to read {path}: {e}"


def _discover_sources(account_dir: Path) -> tuple[str, list[Path], list[str]]:
    legacy_file = account_dir / "security-groups.yaml"
    tenant_files = sorted(account_dir.glob("*/security-groups.yaml"))

    if legacy_file.exists() and tenant_files:
        return "mixed", [legacy_file] + tenant_files, [
            f"Mixed legacy and tenant layouts found under {account_dir}; only one active layout is allowed"
        ]
    if legacy_file.exists():
        return "legacy", [legacy_file], []
    if tenant_files:
        return "tenant", tenant_files, []
    return "missing", [], [f"No security-groups.yaml found under {account_dir}"]


def load_account_config(account_dir: str | Path, repo_root: str | Path | None = None) -> AccountConfigLoadResult:
    """Load an account config from legacy or future tenant-split layout.

    The returned config is normalized to the current Terraform-compatible account
    shape with a single top-level `security_groups` mapping.
    """
    account_dir = Path(account_dir)
    account_id = account_dir.name
    repo_root = Path(repo_root) if repo_root else _find_repo_root(account_dir)
    layout, paths, discovery_errors = _discover_sources(account_dir)

    result = AccountConfigLoadResult(account_id=account_id, layout=layout, errors=discovery_errors)
    if discovery_errors:
        return result

    merged: dict[str, Any] = {}
    merged_sgs: dict[str, Any] = {}
    metadata_seen: dict[str, Any] = {}

    for path in paths:
        data, error = _read_yaml(path)
        if error:
            result.errors.append(error)
            continue

        context = resolve_tenant_context(path, repo_root)
        result.sources.append(AccountConfigSource(path=path, tenant=context.tenant, layout=context.layout, data=data))

        if context.registry_error:
            result.errors.append(context.registry_error)
        elif context.registry_found and not context.tenant_found:
            result.warnings.append(f"Tenant '{context.tenant}' is not defined in registry/tenants.yaml")
        elif context.allowed_accounts and not context.account_allowed:
            result.warnings.append(
                f"Account {context.account_id} is not listed under tenant '{context.tenant}' allowed_accounts"
            )

        for key in ACCOUNT_METADATA_KEYS:
            if key not in data:
                continue
            if key not in metadata_seen:
                metadata_seen[key] = data[key]
                merged[key] = data[key]
            elif metadata_seen[key] != data[key]:
                result.errors.append(
                    f"Conflicting account metadata '{key}' between tenant files in {account_dir}"
                )

        sgs = data.get("security_groups", {}) or {}
        if not isinstance(sgs, dict):
            result.errors.append(f"security_groups in {path} must be a mapping/object")
            continue

        for sg_name, sg_config in sgs.items():
            if sg_name in merged_sgs:
                result.errors.append(f"Duplicate security group '{sg_name}' across tenant files in {account_dir}")
                continue
            merged_sgs[sg_name] = sg_config

    merged["security_groups"] = merged_sgs
    result.config = merged
    return result


def _find_repo_root(start: Path) -> Path:
    current = start.resolve()
    while current != current.parent:
        if (current / "guardrails.yaml").exists():
            return current
        current = current.parent
    return start.resolve().parent
