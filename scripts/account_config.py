#!/usr/bin/env python3
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Tuple
import yaml


class AccountConfigError(Exception):
    pass


class AccountConfigConflict(AccountConfigError):
    pass


ALLOWED_ROOT_FILES = {"security-groups.yaml", "tenant.yaml"}


def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise AccountConfigError(f"Invalid YAML in {path}: {e}") from e
    if not isinstance(data, dict):
        raise AccountConfigError(f"Top-level YAML in {path} must be a mapping")
    return data


def _load_registry(repo_root: Path) -> Dict[str, Any]:
    path = repo_root / 'owners.yaml'
    if not path.exists():
        return {'owners': {}, 'tenants': {}}
    data = _load_yaml(path)
    return {
        'owners': data.get('owners', {}) or {},
        'tenants': data.get('tenants', {}) or {},
    }


def discover_account_layout(account_dir: Path) -> Dict[str, Any]:
    root_file = account_dir / 'security-groups.yaml'
    root_tenant = account_dir / 'tenant.yaml'
    tenant_files = sorted([
        p for p in account_dir.glob('*/security-groups.yaml')
        if p.parent.is_dir()
    ])
    return {
        'root_file': root_file if root_file.exists() else None,
        'root_tenant_file': root_tenant if root_tenant.exists() else None,
        'tenant_files': tenant_files,
    }


def _merge_security_groups(parts: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    owners: Dict[str, str] = {}
    for source, data in parts:
        for sg_name, sg in (data.get('security_groups') or {}).items():
            if sg_name in merged:
                raise AccountConfigConflict(
                    f"Duplicate security group '{sg_name}' found in both {owners[sg_name]} and {source}"
                )
            merged[sg_name] = deepcopy(sg)
            owners[sg_name] = source
    return merged


def load_account_config(account_dir: str | Path) -> Dict[str, Any]:
    account_dir = Path(account_dir)
    repo_root = account_dir.parent.parent
    registry = _load_registry(repo_root)
    layout = discover_account_layout(account_dir)

    if not layout['root_file'] and not layout['tenant_files']:
        raise AccountConfigError(f"No security-groups.yaml found under {account_dir}")

    if layout['root_file'] and layout['tenant_files']:
        raise AccountConfigConflict(
            f"Mixed layout not allowed in {account_dir}: found root security-groups.yaml and tenant subdirectories"
        )

    if layout['root_file']:
        data = _load_yaml(layout['root_file'])
        if 'tenant' not in data and layout['root_tenant_file']:
            tenant_data = _load_yaml(layout['root_tenant_file'])
            if tenant_data.get('tenant'):
                data['tenant'] = tenant_data['tenant']
        tenant = data.get('tenant')
        if tenant and 'owner_team' not in data:
            owner_team = registry.get('tenants', {}).get(tenant, {}).get('owner_team')
            if owner_team:
                data['owner_team'] = owner_team
        data['_sources'] = [str(layout['root_file'].relative_to(repo_root))]
        data['_layout'] = 'legacy'
        return data

    tenant_parts: List[Tuple[str, Dict[str, Any]]] = []
    merged_base: Dict[str, Any] | None = None
    sources: List[str] = []

    for tenant_file in layout['tenant_files']:
        rel = str(tenant_file.relative_to(repo_root))
        tenant_slug = tenant_file.parent.name
        data = _load_yaml(tenant_file)
        sources.append(rel)

        file_tenant = data.get('tenant', tenant_slug)
        if file_tenant != tenant_slug:
            raise AccountConfigConflict(
                f"Tenant file {rel} declares tenant '{file_tenant}' but directory tenant is '{tenant_slug}'"
            )
        data['tenant'] = tenant_slug

        owner_team = data.get('owner_team') or registry.get('tenants', {}).get(tenant_slug, {}).get('owner_team')
        if owner_team:
            data['owner_team'] = owner_team

        if merged_base is None:
            merged_base = deepcopy(data)
            merged_base['security_groups'] = {}
        else:
            for key in ['account_id', 'environment', 'carid', 'default_region', 'regions']:
                if key in data and key in merged_base and data[key] != merged_base[key]:
                    raise AccountConfigConflict(
                        f"Tenant file {rel} conflicts on '{key}' with another tenant file"
                    )
                if key in data and key not in merged_base:
                    merged_base[key] = deepcopy(data[key])
            merged_base['tags'] = {**merged_base.get('tags', {}), **data.get('tags', {})}

        tenant_parts.append((rel, data))

    assert merged_base is not None
    merged_base['security_groups'] = _merge_security_groups(tenant_parts)
    merged_base['_sources'] = sources
    merged_base['_layout'] = 'tenant-split'
    merged_base['_tenants'] = [p.parent.name for p in layout['tenant_files']]
    return merged_base
