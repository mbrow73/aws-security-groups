"""Security group reference classification.

Classifies rule-level security group references as platform built-ins,
same-tenant, cross-tenant, cross-tenant granted, or unknown. This is policy
input, not review enforcement by itself.
"""

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Optional

import yaml

from account_config import AccountConfigLoadResult


@dataclass
class ReferenceClassification:
    source_sg: str
    target_sg: str
    ref_class: str
    source_tenant: Optional[str] = None
    target_tenant: Optional[str] = None
    owner_authority: Optional[str] = None
    grant_name: Optional[str] = None


def load_platform_security_groups(repo_root: str | Path) -> dict:
    path = Path(repo_root) / "registry" / "platform-security-groups.yaml"
    if not path.exists():
        return {}
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    platform_sgs = data.get("platform_security_groups", {}) if isinstance(data, dict) else {}
    return platform_sgs if isinstance(platform_sgs, dict) else {}


def load_tenant_registry(repo_root: str | Path) -> dict:
    path = Path(repo_root) / "registry" / "tenants.yaml"
    if not path.exists():
        return {}
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    tenants = data.get("tenants", {}) if isinstance(data, dict) else {}
    return tenants if isinstance(tenants, dict) else {}


def build_sg_tenant_map(account_config: AccountConfigLoadResult) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for source in account_config.sources:
        sgs = source.data.get("security_groups", {}) or {}
        if not isinstance(sgs, dict):
            continue
        for sg_name in sgs:
            mapping[sg_name] = source.tenant
    return mapping


def _port_matches(grant: dict[str, Any], from_port: Optional[int], to_port: Optional[int]) -> bool:
    if from_port is None or to_port is None:
        return False
    ports = grant.get("ports") or []
    if int(from_port) == int(to_port) and int(from_port) in [int(p) for p in ports]:
        return True
    for port_range in grant.get("port_ranges") or []:
        start = int(port_range.get("from"))
        end = int(port_range.get("to"))
        if int(from_port) >= start and int(to_port) <= end:
            return True
    return False


def _not_expired(grant: dict[str, Any]) -> bool:
    expires = grant.get("expires")
    if not expires:
        return True
    if isinstance(expires, date):
        expiry = expires
    else:
        expiry = date.fromisoformat(str(expires))
    return expiry >= date.today()


def find_matching_reference_grant(
    tenant_registry: dict,
    source_tenant: Optional[str],
    target_tenant: str,
    target_sg: str,
    direction: str,
    protocol: Optional[str],
    from_port: Optional[int],
    to_port: Optional[int],
) -> Optional[dict]:
    target = tenant_registry.get(target_tenant, {}) or {}
    for grant in target.get("reference_grants") or []:
        if grant.get("decision") != "auto_approved":
            continue
        if target_sg not in (grant.get("target_sgs") or []):
            continue
        source_tenants = grant.get("source_tenants") or []
        if "*" not in source_tenants and source_tenant not in source_tenants:
            continue
        protocols = [str(p).lower() for p in (grant.get("protocols") or [])]
        if protocol and protocols and str(protocol).lower() not in protocols:
            continue
        directions = [str(d).lower() for d in (grant.get("directions") or [])]
        if directions and str(direction).lower() not in directions:
            continue
        if not _port_matches(grant, from_port, to_port):
            continue
        if not _not_expired(grant):
            continue
        return grant
    return None


def classify_sg_reference(
    account_config: AccountConfigLoadResult,
    platform_sgs: dict,
    source_sg: str,
    target_sg: str,
    tenant_registry: Optional[dict] = None,
    direction: str = "egress",
    protocol: Optional[str] = None,
    from_port: Optional[int] = None,
    to_port: Optional[int] = None,
) -> ReferenceClassification:
    sg_tenants = build_sg_tenant_map(account_config)
    source_tenant = sg_tenants.get(source_sg)

    if target_sg in platform_sgs:
        return ReferenceClassification(
            source_sg=source_sg,
            target_sg=target_sg,
            ref_class="platform_builtin",
            source_tenant=source_tenant,
            owner_authority=platform_sgs[target_sg].get("owner_authority"),
        )

    target_tenant = sg_tenants.get(target_sg)
    if not target_tenant:
        return ReferenceClassification(
            source_sg=source_sg,
            target_sg=target_sg,
            ref_class="unknown",
            source_tenant=source_tenant,
        )

    if source_tenant and source_tenant == target_tenant:
        ref_class = "same_tenant"
        grant_name = None
    else:
        grant = find_matching_reference_grant(
            tenant_registry or {},
            source_tenant,
            target_tenant,
            target_sg,
            direction,
            protocol,
            from_port,
            to_port,
        )
        ref_class = "cross_tenant_granted" if grant else "cross_tenant"
        grant_name = grant.get("name") if grant else None

    return ReferenceClassification(
        source_sg=source_sg,
        target_sg=target_sg,
        ref_class=ref_class,
        source_tenant=source_tenant,
        target_tenant=target_tenant,
        grant_name=grant_name,
    )
