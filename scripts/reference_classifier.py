"""Security group reference classification.

Classifies rule-level security group references as platform built-ins,
same-tenant, cross-tenant, or unknown. This is policy input, not review
enforcement by itself.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

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


def load_platform_security_groups(repo_root: str | Path) -> dict:
    path = Path(repo_root) / "registry" / "platform-security-groups.yaml"
    if not path.exists():
        return {}
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    platform_sgs = data.get("platform_security_groups", {}) if isinstance(data, dict) else {}
    return platform_sgs if isinstance(platform_sgs, dict) else {}


def build_sg_tenant_map(account_config: AccountConfigLoadResult) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for source in account_config.sources:
        sgs = source.data.get("security_groups", {}) or {}
        if not isinstance(sgs, dict):
            continue
        for sg_name in sgs:
            mapping[sg_name] = source.tenant
    return mapping


def classify_sg_reference(
    account_config: AccountConfigLoadResult,
    platform_sgs: dict,
    source_sg: str,
    target_sg: str,
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
    else:
        ref_class = "cross_tenant"

    return ReferenceClassification(
        source_sg=source_sg,
        target_sg=target_sg,
        ref_class=ref_class,
        source_tenant=source_tenant,
        target_tenant=target_tenant,
    )
