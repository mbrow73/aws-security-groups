#!/usr/bin/env python3
"""Generate machine-readable SG policy summary for review consumers.

This is the single Python policy brain for tenant/source/ref classification. Review
Gate can later consume this artifact instead of re-implementing policy discovery
in JavaScript.
"""

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from account_config import load_account_config
from network_ownership import classify_cidr_ownership, find_matching_network_grant
from reference_classifier import (
    build_sg_tenant_map,
    classify_sg_reference,
    load_platform_security_groups,
    load_tenant_registry,
)


def load_review_authorities(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "registry" / "review-authorities.yaml"
    if not path.exists():
        return {}
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}


def tenant_authority(tenants: dict, tenant_slug: str | None) -> str:
    if not tenant_slug:
        return "platform-sg"
    tenant = tenants.get(tenant_slug, {}) or {}
    return tenant.get("review_authority") or "platform-sg"


def add_requirement(requirements: dict[str, int], authority: str, count: int):
    requirements[authority] = max(requirements.get(authority, 0), count)


def load_changed_files(path: str | None) -> list[str] | None:
    if not path:
        return None
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def changed_tenants_for_account(account_id: str, changed_files: list[str] | None) -> set[str] | None:
    if changed_files is None:
        return None
    tenants: set[str] = set()
    account_prefix = f"accounts/{account_id}/"
    for changed in changed_files:
        if not changed.startswith(account_prefix) or not changed.endswith("security-groups.yaml"):
            continue
        rel = changed[len(account_prefix):]
        parts = rel.split("/")
        if parts == ["security-groups.yaml"]:
            tenants.add("default")
        elif len(parts) == 2 and parts[1] == "security-groups.yaml":
            tenants.add(parts[0])
    return tenants


def changed_files_are_tenant_sg_only(account_id: str, changed_files: list[str] | None) -> bool:
    if changed_files is None:
        return False
    account_prefix = f"accounts/{account_id}/"
    matched = False
    for changed in changed_files:
        if not changed.startswith(account_prefix):
            return False
        rel = changed[len(account_prefix):]
        parts = rel.split("/")
        if parts == ["security-groups.yaml"]:
            return False
        if len(parts) != 2 or parts[1] != "security-groups.yaml":
            return False
        matched = True
    return matched


def iter_cidr_refs(account_config, source_tenants: set[str] | None = None):
    for source in account_config.sources:
        if source_tenants is not None and source.tenant not in source_tenants:
            continue
        for source_sg, sg_config in (source.data.get("security_groups", {}) or {}).items():
            if not isinstance(sg_config, dict):
                continue
            for direction in ["ingress", "egress"]:
                rules = sg_config.get(direction, []) or []
                if not isinstance(rules, list):
                    continue
                for index, rule in enumerate(rules):
                    if not isinstance(rule, dict):
                        continue
                    for cidr in rule.get("cidr_blocks", []) or []:
                        yield source_sg, cidr, direction, index, rule


def iter_sg_refs(account_config, source_tenants: set[str] | None = None):
    for source in account_config.sources:
        if source_tenants is not None and source.tenant not in source_tenants:
            continue
        for source_sg, sg_config in (source.data.get("security_groups", {}) or {}).items():
            if not isinstance(sg_config, dict):
                continue
            for direction in ["ingress", "egress"]:
                rules = sg_config.get(direction, []) or []
                if not isinstance(rules, list):
                    continue
                for index, rule in enumerate(rules):
                    if not isinstance(rule, dict):
                        continue
                    refs = rule.get("security_groups", []) or []
                    if not isinstance(refs, list):
                        continue
                    for target_sg in refs:
                        yield source_sg, target_sg, direction, index, rule


def build_policy_summary(account_dir: Path, repo_root: Path, changed_files: list[str] | None = None) -> dict[str, Any]:
    account_dir = Path(account_dir)
    repo_root = Path(repo_root)
    account_config = load_account_config(account_dir, repo_root)
    tenants = load_tenant_registry(repo_root)
    platform_sgs = load_platform_security_groups(repo_root)
    review_registry = load_review_authorities(repo_root)
    sg_tenant_map = build_sg_tenant_map(account_config)

    all_tenant_slugs = sorted({source.tenant for source in account_config.sources})
    changed_tenants = changed_tenants_for_account(account_config.account_id, changed_files)
    if changed_tenants is None:
        policy_tenants = set(all_tenant_slugs or ["default"])
    else:
        policy_tenants = changed_tenants

    env = str(account_config.config.get("environment", "prod")).lower()
    prod = env == "prod"
    requirements: dict[str, int] = {}

    for tenant in sorted(policy_tenants):
        add_requirement(requirements, tenant_authority(tenants, tenant), 2 if prod else 1)

    references = []
    cidr_references = []
    auto_merge_blockers: list[str] = []
    for source_sg, target_sg, direction, index, rule in iter_sg_refs(account_config, policy_tenants):
        classification = classify_sg_reference(
            account_config,
            platform_sgs,
            source_sg,
            target_sg,
            tenant_registry=tenants,
            direction=direction,
            protocol=rule.get("protocol"),
            from_port=rule.get("from_port"),
            to_port=rule.get("to_port"),
        )
        ref = asdict(classification)
        ref.update({
            "direction": direction,
            "rule_index": index,
            "protocol": rule.get("protocol"),
            "from_port": rule.get("from_port"),
            "to_port": rule.get("to_port"),
        })
        references.append(ref)

        if classification.ref_class == "cross_tenant":
            add_requirement(requirements, tenant_authority(tenants, classification.target_tenant), 1)

    for source_sg, cidr, direction, index, rule in iter_cidr_refs(account_config, policy_tenants):
        ownership = classify_cidr_ownership(
            tenants,
            cidr,
            protocol=rule.get("protocol"),
            from_port=rule.get("from_port"),
            to_port=rule.get("to_port"),
        )
        cidr_ref = ownership.to_dict()
        cidr_ref.update({
            "source_sg": source_sg,
            "source_tenant": sg_tenant_map.get(source_sg),
            "direction": direction,
            "rule_index": index,
            "protocol": rule.get("protocol"),
            "from_port": rule.get("from_port"),
            "to_port": rule.get("to_port"),
        })
        cidr_references.append(cidr_ref)
        if ownership.classification == "owned":
            owner_tenant = tenants.get(ownership.owner_tenant, {}) or {}
            grant_name = find_matching_network_grant(owner_tenant, ownership.network_name, sg_tenant_map.get(source_sg), direction, rule.get("protocol"), rule.get("from_port"), rule.get("to_port"))
            cidr_ref["grant_name"] = grant_name
            if grant_name:
                cidr_ref["classification"] = "owned_granted"
            elif ownership.owner_tenant != sg_tenant_map.get(source_sg):
                add_requirement(requirements, ownership.owner_authority or "platform-sg", 1)
        else:
            add_requirement(requirements, "platform-sg", 1)

    if account_config.layout != "tenant":
        auto_merge_blockers.append("auto-merge requires tenant layout")
    if not changed_files_are_tenant_sg_only(account_config.account_id, changed_files):
        auto_merge_blockers.append("auto-merge requires only tenant security-groups.yaml files to change")
    if "default" in policy_tenants:
        auto_merge_blockers.append("legacy/default tenant changes are not auto-merge eligible")

    for cidr_ref in cidr_references:
        if cidr_ref.get("classification") == "owned_granted":
            continue
        if cidr_ref.get("classification") != "owned":
            auto_merge_blockers.append(f"CIDR {cidr_ref.get('cidr')} is {cidr_ref.get('classification')}, not auto-merge eligible")
        elif cidr_ref.get("owner_tenant") != cidr_ref.get("source_tenant"):
            auto_merge_blockers.append(f"CIDR {cidr_ref.get('cidr')} requires owner tenant {cidr_ref.get('owner_tenant')} approval")

    for ref in references:
        ref_class = ref.get("ref_class")
        target_sg = ref.get("target_sg")
        if ref_class == "platform_builtin" and target_sg == "vpc-endpoints":
            continue
        if ref_class == "same_tenant":
            continue
        auto_merge_blockers.append(f"reference {target_sg} is {ref_class}, not auto-merge eligible")

    auto_merge_eligible = not auto_merge_blockers
    if auto_merge_eligible:
        auto_merge_reason = "only tenant SG files changed with same-tenant refs and/or vpc-endpoints built-in refs"
        effective_requirements: dict[str, int] = {}
    else:
        auto_merge_reason = "; ".join(auto_merge_blockers)
        effective_requirements = dict(sorted(requirements.items()))

    return {
        "account_id": account_config.account_id,
        "environment": env,
        "layout": account_config.layout,
        "tenants": all_tenant_slugs,
        "changed_tenants": sorted(policy_tenants),
        "sg_tenants": sg_tenant_map,
        "references": references,
        "cidr_references": cidr_references,
        "required_review_authorities": effective_requirements,
        "auto_merge_eligible": auto_merge_eligible,
        "auto_merge_reason": auto_merge_reason,
        "review_authorities": review_registry.get("authorities", {}),
        "errors": account_config.errors,
        "warnings": account_config.warnings,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate SG policy summary JSON")
    parser.add_argument("account_dir", help="Account directory, e.g. accounts/123456789012")
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--changed-files", help="Optional newline-delimited changed files list")
    args = parser.parse_args()

    summary = build_policy_summary(
        Path(args.account_dir),
        Path(args.repo_root).resolve(),
        load_changed_files(args.changed_files),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
