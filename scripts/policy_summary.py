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


def iter_sg_refs(account_config):
    for source in account_config.sources:
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


def build_policy_summary(account_dir: Path, repo_root: Path) -> dict[str, Any]:
    account_dir = Path(account_dir)
    repo_root = Path(repo_root)
    account_config = load_account_config(account_dir, repo_root)
    tenants = load_tenant_registry(repo_root)
    platform_sgs = load_platform_security_groups(repo_root)
    review_registry = load_review_authorities(repo_root)
    sg_tenant_map = build_sg_tenant_map(account_config)

    tenant_slugs = sorted({source.tenant for source in account_config.sources})
    env = str(account_config.config.get("environment", "prod")).lower()
    prod = env == "prod"
    requirements: dict[str, int] = {}

    for tenant in tenant_slugs or ["default"]:
        add_requirement(requirements, tenant_authority(tenants, tenant), 2 if prod else 1)

    references = []
    for source_sg, target_sg, direction, index, rule in iter_sg_refs(account_config):
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

    return {
        "account_id": account_config.account_id,
        "environment": env,
        "layout": account_config.layout,
        "tenants": tenant_slugs,
        "sg_tenants": sg_tenant_map,
        "references": references,
        "required_review_authorities": dict(sorted(requirements.items())),
        "review_authorities": review_registry.get("authorities", {}),
        "errors": account_config.errors,
        "warnings": account_config.warnings,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate SG policy summary JSON")
    parser.add_argument("account_dir", help="Account directory, e.g. accounts/123456789012")
    parser.add_argument("--repo-root", default=".", help="Repository root")
    args = parser.parse_args()

    summary = build_policy_summary(Path(args.account_dir), Path(args.repo_root).resolve())
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
