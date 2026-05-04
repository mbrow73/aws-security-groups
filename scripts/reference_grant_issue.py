#!/usr/bin/env python3
"""Convert reference grant issue forms into target-tenant registry PR changes."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
FIELD_ALIASES = {
    "target tenant": "target_tenant",
    "grant name": "grant_name",
    "target sgs, optional": "target_sgs",
    "target owned networks, optional": "target_networks",
    "source tenants": "source_tenants",
    "protocols": "protocols",
    "ports": "ports",
    "port ranges, optional": "port_ranges",
    "directions": "directions",
    "expiry, optional": "expires",
    "reason": "reason",
}


def parse_issue_body(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current = None
    lines: list[str] = []

    def flush():
        nonlocal current, lines
        if current:
            key = FIELD_ALIASES.get(current.strip().lower())
            if key:
                value = "\n".join(lines).strip()
                if value in {"_No response_", "No response"}:
                    value = ""
                fields[key] = value
        current = None
        lines = []

    for line in body.splitlines():
        m = re.match(r"^###\s+(.+?)\s*$", line)
        if m:
            flush()
            current = m.group(1)
        elif current is not None:
            lines.append(line)
    flush()
    return fields


def split_list(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,\n]", value or "") if item.strip()]


def parse_ports(value: str) -> list[Any]:
    ports = split_list(value)
    parsed = []
    for port in ports:
        if port == "*":
            parsed.append("*")
            continue
        if not port.isdigit():
            raise ValueError(f"invalid port {port!r}")
        number = int(port)
        if number < 1 or number > 65535:
            raise ValueError(f"invalid port {port!r}")
        parsed.append(number)
    return parsed


def parse_port_ranges(value: str) -> list[dict[str, int]]:
    if not value.strip():
        return []
    ranges = yaml.safe_load(value)
    if ranges is None:
        return []
    if not isinstance(ranges, list):
        raise ValueError("port_ranges must be a YAML list")
    parsed = []
    for entry in ranges:
        if not isinstance(entry, dict):
            raise ValueError("each port range must be a mapping")
        start = int(entry.get("from_port"))
        end = int(entry.get("to_port"))
        if start < 1 or end > 65535 or start > end:
            raise ValueError(f"invalid port range {entry!r}")
        parsed.append({"from_port": start, "to_port": end})
    return parsed


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: dict[str, Any]):
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def grant_risk(grant: dict[str, Any], target_tenant: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons = []
    if "*" in grant.get("source_tenants", []):
        reasons.append("wildcard source_tenants")
    if "*" in grant.get("protocols", []):
        reasons.append("wildcard protocols")
    if "*" in grant.get("ports", []):
        reasons.append("wildcard ports")
    for r in grant.get("port_ranges", []) or []:
        if int(r["to_port"]) - int(r["from_port"]) + 1 > 20:
            reasons.append("wide port range")
    if not grant.get("expires") and reasons:
        reasons.append("broad grant without expiry")
    owned_networks = target_tenant.get("owned_networks") or {}
    for target in grant.get("target_networks", []) or []:
        for cidr in (owned_networks.get(target, {}) or {}).get("cidrs", []) or []:
            try:
                network = ipaddress.ip_network(str(cidr), strict=False)
                if network.version == 4 and network.prefixlen < 24:
                    reasons.append(f"target network {target} broader than /24")
                if network.version == 6 and network.prefixlen < 64:
                    reasons.append(f"target network {target} broad IPv6 range")
            except ValueError:
                reasons.append(f"target network {target} has invalid CIDR")
    return bool(reasons), reasons


def apply_request(repo_root: Path, fields: dict[str, str]) -> dict[str, Any]:
    tenants_path = repo_root / "registry" / "tenants.yaml"
    doc = load_yaml(tenants_path)
    tenants = doc.setdefault("tenants", {})
    target_tenant = fields.get("target_tenant", "").strip()
    grant_name = fields.get("grant_name", "").strip()
    if not SLUG_RE.match(target_tenant):
        raise ValueError("target_tenant must be lowercase kebab-case")
    if not SLUG_RE.match(grant_name):
        raise ValueError("grant_name must be lowercase kebab-case")
    if target_tenant not in tenants:
        raise ValueError(f"target tenant {target_tenant!r} does not exist")
    tenant = tenants[target_tenant]
    target_sgs = split_list(fields.get("target_sgs", ""))
    target_networks = split_list(fields.get("target_networks", ""))
    if not target_sgs and not target_networks:
        raise ValueError("target_sgs and/or target_networks is required")
    for network in target_networks:
        if network not in (tenant.get("owned_networks") or {}):
            raise ValueError(f"target network {network!r} is not owned by {target_tenant}")
    source_tenants = split_list(fields.get("source_tenants", ""))
    for source in source_tenants:
        if source != "*" and source not in tenants:
            raise ValueError(f"source tenant {source!r} does not exist")
    protocols = [p.lower() for p in split_list(fields.get("protocols", ""))]
    for proto in protocols:
        if proto not in {"tcp", "udp", "icmp", "*"}:
            raise ValueError(f"invalid protocol {proto!r}")
    directions = [d.lower() for d in split_list(fields.get("directions", ""))]
    for direction in directions:
        if direction not in {"ingress", "egress", "*"}:
            raise ValueError(f"invalid direction {direction!r}")
    ports = parse_ports(fields.get("ports", ""))
    port_ranges = parse_port_ranges(fields.get("port_ranges", ""))
    if not ports and not port_ranges:
        raise ValueError("ports and/or port_ranges is required")
    grant = {
        "name": grant_name,
        "source_tenants": source_tenants,
        "protocols": protocols,
        "directions": directions,
        "reason": fields.get("reason", "").strip(),
    }
    if target_sgs:
        grant["target_sgs"] = target_sgs
    if target_networks:
        grant["target_networks"] = target_networks
    if ports:
        grant["ports"] = ports
    if port_ranges:
        grant["port_ranges"] = port_ranges
    expires = fields.get("expires", "").strip()
    if expires and expires.lower() != "null":
        grant["expires"] = expires
    else:
        grant["expires"] = None
    grants = tenant.setdefault("reference_grants", [])
    for existing in grants:
        if isinstance(existing, dict) and existing.get("name") == grant_name:
            raise ValueError(f"grant {grant_name!r} already exists on target tenant {target_tenant}")
    grants.append(grant)
    platform_required, reasons = grant_risk(grant, tenant)
    dump_yaml(tenants_path, doc)
    return {
        "target_tenant": target_tenant,
        "grant_name": grant_name,
        "platform_review_required": platform_required,
        "platform_review_reasons": reasons,
        "target_authority": tenant.get("review_authority"),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--issue-body-file", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()
    fields = parse_issue_body(Path(args.issue_body_file).read_text())
    result = apply_request(Path(args.repo_root), fields)
    Path(args.output_json).write_text(json.dumps(result, indent=2, sort_keys=True))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
