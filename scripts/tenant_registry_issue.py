#!/usr/bin/env python3
"""Convert tenant onboarding issue form payloads into registry/tenants.yaml updates."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
CARID_RE = re.compile(r"^\d{6,12}$")

FIELD_ALIASES = {
    "what do you need?": "request_type",
    "tenant slug, requested or existing": "tenant_slug",
    "display name": "display_name",
    "what does this tenant own?": "ownership_domain",
    "owner team": "owner_team",
    "carid(s)": "carids",
    "aws account id(s) for this tenant": "tenant_accounts",
    "ghe reviewer team slug": "ghe_team_slug",
    "cross-tenant reference pre-approval, optional": "reference_grant",
    "why is this needed?": "justification",
}


def _clean(value: str | None) -> str:
    if value is None:
        return ""
    value = value.strip()
    if value in {"_No response_", "No response"}:
        return ""
    return value


def parse_issue_body(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []

    def flush():
        nonlocal current, lines
        if current:
            key = FIELD_ALIASES.get(current.strip().lower())
            if key:
                fields[key] = _clean("\n".join(lines))
        current = None
        lines = []

    for line in body.splitlines():
        match = re.match(r"^###\s+(.+?)\s*$", line)
        if match:
            flush()
            current = match.group(1)
            continue
        if current is not None:
            lines.append(line)
    flush()
    return fields


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,\n]", value or "") if item.strip()]


def normalize_request_type(value: str) -> str:
    lowered = value.strip().lower()
    if "create" in lowered:
        return "create"
    if "update" in lowered:
        return "update"
    if "reference" in lowered or "pre-approval" in lowered:
        return "reference_grant"
    raise ValueError(f"Unsupported request type: {value!r}")


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: dict[str, Any]):
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def validate_base(fields: dict[str, str]) -> dict[str, Any]:
    request_type = normalize_request_type(fields.get("request_type", ""))
    tenant_slug = fields.get("tenant_slug", "").strip()
    if not TENANT_RE.match(tenant_slug):
        raise ValueError("tenant_slug must be lowercase kebab-case, 3-64 chars")

    carids = split_csv(fields.get("carids", ""))
    accounts = split_csv(fields.get("tenant_accounts", ""))
    if request_type in {"create", "update"}:
        if not carids or any(not CARID_RE.match(carid) for carid in carids):
            raise ValueError("CARID(s) must be comma/newline separated numeric IDs")
        if not accounts or any(not ACCOUNT_RE.match(account) for account in accounts):
            raise ValueError("AWS account IDs must be 12 digit account IDs")

    ghe_team_slug = fields.get("ghe_team_slug", "").strip()
    if request_type in {"create", "update"} and not ghe_team_slug:
        raise ValueError("GHE reviewer team slug is required")

    return {
        "request_type": request_type,
        "tenant_slug": tenant_slug,
        "display_name": fields.get("display_name", "").strip() or tenant_slug,
        "ownership_domain": fields.get("ownership_domain", "").strip(),
        "owner_team": fields.get("owner_team", "").strip(),
        "carids": carids,
        "accounts": accounts,
        "ghe_team_slug": ghe_team_slug,
        "reference_grant_raw": fields.get("reference_grant", "").strip(),
        "justification": fields.get("justification", "").strip(),
    }


def validate_reference_grant(raw: str, tenant_slug: str) -> dict[str, Any] | None:
    if not raw:
        return None
    grant = yaml.safe_load(raw)
    if not isinstance(grant, dict):
        raise ValueError("reference_grant must be YAML mapping")
    for key in ["target_sgs", "source_tenants", "protocols", "directions"]:
        if key not in grant or not isinstance(grant[key], list) or not grant[key]:
            raise ValueError(f"reference_grant.{key} must be a non-empty list")
    if not grant.get("ports") and not grant.get("port_ranges"):
        raise ValueError("reference_grant must include ports or port_ranges")
    ports = grant.get("ports") or []
    if ports and (not isinstance(ports, list) or any(int(port) < 1 or int(port) > 65535 for port in ports)):
        raise ValueError("reference_grant.ports must be valid TCP/UDP ports")
    grant.setdefault("name", f"allow-{tenant_slug}-reference-{len(grant.get('target_sgs', []))}")
    grant.setdefault("decision", "auto_approved")
    grant.setdefault("expires", None)
    return grant


def apply_request(repo_root: Path, fields: dict[str, str]) -> dict[str, Any]:
    req = validate_base(fields)
    tenants_path = repo_root / "registry" / "tenants.yaml"
    authorities_path = repo_root / "registry" / "review-authorities.yaml"
    tenants_doc = load_yaml(tenants_path)
    authorities_doc = load_yaml(authorities_path)
    tenants = tenants_doc.setdefault("tenants", {})
    authorities = authorities_doc.get("authorities", {}) or {}

    request_type = req["request_type"]
    tenant_slug = req["tenant_slug"]
    authority_name = f"{tenant_slug}-sg"

    if request_type == "create" and tenant_slug in tenants:
        raise ValueError(f"Tenant {tenant_slug!r} already exists")
    if request_type in {"update", "reference_grant"} and tenant_slug not in tenants:
        raise ValueError(f"Tenant {tenant_slug!r} does not exist")

    changed = []
    if request_type in {"create", "update"}:
        tenant = tenants.get(tenant_slug, {}) or {}
        tenant.update({
            "display_name": req["display_name"],
            "description": req["ownership_domain"],
            "status": "active",
            "owner_team": req["owner_team"],
            "review_authority": authority_name,
            "github_reviewers": [],
            "slack_channel": None,
            "carids": req["carids"],
            "allowed_accounts": req["accounts"],
        })
        tenants[tenant_slug] = tenant
        changed.append(f"tenant {tenant_slug}")
        if authority_name not in authorities:
            authorities[authority_name] = {
                "description": f"SG review authority for {req['display_name']}",
                "ghe_host": "github.aexp.com",
                "org": "amex-eng",
                "team_slug": req["ghe_team_slug"],
            }
            changed.append(f"authority {authority_name}")

    grant = validate_reference_grant(req["reference_grant_raw"], tenant_slug)
    if grant:
        tenant = tenants.setdefault(tenant_slug, {})
        grants = tenant.setdefault("reference_grants", [])
        existing_names = {g.get("name") for g in grants if isinstance(g, dict)}
        if grant["name"] in existing_names:
            raise ValueError(f"reference grant {grant['name']!r} already exists on tenant {tenant_slug}")
        grants.append(grant)
        changed.append(f"reference grant {grant['name']}")

    dump_yaml(tenants_path, tenants_doc)
    dump_yaml(authorities_path, authorities_doc)
    return {"changed": changed, "tenant_slug": tenant_slug, "request_type": request_type}


def main():
    parser = argparse.ArgumentParser(description="Apply tenant registry issue request")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--issue-body-file", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    body = Path(args.issue_body_file).read_text()
    fields = parse_issue_body(body)
    result = apply_request(Path(args.repo_root), fields)
    Path(args.output_json).write_text(json.dumps(result, indent=2, sort_keys=True))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
