#!/usr/bin/env python3
"""
PR Change Summary Bot.

Compares the PR branch against the base branch to produce a human-readable
diff of security group changes. Posts (or updates) a single comment on the PR.

Only runs when validation passes (with or without warnings).
If validation later fails on a subsequent push, the workflow deletes the
stale summary comment so reviewers don't see an outdated dashboard.

Environment variables (set by GHA workflow):
    CHANGED_ACCOUNTS   - Comma-separated account IDs
    HAS_WARNINGS       - "true" or "false" from validate job
    GITHUB_TOKEN       - GitHub token for posting comments
    PR_NUMBER          - Pull request number
    REPO               - owner/repo string
    BASE_REF           - Base branch ref (e.g. main)
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from tenant_context import resolve_tenant_context


COMMENT_MARKER = "<!-- sg-change-summary-bot -->"


def load_yaml_file(path: str) -> dict:
    """Load a YAML file, returning empty dict on failure."""
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def tenant_context_for_account(account_id: str) -> dict:
    """Resolve tenant summary context for current account config path."""
    context = resolve_tenant_context(Path(f"accounts/{account_id}/security-groups.yaml"), Path.cwd())
    return {
        "tenant": context.tenant,
        "tenant_display_name": context.display_name,
        "tenant_status": context.status,
        "owner_team": context.owner_team,
        "github_reviewers": context.github_reviewers,
        "slack_channel": context.slack_channel,
        "account_allowed": context.account_allowed,
        "tenant_layout": context.layout,
    }


def get_base_yaml(account_id: str, base_ref: str) -> tuple[dict, bool]:
    """Get the account YAML from the base branch. Returns (yaml, found)."""
    file_path = f"accounts/{account_id}/security-groups.yaml"
    try:
        result = subprocess.run(
            ["git", "show", f"origin/{base_ref}:{file_path}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return yaml.safe_load(result.stdout) or {}, True
    except Exception:
        pass
    return {}, False


def format_source(rule: dict) -> str:
    """Format the source/destination of a rule with icons."""
    if rule.get("baseline_ref"):
        return f"🏗️ `baseline:{rule['baseline_ref']}`"
    elif rule.get("cidr_blocks"):
        return ", ".join(f"`{c}`" for c in rule["cidr_blocks"])
    elif rule.get("security_groups"):
        return ", ".join(f"🔗 `{sg}`" for sg in rule["security_groups"])
    elif rule.get("prefix_list_ids"):
        return ", ".join(f"📋 `{pl}`" for pl in rule["prefix_list_ids"])
    return "—"


def format_port(rule: dict) -> str:
    """Format port display."""
    from_port = rule.get("from_port", "?")
    to_port = rule.get("to_port", "?")
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def rules_equal(a: dict, b: dict) -> bool:
    """Check if two rules are functionally identical."""
    keys = ["protocol", "from_port", "to_port", "cidr_blocks",
            "security_groups", "prefix_list_ids", "baseline_ref", "description"]
    for k in keys:
        if a.get(k) != b.get(k):
            return False
    return True


def diff_rules(old_rules: list, new_rules: list) -> tuple:
    """Diff two rule lists. Returns (added, removed, unchanged)."""
    old_rules = old_rules or []
    new_rules = new_rules or []

    added = []
    removed = []
    unchanged = []

    # Find removed and unchanged
    for old_rule in old_rules:
        found = False
        for new_rule in new_rules:
            if rules_equal(old_rule, new_rule):
                found = True
                break
        if found:
            unchanged.append(old_rule)
        else:
            removed.append(old_rule)

    # Find added
    for new_rule in new_rules:
        found = False
        for old_rule in old_rules:
            if rules_equal(old_rule, new_rule):
                found = True
                break
        if not found:
            added.append(new_rule)

    return added, removed, unchanged


def detect_cross_refs(all_sgs: dict) -> list:
    """Detect bidirectional cross-SG references."""
    refs = []
    sg_names = set(all_sgs.keys())

    for sg_name, sg_config in all_sgs.items():
        for direction in ("ingress", "egress"):
            for rule in sg_config.get(direction, []) or []:
                if not isinstance(rule, dict):
                    continue
                for ref_sg in rule.get("security_groups", []):
                    if ref_sg in sg_names and ref_sg != sg_name:
                        # Check if the referenced SG also references back
                        other = all_sgs[ref_sg]
                        other_dir = "egress" if direction == "ingress" else "ingress"
                        for other_rule in other.get(other_dir, []) or []:
                            if not isinstance(other_rule, dict):
                                continue
                            if sg_name in other_rule.get("security_groups", []):
                                port = format_port(rule)
                                proto = rule.get("protocol", "tcp").upper()
                                # Normalize so A↔B and B↔A are the same
                                pair = tuple(sorted([sg_name, ref_sg]))
                                ref_str = f"`{pair[0]}` ↔ `{pair[1]}` (bidirectional {proto}/{port})"
                                if ref_str not in refs:
                                    refs.append(ref_str)
    return refs


def build_rule_table(rules: list, prefix: str = "", direction: str = "") -> str:
    """Build a markdown table of rules."""
    if not rules:
        return ""

    if direction == "ingress":
        dir_label = "Source"
    elif direction == "egress":
        dir_label = "Destination"
    else:
        dir_label = "Source/Dest"

    lines = [
        f"| | Port | Protocol | {dir_label} | Description |",
        "|---|------|----------|-------------|-------------|",
    ]
    for rule in rules:
        icon = prefix
        port = format_port(rule)
        proto = rule.get("protocol", "tcp").upper()
        source = format_source(rule)
        desc = rule.get("description", "")
        lines.append(f"| {icon} | `{port}` | {proto} | {source} | {desc} |")

    return "\n".join(lines)


def build_summary(accounts_data: list, has_warnings: bool) -> str:
    """Build the full PR change summary markdown."""
    lines = [COMMENT_MARKER]
    lines.append("## 🔒 Security Group Change Summary\n")

    total_added = 0
    total_modified = 0
    total_deleted = 0
    total_rules_added = 0
    total_rules_removed = 0
    regions = set()
    all_new_sgs = {}  # For cross-ref detection

    for account in accounts_data:
        account_id = account["id"]
        env = account["env"]
        carid = account.get("carid", "—")
        env_emoji = "🔴" if env == "prod" else "🟢"
        tenant = account.get("tenant", "default")
        tenant_display = account.get("tenant_display_name", "Default Single-Tenant Account")
        owner_team = account.get("owner_team", "—")
        tenant_status = account.get("tenant_status", "unknown")

        lines.append(f"**Account:** `{account_id}` ({env}) | **CARID:** `{carid}`\n")
        lines.append(f"**Tenant:** `{tenant}` ({tenant_display}) | **Owner:** `{owner_team}` | **Status:** `{tenant_status}`\n")
        if not account.get("account_allowed", True):
            lines.append("⚠️ **Registry warning:** account is not listed under this tenant's `allowed_accounts`.\n")
        lines.append("---\n")

        # Group by region
        regions_in_account = {}
        for sg_name, sg_data in account.get("changes", {}).items():
            sg_regions = sg_data.get("regions", []) or [account.get("default_region", "us-east-1")]
            for region in sg_regions:
                regions.add(region)
                if region not in regions_in_account:
                    regions_in_account[region] = []
                regions_in_account[region].append((sg_name, sg_data))

        for region, sgs in sorted(regions_in_account.items()):
            default = account.get("default_region", "us-east-1")
            account_regions = account.get("regions", []) or [default]
            if len(account_regions) > 1 and region in account_regions:
                region_label = f"{region} (account regions)"
            elif region == default:
                region_label = f"{region} (default region)"
            else:
                region_label = f"{region} (explicit override)"
            lines.append(f"### 📍 {region_label}\n")

            for sg_name, sg_data in sgs:
                change_type = sg_data["change_type"]
                desc = sg_data.get("description", "")

                if change_type == "new":
                    total_added += 1
                    lines.append(f"#### ➕ NEW: `{sg_name}`")
                    lines.append(f"> *{desc}*\n")
                    all_new_sgs[sg_name] = sg_data.get("new_config", {})

                    ingress = sg_data.get("new_config", {}).get("ingress", []) or []
                    egress = sg_data.get("new_config", {}).get("egress", []) or []

                    if ingress:
                        lines.append(f"**Ingress ({len(ingress)} rule{'s' if len(ingress) != 1 else ''}):**")
                        lines.append(build_rule_table(ingress, "", "ingress"))
                        lines.append("")
                        total_rules_added += len(ingress)

                    if egress:
                        lines.append(f"**Egress ({len(egress)} rule{'s' if len(egress) != 1 else ''}):**")
                        lines.append(build_rule_table(egress, "", "egress"))
                        lines.append("")
                        total_rules_added += len(egress)

                    if not ingress and not egress:
                        lines.append("**No rules defined** (empty SG)\n")

                    if not egress and ingress:
                        lines.append("**Egress:** None (implicit deny-all ✅)\n")

                    if not ingress and egress:
                        lines.append("**Ingress:** None (implicit deny-all ✅)\n")

                elif change_type == "modified":
                    total_modified += 1
                    lines.append(f"#### ✏️ MODIFIED: `{sg_name}`")
                    lines.append(f"> *{desc}*\n")

                    for direction in ("ingress", "egress"):
                        added, removed, _ = sg_data.get(f"{direction}_diff", ([], [], []))
                        if added:
                            lines.append(f"**Rules Added ({direction}):**")
                            lines.append(build_rule_table(added, "➕"))
                            lines.append("")
                            total_rules_added += len(added)
                        if removed:
                            lines.append(f"**Rules Removed ({direction}):**")
                            lines.append(build_rule_table(removed, "➖"))
                            lines.append("")
                            total_rules_removed += len(removed)

                elif change_type == "deleted":
                    total_deleted += 1
                    lines.append(f"#### 🗑️ DELETED: `{sg_name}`")
                    lines.append(f"> *{desc}*\n")
                    lines.append("⚠️ **This security group is being removed.** Verify no active ENI attachments before approving.\n")

                    old_config = sg_data.get("old_config", {})
                    old_ingress = old_config.get("ingress", []) or []
                    old_egress = old_config.get("egress", []) or []
                    all_old_rules = old_ingress + old_egress
                    total_rules_removed += len(all_old_rules)

                    if all_old_rules:
                        lines.append("<details>")
                        lines.append("<summary>Rules being removed (click to expand)</summary>\n")
                        if old_ingress:
                            lines.append(build_rule_table(old_ingress, "➖"))
                            lines.append("")
                        if old_egress:
                            lines.append(build_rule_table(old_egress, "➖"))
                            lines.append("")
                        lines.append("</details>\n")

                lines.append("---\n")

    # Cross-references
    if all_new_sgs:
        cross_refs = detect_cross_refs(all_new_sgs)
        if cross_refs:
            for ref in cross_refs:
                lines.append(f"🔗 **Cross-references detected:** {ref}\n")
            lines.append("---\n")

    # Summary table
    lines.append("### 📊 Summary\n")
    lines.append("| | Count |")
    lines.append("|---|---|")
    lines.append(f"| Security Groups Added | {total_added} |")
    lines.append(f"| Security Groups Modified | {total_modified} |")
    lines.append(f"| Security Groups Removed | {total_deleted} |")
    lines.append(f"| Rules Added | {total_rules_added} |")
    lines.append(f"| Rules Removed | {total_rules_removed} |")
    lines.append(f"| Regions Affected | {len(regions)} |")
    lines.append("")

    # Validation status
    if has_warnings:
        lines.append("### ⚠️ Validation: Passed with warnings")
    else:
        lines.append("### ✅ Validation: Passed")

    lines.append("")
    lines.append("---")
    lines.append("*🤖 Auto-generated by SG Change Summary Bot*")

    return "\n".join(lines)


def analyze_account(account_id: str, base_ref: str) -> dict:
    """Analyze changes for a single account between base and head."""
    head_data = load_yaml_file(f"accounts/{account_id}/security-groups.yaml")
    base_data, base_found = get_base_yaml(account_id, base_ref)

    head_sgs = head_data.get("security_groups", {})
    base_sgs = base_data.get("security_groups", {})

    result = {
        "id": account_id,
        "env": head_data.get("environment", base_data.get("environment", "unknown")),
        "carid": head_data.get("carid", base_data.get("carid", "—")),
        "default_region": head_data.get("default_region", base_data.get("default_region", "us-east-1")),
        "regions": head_data.get("regions", base_data.get("regions", [])),
        "changes": {},
        "base_found": base_found,
    }
    result.update(tenant_context_for_account(account_id))

    all_sg_names = set(list(head_sgs.keys()) + list(base_sgs.keys()))

    for sg_name in sorted(all_sg_names):
        in_head = sg_name in head_sgs
        in_base = sg_name in base_sgs

        if in_head and not in_base:
            # New SG
            new_config = head_sgs[sg_name]
            result["changes"][sg_name] = {
                "change_type": "new",
                "description": new_config.get("description", ""),
                "regions": new_config.get("regions") or ([new_config["region"]] if "region" in new_config else result["regions"] or [result["default_region"]]),
                "new_config": new_config,
            }

        elif not in_head and in_base:
            # Deleted SG
            old_config = base_sgs[sg_name]
            result["changes"][sg_name] = {
                "change_type": "deleted",
                "description": old_config.get("description", ""),
                "regions": old_config.get("regions") or ([old_config["region"]] if "region" in old_config else result["regions"] or [result["default_region"]]),
                "old_config": old_config,
            }

        elif in_head and in_base:
            # Possibly modified
            old_config = base_sgs[sg_name]
            new_config = head_sgs[sg_name]

            ingress_added, ingress_removed, _ = diff_rules(
                old_config.get("ingress", []),
                new_config.get("ingress", [])
            )
            egress_added, egress_removed, _ = diff_rules(
                old_config.get("egress", []),
                new_config.get("egress", [])
            )

            # Check if description changed
            desc_changed = old_config.get("description") != new_config.get("description")

            if ingress_added or ingress_removed or egress_added or egress_removed or desc_changed:
                result["changes"][sg_name] = {
                    "change_type": "modified",
                    "description": new_config.get("description", ""),
                    "regions": new_config.get("regions") or ([new_config["region"]] if "region" in new_config else result["regions"] or [result["default_region"]]),
                    "ingress_diff": (ingress_added, ingress_removed, []),
                    "egress_diff": (egress_added, egress_removed, []),
                    "old_config": old_config,
                    "new_config": new_config,
                }

    return result


def main():
    changed_accounts = os.environ.get("CHANGED_ACCOUNTS", "")
    if not changed_accounts:
        print("No changed accounts — skipping summary")
        return

    account_ids = [a.strip() for a in changed_accounts.split(",") if a.strip()]
    base_ref = os.environ.get("BASE_REF", "main")
    has_warnings_env = os.environ.get("HAS_WARNINGS", "false").lower()
    has_warnings = has_warnings_env == "true"

    # Analyze all accounts
    accounts_data = [analyze_account(aid, base_ref) for aid in account_ids]

    # Filter to only accounts with actual changes
    accounts_with_changes = [a for a in accounts_data if a["changes"]]

    if not accounts_with_changes:
        print("No SG changes detected — skipping summary")
        return

    summary = build_summary(accounts_with_changes, has_warnings)

    # Output for GHA
    output_path = os.environ.get("GITHUB_OUTPUT", "")
    if output_path:
        with open(output_path, "a") as f:
            f.write("summary<<SUMMARY_EOF\n")
            f.write(summary)
            f.write("\nSUMMARY_EOF\n")

    # Also print for logs
    print(summary)


if __name__ == "__main__":
    main()
