#!/usr/bin/env python3
"""
Slack notification for SG validation results.

Builds a compact delta-focused Slack message from the same account diff model
used by the PR summary, instead of dumping every rule from every SG.
"""

import json
import os
import sys
import subprocess
import urllib.request
from datetime import datetime, timezone

import yaml

from pr_summary import analyze_account


def count_rules(sg_config: dict) -> int:
    ingress = sg_config.get("ingress", []) or []
    egress = sg_config.get("egress", []) or []
    return len(ingress) + len(egress)


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def changed_file_categories(changed_files: list[str]) -> set[str]:
    categories = set()
    for filename in changed_files:
        if filename.startswith("accounts/"):
            categories.add("accounts")
        elif filename.startswith("registry/"):
            categories.add("registry")
        elif filename.startswith(".github/") or filename.startswith("scripts/") or filename.startswith("modules/"):
            categories.add("framework")
        elif filename in {"guardrails.yaml", "known-prefix-lists.yaml", "shared-prefix-lists.yaml"}:
            categories.add("guardrails")
        else:
            categories.add("other")
    return categories


def run_policy_summary(account_id: str, changed_files_path: str) -> dict:
    try:
        output = subprocess.check_output(
            [sys.executable, "scripts/policy_summary.py", f"accounts/{account_id}", "--changed-files", changed_files_path],
            text=True,
        )
        return json.loads(output)
    except Exception as exc:
        return {"account_id": account_id, "auto_merge_eligible": False, "auto_merge_reason": f"policy summary unavailable: {exc}", "required_review_authorities": {}}


def load_yaml_file(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def build_delta_blocks(changed_accounts: str, base_ref: str) -> tuple[list, str, bool]:
    account_ids = [a.strip() for a in changed_accounts.split(",") if a.strip()]
    summaries = [analyze_account(aid, base_ref) for aid in account_ids]
    summaries = [s for s in summaries if s.get("changes")]
    if not summaries:
        return [], "No material security group delta detected.", False

    lines = []
    has_prod = False
    max_accounts = 5
    max_sgs = 10
    sg_counter = 0

    for account in summaries[:max_accounts]:
        env = account.get("env", "unknown")
        if env == "prod":
            has_prod = True
        account_regions = account.get("regions", []) or [account.get("default_region", "us-east-1")]
        tenant = account.get("tenant", "default")
        tenant_status = account.get("tenant_status", "unknown")
        owner_team = account.get("owner_team", "—")
        allowed_icon = "✅" if account.get("account_allowed", True) else "⚠️"
        lines.append(
            f"*`{account['id']}`* ({env}) — tenant: `{tenant}` ({tenant_status}) — owner: `{owner_team}` — regions: {', '.join(account_regions)} {allowed_icon}"
        )
        if not account.get("account_allowed", True):
            lines.append("  ⚠️ account not listed in tenant `allowed_accounts`")

        if not account.get("base_found", True):
            changes = account.get("changes", {})
            total_sgs = len(changes)
            total_rules = sum(count_rules(change.get("new_config", {})) for change in changes.values())
            lines.append(f"• new account config — {total_sgs} SG(s), {total_rules} total rule(s)")
            preview_names = list(changes.keys())[:5]
            if preview_names:
                lines.append(f"  SGs: {', '.join(f'`{name}`' for name in preview_names)}")
            if total_sgs > len(preview_names):
                lines.append(f"  _...{total_sgs - len(preview_names)} additional SG(s) omitted for brevity_")
            continue

        for sg_name, sg_data in list(account.get("changes", {}).items()):
            if sg_counter >= max_sgs:
                lines.append("_...additional SG changes omitted for brevity_")
                return summaries, "\n".join(lines), has_prod
            change_type = sg_data.get("change_type", "modified")
            regions = sg_data.get("regions", []) or [account.get("default_region", "us-east-1")]
            lines.append(f"• `{sg_name}` — {change_type} — {', '.join(regions)}")
            ingress = sg_data.get("ingress_diff") or ([], [], [])
            egress = sg_data.get("egress_diff") or ([], [], [])
            added = len(ingress[0]) + len(egress[0])
            removed = len(ingress[1]) + len(egress[1])
            if change_type == "new":
                new_config = sg_data.get("new_config", {})
                lines.append(f"  new SG, {count_rules(new_config)} rule(s) proposed")
            elif change_type == "deleted":
                lines.append(f"  SG removed, {removed} rule(s) disappear")
            else:
                delta_bits = []
                if added:
                    delta_bits.append(f"+{added} rules")
                if removed:
                    delta_bits.append(f"-{removed} rules")
                if not delta_bits:
                    delta_bits.append("region/metadata change")
                lines.append(f"  {' | '.join(delta_bits)}")
            sg_counter += 1

    return summaries, "\n".join(lines), has_prod


def build_sg_payload(changed_accounts: str, base_ref: str, has_warnings: bool, changed_files: list[str], changed_files_path: str) -> dict:
    pr_number = os.environ.get("PR_NUMBER", "?")
    pr_title = os.environ.get("PR_TITLE", "Unknown")
    pr_url = os.environ.get("PR_URL", "")
    pr_author = os.environ.get("PR_AUTHOR", "unknown")
    account_ids = split_csv(changed_accounts)
    policies = [run_policy_summary(account_id, changed_files_path) for account_id in account_ids]
    auto_merge_eligible = bool(policies) and all(policy.get("auto_merge_eligible") for policy in policies)
    summaries, delta_text, has_prod = build_delta_blocks(changed_accounts, base_ref)
    required_authorities = {}
    for policy in policies:
        required_authorities.update(policy.get("required_review_authorities") or {})
    if auto_merge_eligible:
        title_prefix = "✅ Auto-merge eligible"
        sidebar_color = "#2eb67d"
        approvals_text = "None, policy-approved"
    else:
        title_prefix = "⏳ Review required"
        sidebar_color = "#ecb22e"
        approvals_text = ", ".join(f"{name}: {count}" for name, count in required_authorities.items()) or ("2 platform approvals" if has_prod else "1 approval")
    validation_text = "⚠️ Passed with warnings" if has_warnings else "✅ Passed"
    policy_lines = [
        f"• `{policy.get('account_id')}` — {'✅ eligible' if policy.get('auto_merge_eligible') else '❌ not eligible'}"
        + (f" — {policy.get('auto_merge_reason')}" if policy.get('auto_merge_reason') else "")
        for policy in policies
    ] or ["• Not evaluated"]
    timestamp = datetime.now(timezone.utc).strftime("%a %b %d, %I:%M %p UTC")
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{title_prefix} — Security Group Change", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*PR:*\n<{pr_url}|#{pr_number} — {pr_title}>"},
            {"type": "mrkdwn", "text": f"*Author:*\n{pr_author}"},
            {"type": "mrkdwn", "text": f"*Approvals:*\n{approvals_text}"},
            {"type": "mrkdwn", "text": f"*Validation:*\n{validation_text}"},
        ]},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": "*Policy:*\n" + "\n".join(policy_lines)}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Summary:*\n{delta_text}"}},
        {"type": "divider"},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "📋 View PR", "emoji": True}, "url": pr_url, "style": "primary"},
            {"type": "button", "text": {"type": "plain_text", "text": "📁 View Files", "emoji": True}, "url": f"{pr_url}/files"},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"📋 aws-security-groups • {timestamp}"}]},
    ]
    return {"attachments": [{"color": sidebar_color, "blocks": blocks}]}


def build_registry_payload(changed_files: list[str]) -> dict:
    pr_number = os.environ.get("PR_NUMBER", "?")
    pr_title = os.environ.get("PR_TITLE", "Unknown")
    pr_url = os.environ.get("PR_URL", "")
    pr_author = os.environ.get("PR_AUTHOR", "unknown")
    issue_url = os.environ.get("ISSUE_URL", "")
    tenants = load_yaml_file("registry/tenants.yaml").get("tenants", {})
    tenant_lines = []
    for slug, tenant in tenants.items():
        if slug == "default":
            continue
        tenant_lines.append(f"• `{slug}` — {tenant.get('display_name', slug)} — authority `{tenant.get('review_authority', '—')}` — accounts: {', '.join(tenant.get('allowed_accounts') or []) or '—'}")
    tenant_lines = tenant_lines[-8:] or ["• Registry metadata changed, inspect PR files for details."]
    issue_text = f"\n*Issue:* <{issue_url}|source issue>" if issue_url else ""
    timestamp = datetime.now(timezone.utc).strftime("%a %b %d, %I:%M %p UTC")
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🧾 Tenant registry onboarding request", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*PR:*\n<{pr_url}|#{pr_number} — {pr_title}>"},
            {"type": "mrkdwn", "text": f"*Author:*\n{pr_author}"},
            {"type": "mrkdwn", "text": "*Review:*\nPlatform review required"},
            {"type": "mrkdwn", "text": f"*Changed files:*\n{len(changed_files)}"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": "*Tenant registry delta:*\n" + "\n".join(tenant_lines) + issue_text}},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "📋 Review Registry PR", "emoji": True}, "url": pr_url, "style": "primary"},
            {"type": "button", "text": {"type": "plain_text", "text": "📁 View Files", "emoji": True}, "url": f"{pr_url}/files"},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"📋 aws-security-groups • {timestamp}"}]},
    ]
    return {"attachments": [{"color": "#785ef0", "blocks": blocks}]}


def build_framework_payload(changed_files: list[str]) -> dict:
    pr_number = os.environ.get("PR_NUMBER", "?")
    pr_title = os.environ.get("PR_TITLE", "Unknown")
    pr_url = os.environ.get("PR_URL", "")
    pr_author = os.environ.get("PR_AUTHOR", "unknown")
    preview = "\n".join(f"• `{f}`" for f in changed_files[:12])
    if len(changed_files) > 12:
        preview += f"\n• _...{len(changed_files)-12} more_"
    timestamp = datetime.now(timezone.utc).strftime("%a %b %d, %I:%M %p UTC")
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🛠️ Framework governance change", "emoji": True}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*PR:*\n<{pr_url}|#{pr_number} — {pr_title}>"},
            {"type": "mrkdwn", "text": f"*Author:*\n{pr_author}"},
            {"type": "mrkdwn", "text": "*Review:*\nPlatform review required"},
            {"type": "mrkdwn", "text": "*Auto-merge:*\nNot eligible"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Changed files:*\n{preview}"}},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "📋 Review PR", "emoji": True}, "url": pr_url, "style": "primary"},
            {"type": "button", "text": {"type": "plain_text", "text": "📁 View Files", "emoji": True}, "url": f"{pr_url}/files"},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"📋 aws-security-groups • {timestamp}"}]},
    ]
    return {"attachments": [{"color": "#439fe0", "blocks": blocks}]}


def build_payload(changed_accounts: str, base_ref: str, has_warnings: bool) -> dict:
    changed_files_path = os.environ.get("CHANGED_FILES_PATH", "/tmp/changed-files.txt")
    if os.path.exists(changed_files_path):
        changed_files = [line.strip() for line in open(changed_files_path) if line.strip()]
    else:
        changed_files = subprocess.check_output(["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"], text=True).splitlines()
    categories = changed_file_categories(changed_files)
    account_ids = split_csv(changed_accounts)
    if categories == {"registry"} or ("registry" in categories and not account_ids):
        return build_registry_payload(changed_files)
    if not account_ids:
        return build_framework_payload(changed_files)
    return build_sg_payload(changed_accounts, base_ref, has_warnings, changed_files, changed_files_path)


def send_webhook(payload: dict) -> bool:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        print("::warning::SLACK_WEBHOOK_URL not set — skipping notification")
        return False

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                print("✅ Slack notification sent")
                return True
            print(f"::warning::Slack webhook returned {resp.status}")
            return False
    except Exception as e:
        print(f"::warning::Slack webhook error: {e}")
        return False


def main():
    changed_accounts = os.environ.get("CHANGED_ACCOUNTS", "")
    base_ref = os.environ.get("BASE_REF", "main")

    has_warnings_env = os.environ.get("HAS_WARNINGS", "").lower()
    has_warnings = has_warnings_env == "true" if has_warnings_env in ("true", "false") else False

    payload = build_payload(changed_accounts, base_ref, has_warnings)
    print("Slack payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    send_webhook(payload)


if __name__ == "__main__":
    main()
