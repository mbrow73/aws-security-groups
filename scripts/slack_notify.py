#!/usr/bin/env python3
"""
Slack notification for SG validation results.

Builds a compact delta-focused Slack message from the same account diff model
used by the PR summary, instead of dumping every rule from every SG.
"""

import json
import os
import urllib.request
from datetime import datetime, timezone

from pr_summary import analyze_account


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
        lines.append(f"*`{account['id']}`* ({env}) — regions: {', '.join(account_regions)}")

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
                lines.append(f"  new SG, {added} rule(s) proposed")
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


def build_payload(changed_accounts: str, base_ref: str, has_warnings: bool) -> dict:
    pr_number = os.environ.get("PR_NUMBER", "?")
    pr_title = os.environ.get("PR_TITLE", "Unknown")
    pr_url = os.environ.get("PR_URL", "")
    pr_author = os.environ.get("PR_AUTHOR", "unknown")

    summaries, delta_text, has_prod = build_delta_blocks(changed_accounts, base_ref)

    required_approvals = 2 if has_prod else 1
    env_emoji = "🔴" if has_prod else "🟢"
    env_label = "PROD" if has_prod else "NONPROD"
    sidebar_color = "#dc3545" if has_prod else "#28a745"
    validation_text = "⚠️ Passed with warnings" if has_warnings else "✅ Passed"
    timestamp = datetime.now(timezone.utc).strftime("%a %b %d, %I:%M %p UTC")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{env_emoji} {env_label} — Security Group Change Request",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*PR:*\n<{pr_url}|#{pr_number} — {pr_title}>"},
                {"type": "mrkdwn", "text": f"*Author:*\n{pr_author}"},
                {"type": "mrkdwn", "text": f"*Approvals Required:*\n{required_approvals}"},
                {"type": "mrkdwn", "text": f"*Validation:*\n{validation_text}"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Delta:*\n{delta_text}",
            },
        },
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "📋 View PR", "emoji": True},
                    "url": pr_url,
                    "style": "primary",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "📁 View Files", "emoji": True},
                    "url": f"{pr_url}/files",
                },
            ],
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"📋 aws-security-groups • {timestamp}"}],
        },
    ]

    return {"attachments": [{"color": sidebar_color, "blocks": blocks}]}


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
    if not changed_accounts:
        print("No changed accounts — skipping")
        return

    has_warnings_env = os.environ.get("HAS_WARNINGS", "").lower()
    has_warnings = has_warnings_env == "true" if has_warnings_env in ("true", "false") else False

    payload = build_payload(changed_accounts, base_ref, has_warnings)
    print("Slack payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    send_webhook(payload)


if __name__ == "__main__":
    main()
