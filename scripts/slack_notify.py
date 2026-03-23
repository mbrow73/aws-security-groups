#!/usr/bin/env python3
"""
Slack notification for SG validation results.

Parses account YAMLs and sends a styled Block Kit message to Slack
via webhook. Only called when validation passes (with or without warnings).

Environment variables (set by GHA workflow):
    SLACK_WEBHOOK_URL  - Slack incoming webhook URL
    CHANGED_ACCOUNTS   - Comma-separated account IDs
    PR_NUMBER          - Pull request number
    PR_TITLE           - Pull request title
    PR_URL             - Pull request URL
    PR_AUTHOR          - Pull request author login
    VALIDATE_RESULT    - "success" or "failure"
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

import yaml


def parse_account(account_id: str) -> dict:
    """Parse an account YAML and extract SG details."""
    yaml_path = Path(f"accounts/{account_id}/security-groups.yaml")
    result = {
        "id": account_id,
        "env": "unknown",
        "security_groups": [],
        "warnings": [],
    }

    try:
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        result["warnings"].append(f"Could not read YAML: {e}")
        return result

    result["env"] = data.get("environment", "unknown").lower().strip()
    sgs = data.get("security_groups", {})

    for sg_name, sg_config in sgs.items():
        sg = {
            "name": sg_name,
            "description": sg_config.get("description", ""),
            "rules": [],
            "warnings": [],
        }

        # Parse ingress rules
        for rule in sg_config.get("ingress", []) or []:
            if not isinstance(rule, dict):
                continue
            sg["rules"].append(format_rule("ingress", rule))

        # Parse egress rules
        for rule in sg_config.get("egress", []) or []:
            if not isinstance(rule, dict):
                continue
            sg["rules"].append(format_rule("egress", rule))

        # Check for empty rule lists (these are warnings)
        if "ingress" in sg_config and sg_config["ingress"] == []:
            sg["warnings"].append("Empty ingress list")
        if "egress" in sg_config and sg_config["egress"] == []:
            sg["warnings"].append("Empty egress list")

        result["security_groups"].append(sg)

    return result


def format_rule(direction: str, rule: dict) -> str:
    """Format a single rule into a human-readable line."""
    arrow = "\u2190" if direction == "ingress" else "\u2192"  # ← or →
    protocol = rule.get("protocol", "tcp").upper()
    from_port = rule.get("from_port", "?")
    to_port = rule.get("to_port", "?")
    desc = rule.get("description", "")

    # Port display
    if from_port == to_port:
        port = str(from_port)
    else:
        port = f"{from_port}-{to_port}"

    # Source/destination
    source = ""
    if rule.get("baseline_ref"):
        source = f"\U0001f3d7\ufe0f baseline:{rule['baseline_ref']}"  # 🏗️
    elif rule.get("cidr_blocks"):
        source = ", ".join(rule["cidr_blocks"])
    elif rule.get("security_groups"):
        sgs = rule["security_groups"]
        source = ", ".join(f"\U0001f517 {sg}" for sg in sgs)  # 🔗
    elif rule.get("prefix_list_ids"):
        pls = rule["prefix_list_ids"]
        source = ", ".join(f"\U0001f4cb {pl}" for pl in pls)  # 📋

    direction_label = "from" if direction == "ingress" else "to  "

    return f"{arrow} {protocol}/{port} {direction_label} {source}  {desc}"


def build_sg_blocks(accounts: list) -> str:
    """Build the security groups detail section for Slack."""
    lines = []
    sg_count = 0
    max_sgs = 10
    max_rules_per_sg = 5

    for account in accounts:
        for sg in account["security_groups"]:
            if sg_count >= max_sgs:
                remaining = sum(len(a["security_groups"]) for a in accounts) - max_sgs
                if remaining > 0:
                    lines.append(f"_...and {remaining} more security group(s)_")
                return "\n".join(lines)

            lines.append(f"\n`{sg['name']}` \u2014 {sg['description']}")

            # Rules
            rules = sg["rules"]
            if rules:
                rule_lines = rules[:max_rules_per_sg]
                lines.append("```")
                lines.extend(rule_lines)
                if len(rules) > max_rules_per_sg:
                    lines.append(f"  ...and {len(rules) - max_rules_per_sg} more rule(s)")
                lines.append("```")

            # Inline warnings
            for warn in sg.get("warnings", []):
                lines.append(f"\u26a0\ufe0f {warn}")

            sg_count += 1

    return "\n".join(lines)


def build_payload(accounts: list, has_prod: bool, has_warnings: bool) -> dict:
    """Build the Slack Block Kit payload."""
    pr_number = os.environ.get("PR_NUMBER", "?")
    pr_title = os.environ.get("PR_TITLE", "Unknown")
    pr_url = os.environ.get("PR_URL", "")
    pr_author = os.environ.get("PR_AUTHOR", "unknown")

    required_approvals = 2 if has_prod else 1
    env_emoji = "\U0001f534" if has_prod else "\U0001f7e2"  # 🔴 or 🟢
    env_label = "PROD" if has_prod else "NONPROD"
    sidebar_color = "#dc3545" if has_prod else "#28a745"

    if has_warnings:
        validation_text = "\u26a0\ufe0f Passed with warnings"
    else:
        validation_text = "\u2705 Passed"

    # Account summary lines
    account_lines = []
    for a in accounts:
        emoji = "\U0001f534" if a["env"] == "prod" else "\U0001f7e2"
        sg_count = len(a["security_groups"])
        account_lines.append(
            f"{emoji} `{a['id']}` ({a['env']}) \u2014 {sg_count} security group(s)"
        )

    # SG detail block
    sg_detail = build_sg_blocks(accounts)

    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).strftime("%a %b %d, %I:%M %p UTC")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{env_emoji} {env_label} \u2014 Security Group Change Request",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*PR:*\n<{pr_url}|#{pr_number} \u2014 {pr_title}>",
                },
                {"type": "mrkdwn", "text": f"*Author:*\n{pr_author}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Approvals Required:*\n{required_approvals}",
                },
                {"type": "mrkdwn", "text": f"*Validation:*\n{validation_text}"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Accounts Affected:*\n" + "\n".join(account_lines),
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Security Groups:*\n{sg_detail}",
            },
        },
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "\U0001f4cb View PR",
                        "emoji": True,
                    },
                    "url": pr_url,
                    "style": "primary",
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "\U0001f4c1 View Files",
                        "emoji": True,
                    },
                    "url": f"{pr_url}/files",
                },
            ],
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"\U0001f4cb aws-security-groups \u2022 {timestamp}",
                }
            ],
        },
    ]

    return {"attachments": [{"color": sidebar_color, "blocks": blocks}]}


def send_webhook(payload: dict) -> bool:
    """Send payload to Slack webhook. Returns True on success."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        print("::warning::SLACK_WEBHOOK_URL not set \u2014 skipping notification")
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
                print("\u2705 Slack notification sent")
                return True
            else:
                print(f"::warning::Slack webhook returned {resp.status}")
                return False
    except Exception as e:
        print(f"::warning::Slack webhook error: {e}")
        return False


def main():
    changed_accounts = os.environ.get("CHANGED_ACCOUNTS", "")
    if not changed_accounts:
        print("No changed accounts \u2014 skipping")
        return

    account_ids = [a.strip() for a in changed_accounts.split(",") if a.strip()]

    # Parse all accounts
    accounts = [parse_account(aid) for aid in account_ids]

    has_prod = any(a["env"] == "prod" for a in accounts)
    # Use the authoritative warning flag from validate.py (passed via GHA output).
    # Falls back to local detection if not set.
    has_warnings_env = os.environ.get("HAS_WARNINGS", "").lower()
    if has_warnings_env in ("true", "false"):
        has_warnings = has_warnings_env == "true"
    else:
        has_warnings = any(
            w
            for a in accounts
            for sg in a["security_groups"]
            for w in sg.get("warnings", [])
        )

    payload = build_payload(accounts, has_prod, has_warnings)

    # Debug: print payload for GHA logs
    print("Slack payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))

    send_webhook(payload)


if __name__ == "__main__":
    main()
