#!/usr/bin/env python3
"""
TFE Workspace Provisioning & Run Trigger

Manages the lifecycle of TFE workspaces for the SG platform:
  - Discovers account directories that need workspaces
  - Creates/updates TFE workspaces with correct configuration
  - Triggers runs on merge for changed accounts
  - Outputs a plan of actions (dry-run mode for CI)

Usage:
    # Dry-run: show what would be created/triggered
    python tfe_workspace.py plan --org ORGNAME --changed-accounts 111222333444,555666777888

    # Apply: actually create workspaces and trigger runs
    python tfe_workspace.py apply --org ORGNAME --changed-accounts 111222333444

    # Sync: ensure all account dirs have workspaces (drift reconciliation)
    python tfe_workspace.py sync --org ORGNAME

Environment:
    TFE_TOKEN         - TFE API token (team or user token with workspace admin)
    TFE_ORG           - TFE organization name (or use --org)
    TFE_ADDRESS       - TFE hostname (default: app.terraform.io)
    TFE_PROJECT_ID    - Optional TFE project ID to group workspaces

Exit codes:
    0 - Success
    1 - Error
    2 - Dry-run plan has changes
"""

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config & Constants
# ---------------------------------------------------------------------------

WORKSPACE_PREFIX = "sg-"
VCS_WORKING_DIR_TEMPLATE = "accounts/{account_id}"
DEFAULT_TFE_ADDRESS = "app.terraform.io"
DEFAULT_TERRAFORM_VERSION = "1.6.0"
DEFAULT_AUTO_APPLY = False  # require manual approval by default

# Tags applied to every managed workspace
MANAGED_TAGS = ["sg-platform", "managed-by:sg-pipeline"]


@dataclass
class WorkspaceConfig:
    """Configuration for a TFE workspace."""
    name: str
    account_id: str
    working_directory: str
    terraform_version: str = DEFAULT_TERRAFORM_VERSION
    auto_apply: bool = DEFAULT_AUTO_APPLY
    vcs_repo: Optional[str] = None
    vcs_branch: str = "main"
    vcs_oauth_token_id: Optional[str] = None
    project_id: Optional[str] = None
    tags: List[str] = field(default_factory=lambda: list(MANAGED_TAGS))
    trigger_patterns: List[str] = field(default_factory=list)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    terraform_variables: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.trigger_patterns:
            self.trigger_patterns = [
                f"accounts/{self.account_id}/**/*",
                "modules/**/*",
                "prefix-lists.yaml",
                "guardrails.yaml",
            ]


@dataclass
class PlanAction:
    """A planned action to take."""
    action: str       # create, update, trigger_run, skip
    workspace: str
    account_id: str
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# TFE API Client
# ---------------------------------------------------------------------------

class TFEClient:
    """Minimal TFE API client using only stdlib."""

    def __init__(self, token: str, address: str = DEFAULT_TFE_ADDRESS, org: str = ""):
        self.token = token
        self.base_url = f"https://{address}/api/v2"
        self.org = org

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        """Make an authenticated TFE API request."""
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/vnd.api+json",
        }

        data = json.dumps(body).encode() if body else None
        req = Request(url, data=data, headers=headers, method=method)

        try:
            with urlopen(req) as resp:
                if resp.status == 204:
                    return {}
                return json.loads(resp.read().decode())
        except HTTPError as e:
            error_body = e.read().decode() if e.fp else ""
            logger.error(f"TFE API {method} {path} → {e.code}: {error_body}")
            raise

    def list_workspaces(self, search: Optional[str] = None) -> List[dict]:
        """List workspaces in the organization, with optional name search."""
        workspaces = []
        page = 1
        while True:
            params = f"?page[number]={page}&page[size]=100"
            if search:
                params += f"&search[name]={search}"
            resp = self._request("GET", f"/organizations/{self.org}/workspaces{params}")
            workspaces.extend(resp.get("data", []))
            pagination = resp.get("meta", {}).get("pagination", {})
            if page >= pagination.get("total-pages", 1):
                break
            page += 1
        return workspaces

    def get_workspace(self, name: str) -> Optional[dict]:
        """Get a workspace by name. Returns None if not found."""
        try:
            return self._request("GET", f"/organizations/{self.org}/workspaces/{name}")
        except HTTPError as e:
            if e.code == 404:
                return None
            raise

    def create_workspace(self, config: WorkspaceConfig) -> dict:
        """Create a new TFE workspace."""
        payload = self._build_workspace_payload(config)
        return self._request("POST", f"/organizations/{self.org}/workspaces", payload)

    def update_workspace(self, workspace_id: str, config: WorkspaceConfig) -> dict:
        """Update an existing TFE workspace."""
        payload = self._build_workspace_payload(config)
        return self._request("PATCH", f"/workspaces/{workspace_id}", payload)

    def create_run(self, workspace_id: str, message: str, auto_apply: bool = False) -> dict:
        """Trigger a new run on a workspace."""
        payload = {
            "data": {
                "type": "runs",
                "attributes": {
                    "message": message,
                    "auto-apply": auto_apply,
                },
                "relationships": {
                    "workspace": {
                        "data": {
                            "type": "workspaces",
                            "id": workspace_id,
                        }
                    }
                },
            }
        }
        return self._request("POST", "/runs", payload)

    def set_variable(self, workspace_id: str, key: str, value: str,
                     category: str = "terraform", sensitive: bool = False,
                     hcl: bool = False) -> dict:
        """Create or update a workspace variable."""
        payload = {
            "data": {
                "type": "vars",
                "attributes": {
                    "key": key,
                    "value": value,
                    "category": category,
                    "sensitive": sensitive,
                    "hcl": hcl,
                },
            }
        }
        return self._request("POST", f"/workspaces/{workspace_id}/vars", payload)

    def list_variables(self, workspace_id: str) -> List[dict]:
        """List variables for a workspace."""
        resp = self._request("GET", f"/workspaces/{workspace_id}/vars")
        return resp.get("data", [])

    def _build_workspace_payload(self, config: WorkspaceConfig) -> dict:
        """Build the JSON:API payload for workspace create/update."""
        attributes = {
            "name": config.name,
            "working-directory": config.working_directory,
            "terraform-version": config.terraform_version,
            "auto-apply": config.auto_apply,
            "file-triggers-enabled": True,
            "trigger-patterns": config.trigger_patterns,
            "queue-all-runs": False,
            "speculative-enabled": True,
            "tag-names": config.tags,
        }

        payload: dict = {
            "data": {
                "type": "workspaces",
                "attributes": attributes,
            }
        }

        # VCS configuration (optional — can also use API-driven runs)
        if config.vcs_repo and config.vcs_oauth_token_id:
            attributes["vcs-repo"] = {
                "identifier": config.vcs_repo,
                "branch": config.vcs_branch,
                "oauth-token-id": config.vcs_oauth_token_id,
            }

        # Project assignment
        if config.project_id:
            payload["data"]["relationships"] = {
                "project": {
                    "data": {
                        "type": "projects",
                        "id": config.project_id,
                    }
                }
            }

        return payload


# ---------------------------------------------------------------------------
# Workspace Provisioner (the brain)
# ---------------------------------------------------------------------------

class WorkspaceProvisioner:
    """Orchestrates workspace provisioning and run triggering."""

    def __init__(self, repo_root: str, org: str, client: Optional[TFEClient] = None,
                 vcs_repo: Optional[str] = None, vcs_oauth_token_id: Optional[str] = None,
                 project_id: Optional[str] = None, terraform_version: str = DEFAULT_TERRAFORM_VERSION,
                 auto_apply: bool = DEFAULT_AUTO_APPLY):
        self.repo_root = Path(repo_root)
        self.org = org
        self.client = client
        self.vcs_repo = vcs_repo
        self.vcs_oauth_token_id = vcs_oauth_token_id
        self.project_id = project_id
        self.terraform_version = terraform_version
        self.auto_apply = auto_apply

    def discover_accounts(self) -> List[str]:
        """Find all 12-digit account directories under accounts/."""
        accounts_dir = self.repo_root / "accounts"
        if not accounts_dir.exists():
            return []
        return sorted([
            d.name for d in accounts_dir.iterdir()
            if d.is_dir() and re.match(r'^\d{12}$', d.name)
            and (d / "security-groups.yaml").exists()
        ])

    def build_workspace_config(self, account_id: str) -> WorkspaceConfig:
        """Build the desired workspace config for an account."""
        return WorkspaceConfig(
            name=f"{WORKSPACE_PREFIX}{account_id}",
            account_id=account_id,
            working_directory=VCS_WORKING_DIR_TEMPLATE.format(account_id=account_id),
            terraform_version=self.terraform_version,
            auto_apply=self.auto_apply,
            vcs_repo=self.vcs_repo,
            vcs_oauth_token_id=self.vcs_oauth_token_id,
            project_id=self.project_id,
        )

    def plan(self, changed_accounts: Optional[List[str]] = None) -> List[PlanAction]:
        """Generate a plan of actions without executing anything."""
        actions = []
        all_accounts = self.discover_accounts()

        # If specific accounts were changed, only plan those
        target_accounts = changed_accounts if changed_accounts else all_accounts

        for account_id in target_accounts:
            if account_id not in all_accounts:
                actions.append(PlanAction(
                    action="skip",
                    workspace=f"{WORKSPACE_PREFIX}{account_id}",
                    account_id=account_id,
                    reason=f"Account directory accounts/{account_id}/security-groups.yaml not found",
                ))
                continue

            config = self.build_workspace_config(account_id)

            # Check if workspace already exists
            if self.client:
                existing = self.client.get_workspace(config.name)
                if existing:
                    ws_id = existing["data"]["id"]
                    # Check for config drift
                    drift = self._detect_drift(existing["data"], config)
                    if drift:
                        actions.append(PlanAction(
                            action="update",
                            workspace=config.name,
                            account_id=account_id,
                            reason=f"Workspace config drift: {', '.join(drift)}",
                            details={"workspace_id": ws_id, "drift": drift},
                        ))

                    # If this account was changed, trigger a run
                    if changed_accounts and account_id in changed_accounts:
                        actions.append(PlanAction(
                            action="trigger_run",
                            workspace=config.name,
                            account_id=account_id,
                            reason="Account YAML changed in this PR",
                            details={"workspace_id": ws_id},
                        ))
                else:
                    actions.append(PlanAction(
                        action="create",
                        workspace=config.name,
                        account_id=account_id,
                        reason="New account — workspace does not exist",
                        details={"config": asdict(config)},
                    ))
                    if changed_accounts and account_id in changed_accounts:
                        actions.append(PlanAction(
                            action="trigger_run",
                            workspace=config.name,
                            account_id=account_id,
                            reason="New workspace — initial run",
                        ))
            else:
                # No client (dry-run without TFE access)
                actions.append(PlanAction(
                    action="create",
                    workspace=config.name,
                    account_id=account_id,
                    reason="Workspace needed (dry-run — no TFE connection)",
                    details={"config": asdict(config)},
                ))
                if changed_accounts and account_id in changed_accounts:
                    actions.append(PlanAction(
                        action="trigger_run",
                        workspace=config.name,
                        account_id=account_id,
                        reason="Changed account (dry-run — no TFE connection)",
                    ))

        return actions

    def apply(self, actions: List[PlanAction]) -> List[Dict[str, Any]]:
        """Execute a list of planned actions against TFE."""
        if not self.client:
            raise RuntimeError("Cannot apply without a TFE client")

        results = []
        workspace_ids: Dict[str, str] = {}  # name -> id cache

        for action in actions:
            result = {"action": action.action, "workspace": action.workspace,
                      "account_id": action.account_id, "status": "pending"}
            try:
                if action.action == "create":
                    config = self.build_workspace_config(action.account_id)
                    resp = self.client.create_workspace(config)
                    ws_id = resp["data"]["id"]
                    workspace_ids[action.workspace] = ws_id

                    # Set the yaml_file variable
                    self.client.set_variable(
                        ws_id, "yaml_file",
                        f"accounts/{action.account_id}/security-groups.yaml",
                        category="terraform"
                    )

                    result["status"] = "created"
                    result["workspace_id"] = ws_id
                    logger.info(f"✅ Created workspace {action.workspace} ({ws_id})")

                elif action.action == "update":
                    ws_id = action.details.get("workspace_id", "")
                    config = self.build_workspace_config(action.account_id)
                    self.client.update_workspace(ws_id, config)
                    workspace_ids[action.workspace] = ws_id
                    result["status"] = "updated"
                    logger.info(f"🔄 Updated workspace {action.workspace}")

                elif action.action == "trigger_run":
                    ws_id = (action.details.get("workspace_id")
                             or workspace_ids.get(action.workspace))
                    if not ws_id:
                        result["status"] = "error"
                        result["error"] = "No workspace ID available for run trigger"
                    else:
                        resp = self.client.create_run(
                            ws_id,
                            f"Triggered by SG platform pipeline for account {action.account_id}",
                            auto_apply=self.auto_apply,
                        )
                        run_id = resp["data"]["id"]
                        result["status"] = "triggered"
                        result["run_id"] = run_id
                        logger.info(f"🚀 Triggered run {run_id} on {action.workspace}")

                elif action.action == "skip":
                    result["status"] = "skipped"
                    logger.info(f"⏭️  Skipped {action.workspace}: {action.reason}")

            except Exception as e:
                result["status"] = "error"
                result["error"] = str(e)
                logger.error(f"❌ Failed {action.action} on {action.workspace}: {e}")

            results.append(result)

        return results

    def _detect_drift(self, existing_data: dict, desired: WorkspaceConfig) -> List[str]:
        """Compare existing workspace with desired config, return list of drifted fields."""
        drift = []
        attrs = existing_data.get("attributes", {})

        if attrs.get("working-directory") != desired.working_directory:
            drift.append("working-directory")
        if attrs.get("terraform-version") != desired.terraform_version:
            drift.append("terraform-version")
        if attrs.get("auto-apply") != desired.auto_apply:
            drift.append("auto-apply")

        # Check trigger patterns
        existing_patterns = set(attrs.get("trigger-patterns", []) or [])
        desired_patterns = set(desired.trigger_patterns)
        if existing_patterns != desired_patterns:
            drift.append("trigger-patterns")

        return drift


# ---------------------------------------------------------------------------
# CLI & Output Formatting
# ---------------------------------------------------------------------------

def format_plan_text(actions: List[PlanAction]) -> str:
    """Format plan actions as human-readable text."""
    if not actions:
        return "✅ No actions needed — all workspaces are in sync."

    lines = ["📋 TFE Workspace Provisioning Plan", "=" * 50, ""]
    
    creates = [a for a in actions if a.action == "create"]
    updates = [a for a in actions if a.action == "update"]
    triggers = [a for a in actions if a.action == "trigger_run"]
    skips = [a for a in actions if a.action == "skip"]

    if creates:
        lines.append(f"🆕 Workspaces to create: {len(creates)}")
        for a in creates:
            lines.append(f"   + {a.workspace} (account {a.account_id})")
            lines.append(f"     Reason: {a.reason}")
        lines.append("")

    if updates:
        lines.append(f"🔄 Workspaces to update: {len(updates)}")
        for a in updates:
            lines.append(f"   ~ {a.workspace} (account {a.account_id})")
            lines.append(f"     Drift: {', '.join(a.details.get('drift', []))}")
        lines.append("")

    if triggers:
        lines.append(f"🚀 Runs to trigger: {len(triggers)}")
        for a in triggers:
            lines.append(f"   → {a.workspace} (account {a.account_id})")
            lines.append(f"     Reason: {a.reason}")
        lines.append("")

    if skips:
        lines.append(f"⏭️  Skipped: {len(skips)}")
        for a in skips:
            lines.append(f"   - {a.workspace}: {a.reason}")
        lines.append("")

    lines.append(f"Total: {len(creates)} create, {len(updates)} update, "
                 f"{len(triggers)} trigger, {len(skips)} skip")
    return "\n".join(lines)


def format_plan_markdown(actions: List[PlanAction]) -> str:
    """Format plan actions as markdown for PR/commit comments."""
    if not actions:
        return "## ✅ TFE Workspace Status\n\nAll workspaces in sync. No changes needed."

    lines = ["## 📋 TFE Workspace Provisioning Plan", ""]
    
    creates = [a for a in actions if a.action == "create"]
    updates = [a for a in actions if a.action == "update"]
    triggers = [a for a in actions if a.action == "trigger_run"]
    skips = [a for a in actions if a.action == "skip"]

    summary_parts = []
    if creates:
        summary_parts.append(f"**{len(creates)}** to create")
    if updates:
        summary_parts.append(f"**{len(updates)}** to update")
    if triggers:
        summary_parts.append(f"**{len(triggers)}** runs to trigger")
    if skips:
        summary_parts.append(f"**{len(skips)}** skipped")
    lines.append(" | ".join(summary_parts))
    lines.append("")

    if creates:
        lines.append("<details>")
        lines.append(f"<summary>🆕 Create {len(creates)} workspace(s)</summary>")
        lines.append("")
        for a in creates:
            config = a.details.get("config", {})
            lines.append(f"**`{a.workspace}`** — account `{a.account_id}`")
            lines.append(f"- Working directory: `{config.get('working_directory', 'N/A')}`")
            lines.append(f"- Terraform version: `{config.get('terraform_version', 'N/A')}`")
            lines.append(f"- Auto-apply: `{config.get('auto_apply', False)}`")
            trigger_patterns = config.get('trigger_patterns', [])
            if trigger_patterns:
                lines.append(f"- Trigger patterns: `{', '.join(trigger_patterns)}`")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    if updates:
        lines.append("<details>")
        lines.append(f"<summary>🔄 Update {len(updates)} workspace(s)</summary>")
        lines.append("")
        for a in updates:
            drift = a.details.get("drift", [])
            lines.append(f"**`{a.workspace}`** — account `{a.account_id}`")
            lines.append(f"- Drifted fields: `{', '.join(drift)}`")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    if triggers:
        lines.append("<details>")
        lines.append(f"<summary>🚀 Trigger {len(triggers)} run(s)</summary>")
        lines.append("")
        for a in triggers:
            lines.append(f"**`{a.workspace}`** — {a.reason}")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="TFE Workspace Provisioner for AWS SG Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", choices=["plan", "apply", "sync"],
                        help="plan: dry-run | apply: execute | sync: reconcile all")
    parser.add_argument("--org", default=None, help="TFE organization name (default: TFE_ORG env var)")
    parser.add_argument("--changed-accounts", default="",
                        help="Comma-separated list of changed account IDs")
    parser.add_argument("--repo-root", default=".",
                        help="Repository root directory (default: cwd)")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--vcs-repo", default=None,
                        help="VCS repo identifier (e.g., mbrow73/aws-security-groups)")
    parser.add_argument("--vcs-oauth-token-id", default=None,
                        help="TFE OAuth token ID for VCS integration")
    parser.add_argument("--terraform-version", default=DEFAULT_TERRAFORM_VERSION)
    parser.add_argument("--auto-apply", action="store_true", default=False)
    parser.add_argument("--project-id", default=None,
                        help="TFE project ID (from TFE_PROJECT_ID env if not set)")

    args = parser.parse_args()

    # Parse changed accounts
    changed_accounts = [a.strip() for a in args.changed_accounts.split(",") if a.strip()]

    # Resolve config from CLI args or environment variables
    org = args.org or os.environ.get("TFE_ORG")
    if not org:
        logger.error("Organization required. Set TFE_ORG env var or pass --org.")
        sys.exit(1)

    tfe_token = os.environ.get("TFE_TOKEN")
    tfe_address = os.environ.get("TFE_ADDRESS", DEFAULT_TFE_ADDRESS)
    project_id = args.project_id or os.environ.get("TFE_PROJECT_ID")

    client = None
    if tfe_token:
        client = TFEClient(token=tfe_token, address=tfe_address, org=args.org)
    elif args.command == "apply":
        logger.error("TFE_TOKEN is required for apply. Set it in your environment.")
        sys.exit(1)

    provisioner = WorkspaceProvisioner(
        repo_root=args.repo_root,
        org=org,
        client=client,
        vcs_repo=args.vcs_repo,
        vcs_oauth_token_id=args.vcs_oauth_token_id,
        project_id=project_id,
        terraform_version=args.terraform_version,
        auto_apply=args.auto_apply,
    )

    if args.command == "sync":
        changed_accounts = None  # sync all

    # Plan
    actions = provisioner.plan(changed_accounts=changed_accounts or None)

    if args.command == "plan":
        if args.format == "json":
            print(json.dumps([asdict(a) for a in actions], indent=2))
        elif args.format == "markdown":
            print(format_plan_markdown(actions))
        else:
            print(format_plan_text(actions))
        # Exit 2 if there are changes to make, 0 if no changes
        sys.exit(2 if actions and any(a.action != "skip" for a in actions) else 0)

    elif args.command in ("apply", "sync"):
        if not client:
            logger.error("TFE_TOKEN required for apply/sync")
            sys.exit(1)

        results = provisioner.apply(actions)

        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                status_icon = {"created": "✅", "updated": "🔄", "triggered": "🚀",
                               "skipped": "⏭️", "error": "❌"}.get(r["status"], "❓")
                print(f"{status_icon} {r['workspace']}: {r['status']}")
                if r.get("error"):
                    print(f"   Error: {r['error']}")

        if any(r["status"] == "error" for r in results):
            sys.exit(1)


if __name__ == "__main__":
    main()
