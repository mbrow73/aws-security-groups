#!/usr/bin/env python3
"""
TFE Workspace Provisioning via CloudIaC API

Creates TFE workspaces through the organization's CloudIaC wrapper API.
CloudIaC handles dynamic credential provisioning — each workspace gets
credentials scoped to its target AWS account via the role ARN.

No variable sets needed — account_id is derived from the workspace name
(sg-<account_id>) in the root Terraform config.

Usage:
    # Dry-run: show what would be created
    python tfe_workspace.py plan --changed-accounts 111222333444,555666777888

    # Apply: create workspaces
    python tfe_workspace.py apply --changed-accounts 111222333444

    # Sync: ensure all account dirs have workspaces
    python tfe_workspace.py sync

Environment:
    CLDIAC_URL            - CloudIaC API base URL (e.g. https://cldiac.example.com)
    CLDIAC_AUTH_URL       - Auth service URL (e.g. https://authservice.example.com)
    CLDIAC_AUTH_ENV       - Auth environment header (e.g. E1)
    CLDIAC_USER           - AD service account ID
    CLDIAC_PASSWORD       - AD service account key
    CLDIAC_CAR_ID         - Cloud account reference ID
    CLDIAC_PROJECT_ID     - TFE project ID (prj-xxx)
    CLDIAC_REPOSITORY     - Repository to attach (e.g. org-eng/aws-security-groups)
    CLDIAC_CREDS_PROVIDER - Dynamic credentials provider (aws, gcp)
    CLDIAC_CREDS_AUTH     - Dynamic credentials auth role name (e.g. TfcSgPlatformRole).
                            Combined with account ID to form full ARN per workspace:
                            arn:aws:iam::<account_id>:role/<CLDIAC_CREDS_AUTH>
    TFE_ADDRESS           - TFE instance URL (e.g. https://app.terraform.io)
    TFE_TOKEN             - TFE team/user token for triggering runs
    TFE_ORG               - TFE organization name

Exit codes:
    0 - Success / no changes
    1 - Error
    2 - Dry-run plan has changes
"""

import argparse
import base64
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config & Constants
# ---------------------------------------------------------------------------

WORKSPACE_SUFFIX_PREFIX = "sg-"


@dataclass
class WorkspaceRequest:
    """Payload for CloudIaC workspace creation."""
    car_id: str
    env: str
    suffix: str
    project_id: str
    attach_repository: str
    dynamic_credentials_provider: str = "aws"
    dynamic_credentials_auth: str = ""

    def to_dict(self) -> dict:
        return {
            "car_id": self.car_id,
            "env": self.env,
            "suffix": self.suffix,
            "project_id": self.project_id,
            "attach_repository": self.attach_repository,
            "dynamic_credentials_provider": self.dynamic_credentials_provider,
            "dynamic_credentials_auth": self.dynamic_credentials_auth,
        }


@dataclass
class PlanAction:
    """A planned action to take."""
    action: str       # create, skip
    workspace: str
    account_id: str
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# CloudIaC API Client
# ---------------------------------------------------------------------------

class CloudIaCClient:
    """Client for the organization's CloudIaC TFE wrapper API."""

    def __init__(self, base_url: str, auth_url: str, auth_env: str = "E1",
                 username: str = "", password: str = "", token: str = ""):
        self.base_url = base_url.rstrip("/")
        self.auth_url = auth_url.rstrip("/")
        self.auth_env = auth_env
        self._username = username
        self._password = password
        self._token = token

    def authenticate(self) -> str:
        """Authenticate via AD basic auth and return bearer token."""
        if self._token:
            return self._token

        if not self._username or not self._password:
            raise RuntimeError("CLDIAC_USER and CLDIAC_PASSWORD required for authentication")

        creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        headers = {
            "Authorization": f"Basic {creds}",
            "Environment": self.auth_env,
            "Content-Type": "application/json",
        }

        req = Request(
            f"{self.auth_url}/api/v1/login",
            headers=headers,
            method="POST",
        )

        try:
            with urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                self._token = data.get("id_token", "")
                if not self._token:
                    raise RuntimeError("Auth response missing id_token")
                return self._token
        except HTTPError as e:
            error_body = e.read().decode() if e.fp else ""
            raise RuntimeError(f"Authentication failed ({e.code}): {error_body}")

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        """Make an authenticated CloudIaC API request."""
        token = self.authenticate()
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {token}",
            "accept": "application/json",
            "Content-Type": "application/json",
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
            logger.error(f"CloudIaC API {method} {path} -> {e.code}: {error_body}")
            raise

    def create_workspace(self, request: WorkspaceRequest) -> dict:
        """Create a TFE workspace via CloudIaC API."""
        return self._request("POST", "/v1/tfe/workspaces", request.to_dict())

    def list_workspaces(self, project_id: Optional[str] = None) -> list:
        """List workspaces. Optionally filter by project."""
        path = "/v1/tfe/workspaces"
        if project_id:
            path += f"?project_id={project_id}"
        return self._request("GET", path)


# ---------------------------------------------------------------------------
# Native TFE API Client
# ---------------------------------------------------------------------------

class TFEClient:
    """Client for the native Terraform Enterprise JSON:API."""

    def __init__(self, address: str, token: str, org: str):
        self.address = address.rstrip("/")
        self.token = token
        self.org = org

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        """Make an authenticated TFE API request."""
        url = f"{self.address}/api/v2{path}"
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
            logger.error(f"TFE API {method} {path} -> {e.code}: {error_body}")
            raise

    def get_workspace_id(self, workspace_name: str) -> Optional[str]:
        """Look up a workspace ID by name. Returns None if not found."""
        try:
            resp = self._request("GET", f"/organizations/{self.org}/workspaces/{workspace_name}")
            return resp.get("data", {}).get("id")
        except HTTPError as e:
            if e.code == 404:
                return None
            raise

    def trigger_run(self, workspace_id: str, message: str = "Triggered by SG provisioner") -> dict:
        """Trigger a new run on a workspace."""
        body = {
            "data": {
                "attributes": {
                    "message": message,
                },
                "type": "runs",
                "relationships": {
                    "workspace": {
                        "data": {
                            "type": "workspaces",
                            "id": workspace_id,
                        }
                    }
                }
            }
        }
        return self._request("POST", "/runs", body)


# ---------------------------------------------------------------------------
# Workspace Provisioner
# ---------------------------------------------------------------------------

class WorkspaceProvisioner:
    """Orchestrates workspace provisioning through CloudIaC."""

    def __init__(self, repo_root: str, client: Optional[CloudIaCClient] = None,
                 tfe_client: Optional['TFEClient'] = None,
                 car_id: str = "", project_id: str = "", repository: str = "",
                 creds_provider: str = "aws", creds_auth: str = ""):
        self.repo_root = Path(repo_root)
        self.client = client
        self.tfe_client = tfe_client
        self.car_id = car_id
        self.project_id = project_id
        self.repository = repository
        self.creds_provider = creds_provider
        self.creds_auth = creds_auth

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

    def _read_account_env(self, account_id: str) -> str:
        """Read the environment from an account's YAML."""
        import yaml
        yaml_path = self.repo_root / "accounts" / account_id / "security-groups.yaml"
        try:
            with open(yaml_path) as f:
                data = yaml.safe_load(f)
                return data.get("environment", "dev")
        except Exception:
            return "dev"

    def _build_creds_auth(self, account_id: str) -> str:
        """Build the dynamic credentials auth ARN for a target account.

        If creds_auth is already a full ARN, returns it as-is.
        Otherwise treats it as a role name and builds:
            arn:aws:iam::<account_id>:role/<creds_auth>
        """
        if not self.creds_auth:
            return ""
        if self.creds_auth.startswith("arn:"):
            return self.creds_auth
        return f"arn:aws:iam::{account_id}:role/{self.creds_auth}"

    def build_workspace_request(self, account_id: str) -> WorkspaceRequest:
        """Build a CloudIaC workspace creation request for an account."""
        env = self._read_account_env(account_id)
        return WorkspaceRequest(
            car_id=self.car_id,
            env=env,
            suffix=f"{WORKSPACE_SUFFIX_PREFIX}{account_id}",
            project_id=self.project_id,
            attach_repository=self.repository,
            dynamic_credentials_provider=self.creds_provider,
            dynamic_credentials_auth=self._build_creds_auth(account_id),
        )

    def plan(self, changed_accounts: Optional[List[str]] = None) -> List[PlanAction]:
        """Generate a plan of actions without executing anything."""
        actions = []
        all_accounts = self.discover_accounts()
        target_accounts = changed_accounts if changed_accounts else all_accounts

        for account_id in target_accounts:
            if account_id not in all_accounts:
                actions.append(PlanAction(
                    action="skip",
                    workspace=f"{WORKSPACE_SUFFIX_PREFIX}{account_id}",
                    account_id=account_id,
                    reason=f"Account directory accounts/{account_id}/security-groups.yaml not found",
                ))
                continue

            ws_request = self.build_workspace_request(account_id)
            actions.append(PlanAction(
                action="create",
                workspace=ws_request.suffix,
                account_id=account_id,
                reason="Ensure workspace exists for account",
                details={"request": ws_request.to_dict()},
            ))

        return actions

    def _execute_action(self, action: PlanAction) -> Dict[str, Any]:
        """Execute a single action. Thread-safe — client auth is cached.

        For new workspaces, triggers an initial TFE run via native API
        since the VCS commit that triggered provisioning already happened
        before the workspace existed.
        """
        result = {"action": action.action, "workspace": action.workspace,
                  "account_id": action.account_id, "status": "pending"}

        try:
            if action.action == "create":
                ws_request = self.build_workspace_request(action.account_id)
                try:
                    self.client.create_workspace(ws_request)
                    result["status"] = "created"
                    logger.info(f"✅ Created workspace {action.workspace}")
                except HTTPError as e:
                    if e.code == 409:
                        result["status"] = "exists"
                        logger.info(f"ℹ️  Workspace {action.workspace} already exists")
                    else:
                        raise

                # Always trigger a run — GitHub Actions is the trigger, not VCS
                if self.tfe_client:
                    try:
                        ws_id = self.tfe_client.get_workspace_id(action.workspace)
                        if ws_id:
                            self.tfe_client.trigger_run(
                                ws_id,
                                message=f"Triggered by SG provisioner for account {action.account_id}",
                            )
                            result["run_triggered"] = True
                            logger.info(f"🚀 Triggered initial run on {action.workspace}")
                        else:
                            result["run_triggered"] = False
                            result["run_warning"] = "Workspace created but not found in TFE — run not triggered"
                            logger.warning(f"⚠️  Workspace {action.workspace} not found in TFE after creation")
                    except Exception as e:
                        result["run_triggered"] = False
                        result["run_error"] = str(e)
                        logger.warning(f"⚠️  Failed to trigger run on {action.workspace}: {e}")

            elif action.action == "skip":
                result["status"] = "skipped"
                logger.info(f"⏭️  Skipped {action.workspace}: {action.reason}")

        except HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode() if e.fp else ""
            except Exception:
                pass
            result["status"] = "error"
            result["error"] = f"HTTP {e.code}: {error_body}" if error_body else str(e)
            logger.error(f"❌ Failed {action.action} on {action.workspace}: {e}")
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"❌ Failed {action.action} on {action.workspace}: {e}")

        return result

    def apply(self, actions: List[PlanAction], max_workers: int = 5) -> List[Dict[str, Any]]:
        """Execute planned actions against CloudIaC. Threaded for parallel provisioning."""
        if not self.client:
            raise RuntimeError("Cannot apply without a CloudIaC client")

        if not actions:
            return []

        # Pre-authenticate so all threads share the cached token
        self.client.authenticate()

        # Split skips (instant) from API calls (threadable)
        skips = [a for a in actions if a.action == "skip"]
        api_actions = [a for a in actions if a.action != "skip"]

        results = [self._execute_action(a) for a in skips]

        if api_actions:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(api_actions))) as pool:
                futures = {pool.submit(self._execute_action, a): a for a in api_actions}
                for future in as_completed(futures):
                    results.append(future.result())

        results.sort(key=lambda r: r.get("account_id", ""))
        return results


# ---------------------------------------------------------------------------
# Output Formatting
# ---------------------------------------------------------------------------

def format_plan_text(actions: List[PlanAction]) -> str:
    """Format plan actions as human-readable text."""
    if not actions:
        return "✅ No actions needed — all workspaces are in sync."

    lines = ["📋 CloudIaC Workspace Provisioning Plan", "=" * 50, ""]

    creates = [a for a in actions if a.action == "create"]
    skips = [a for a in actions if a.action == "skip"]

    if creates:
        lines.append(f"🆕 Workspaces to provision: {len(creates)}")
        for a in creates:
            req = a.details.get("request", {})
            lines.append(f"   + {a.workspace} (account {a.account_id}, env: {req.get('env', '?')})")
            lines.append(f"     Dynamic creds: {req.get('dynamic_credentials_auth', 'N/A')}")
            lines.append(f"     → Initial TFE run will be triggered after creation")
        lines.append("")

    if skips:
        lines.append(f"⏭️  Skipped: {len(skips)}")
        for a in skips:
            lines.append(f"   - {a.workspace}: {a.reason}")
        lines.append("")

    lines.append(f"Total: {len(creates)} create, {len(skips)} skip")
    return "\n".join(lines)


def format_plan_markdown(actions: List[PlanAction]) -> str:
    """Format plan actions as markdown."""
    if not actions:
        return "## ✅ CloudIaC Workspace Status\n\nAll workspaces in sync."

    lines = ["## 📋 CloudIaC Workspace Provisioning Plan", ""]

    creates = [a for a in actions if a.action == "create"]
    skips = [a for a in actions if a.action == "skip"]

    parts = []
    if creates:
        parts.append(f"**{len(creates)}** to create")
    if skips:
        parts.append(f"**{len(skips)}** skipped")
    lines.append(" | ".join(parts))
    lines.append("")

    if creates:
        lines.append("<details>")
        lines.append(f"<summary>🆕 Create {len(creates)} workspace(s)</summary>")
        lines.append("")
        for a in creates:
            req = a.details.get("request", {})
            lines.append(f"**`{a.workspace}`** — account `{a.account_id}`")
            lines.append(f"- Environment: `{req.get('env', '?')}`")
            lines.append(f"- Dynamic creds: `{req.get('dynamic_credentials_auth', 'N/A')}`")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="TFE Workspace Provisioner via CloudIaC API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", choices=["plan", "apply", "sync"],
                        help="plan: dry-run | apply: execute | sync: reconcile all")
    parser.add_argument("--changed-accounts", default="",
                        help="Comma-separated list of changed account IDs")
    parser.add_argument("--repo-root", default=".",
                        help="Repository root directory (default: cwd)")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")

    parser.add_argument("--car-id", default=None, help="Override CLDIAC_CAR_ID")
    parser.add_argument("--project-id", default=None, help="Override CLDIAC_PROJECT_ID")
    parser.add_argument("--repository", default=None, help="Override CLDIAC_REPOSITORY")
    parser.add_argument("--max-workers", type=int, default=5,
                        help="Max parallel workspace operations (default: 5)")

    args = parser.parse_args()

    changed_accounts = [a.strip() for a in args.changed_accounts.split(",") if a.strip()]

    cldiac_url = os.environ.get("CLDIAC_URL", "")
    auth_url = os.environ.get("CLDIAC_AUTH_URL", "")
    auth_env = os.environ.get("CLDIAC_AUTH_ENV", "E1")
    username = os.environ.get("CLDIAC_USER", "")
    password = os.environ.get("CLDIAC_PASSWORD", "")

    car_id = args.car_id or os.environ.get("CLDIAC_CAR_ID", "")
    project_id = args.project_id or os.environ.get("CLDIAC_PROJECT_ID", "")
    repository = args.repository or os.environ.get("CLDIAC_REPOSITORY", "")
    creds_provider = os.environ.get("CLDIAC_CREDS_PROVIDER", "aws")
    creds_auth = os.environ.get("CLDIAC_CREDS_AUTH", "")

    tfe_address = os.environ.get("TFE_ADDRESS", "")
    tfe_token = os.environ.get("TFE_TOKEN", "")
    tfe_org = os.environ.get("TFE_ORG", "")

    if args.command in ("apply", "sync"):
        missing = []
        if not cldiac_url:
            missing.append("CLDIAC_URL")
        if not auth_url:
            missing.append("CLDIAC_AUTH_URL")
        if not username:
            missing.append("CLDIAC_USER")
        if not password:
            missing.append("CLDIAC_PASSWORD")
        if not car_id:
            missing.append("CLDIAC_CAR_ID")
        if not project_id:
            missing.append("CLDIAC_PROJECT_ID")
        if not repository:
            missing.append("CLDIAC_REPOSITORY")
        if missing:
            logger.error(f"Missing required config: {', '.join(missing)}")
            sys.exit(1)

    client = None
    if cldiac_url and (username or password):
        client = CloudIaCClient(
            base_url=cldiac_url,
            auth_url=auth_url,
            auth_env=auth_env,
            username=username,
            password=password,
        )

    tfe_client = None
    if tfe_address and tfe_token and tfe_org:
        tfe_client = TFEClient(
            address=tfe_address,
            token=tfe_token,
            org=tfe_org,
        )
    elif args.command in ("apply", "sync") and not tfe_address:
        logger.warning("TFE_ADDRESS/TFE_TOKEN/TFE_ORG not set — initial runs will not be triggered")

    provisioner = WorkspaceProvisioner(
        repo_root=args.repo_root,
        client=client,
        tfe_client=tfe_client,
        car_id=car_id,
        project_id=project_id,
        repository=repository,
        creds_provider=creds_provider,
        creds_auth=creds_auth,
    )

    if args.command == "sync":
        changed_accounts = None

    actions = provisioner.plan(changed_accounts=changed_accounts or None)

    if args.command == "plan":
        if args.format == "json":
            print(json.dumps([asdict(a) for a in actions], indent=2))
        elif args.format == "markdown":
            print(format_plan_markdown(actions))
        else:
            print(format_plan_text(actions))
        sys.exit(2 if actions and any(a.action != "skip" for a in actions) else 0)

    elif args.command in ("apply", "sync"):
        results = provisioner.apply(actions, max_workers=args.max_workers)

        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                icon = {"created": "✅", "exists": "ℹ️", "skipped": "⏭️",
                        "error": "❌"}.get(r["status"], "❓")
                print(f"{icon} {r['workspace']}: {r['status']}")
                if r.get("error"):
                    print(f"   Error: {r['error']}")

        if any(r["status"] == "error" for r in results):
            sys.exit(1)


if __name__ == "__main__":
    main()
