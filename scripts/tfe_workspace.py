#!/usr/bin/env python3
"""
TFE Workspace Provisioning via CloudIaC API

Manages TFE workspace lifecycle through the organization's CloudIaC wrapper API:
  - Authenticates via AD service account (basic auth -> bearer token)
  - Creates/lists workspaces through CloudIaC's /v1/tfe/workspaces endpoint
  - Triggers runs on merge for changed accounts

Usage:
    # Dry-run: show what would be created/triggered
    python tfe_workspace.py plan --changed-accounts 111222333444,555666777888

    # Apply: create workspaces and trigger runs
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
    CLDIAC_CREDS_AUTH     - Dynamic credentials auth (IAM role ARN, service account)

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
    action: str       # create, trigger_run, skip
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
# Workspace Provisioner
# ---------------------------------------------------------------------------

class WorkspaceProvisioner:
    """Orchestrates workspace provisioning through CloudIaC."""

    def __init__(self, repo_root: str, client: Optional[CloudIaCClient] = None,
                 car_id: str = "", project_id: str = "", repository: str = "",
                 creds_provider: str = "aws", creds_auth: str = ""):
        self.repo_root = Path(repo_root)
        self.client = client
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
            dynamic_credentials_auth=self.creds_auth,
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

            # Without a client, assume workspace needs creation
            if not self.client:
                actions.append(PlanAction(
                    action="create",
                    workspace=ws_request.suffix,
                    account_id=account_id,
                    reason="Workspace needed (dry-run — no CloudIaC connection)",
                    details={"request": ws_request.to_dict()},
                ))
                continue

            # With client, check if workspace exists
            # CloudIaC may not have a direct "get by name" — plan create regardless
            # The API should be idempotent or return conflict if exists
            actions.append(PlanAction(
                action="create",
                workspace=ws_request.suffix,
                account_id=account_id,
                reason="Ensure workspace exists for account",
                details={"request": ws_request.to_dict()},
            ))

        return actions

    def _execute_action(self, action: PlanAction) -> Dict[str, Any]:
        """Execute a single action. Thread-safe — client auth is cached."""
        result = {"action": action.action, "workspace": action.workspace,
                  "account_id": action.account_id, "status": "pending"}
        try:
            if action.action == "create":
                ws_request = self.build_workspace_request(action.account_id)
                resp = self.client.create_workspace(ws_request)
                result["status"] = "created"
                result["response"] = resp
                logger.info(f"✅ Created workspace {action.workspace}")

            elif action.action == "skip":
                result["status"] = "skipped"
                logger.info(f"⏭️  Skipped {action.workspace}: {action.reason}")

        except HTTPError as e:
            if e.code == 409:
                result["status"] = "exists"
                logger.info(f"ℹ️  Workspace {action.workspace} already exists")
            else:
                result["status"] = "error"
                result["error"] = str(e)
                logger.error(f"❌ Failed {action.action} on {action.workspace}: {e}")
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"❌ Failed {action.action} on {action.workspace}: {e}")

        return result

    def apply(self, actions: List[PlanAction], max_workers: int = 5) -> List[Dict[str, Any]]:
        """Execute planned actions against CloudIaC. Threaded for parallel provisioning.

        Auth happens once on the first API call, then the cached bearer token
        is reused across all threads. max_workers controls concurrency.
        """
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

        # Sort results by account_id for deterministic output
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
        lines.append(f"🆕 Workspaces to create: {len(creates)}")
        for a in creates:
            req = a.details.get("request", {})
            lines.append(f"   + {a.workspace} (account {a.account_id}, env: {req.get('env', '?')})")
            lines.append(f"     CAR: {req.get('car_id', 'N/A')}")
            lines.append(f"     Project: {req.get('project_id', 'N/A')}")
            lines.append(f"     Repository: {req.get('attach_repository', 'N/A')}")
            lines.append(f"     Credentials: {req.get('dynamic_credentials_provider', 'N/A')}"
                         f" → {req.get('dynamic_credentials_auth', 'N/A')}")
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
            lines.append(f"- CAR ID: `{req.get('car_id', 'N/A')}`")
            lines.append(f"- Project: `{req.get('project_id', 'N/A')}`")
            lines.append(f"- Repository: `{req.get('attach_repository', 'N/A')}`")
            lines.append(f"- Credentials: `{req.get('dynamic_credentials_provider', 'N/A')}`")
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

    # All config from env vars — CLI overrides available
    parser.add_argument("--car-id", default=None, help="Override CLDIAC_CAR_ID")
    parser.add_argument("--project-id", default=None, help="Override CLDIAC_PROJECT_ID")
    parser.add_argument("--repository", default=None, help="Override CLDIAC_REPOSITORY")
    parser.add_argument("--max-workers", type=int, default=5,
                        help="Max parallel workspace operations (default: 5)")

    args = parser.parse_args()

    # Parse changed accounts
    changed_accounts = [a.strip() for a in args.changed_accounts.split(",") if a.strip()]

    # Resolve config from env vars with CLI overrides
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

    # Validate required config for apply
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

    # Build client if credentials available
    client = None
    if cldiac_url and (username or password):
        client = CloudIaCClient(
            base_url=cldiac_url,
            auth_url=auth_url,
            auth_env=auth_env,
            username=username,
            password=password,
        )

    provisioner = WorkspaceProvisioner(
        repo_root=args.repo_root,
        client=client,
        car_id=car_id,
        project_id=project_id,
        repository=repository,
        creds_provider=creds_provider,
        creds_auth=creds_auth,
    )

    if args.command == "sync":
        changed_accounts = None

    # Plan
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
