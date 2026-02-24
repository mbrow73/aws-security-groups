"""
Tests for TFE Workspace Provisioner

Tests the provisioner logic without hitting real TFE — mocks the API client
and validates plan generation, drift detection, and action sequencing.
"""

import json
import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from dataclasses import asdict

import pytest

# Add scripts/ to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from tfe_workspace import (
    WorkspaceConfig, WorkspaceProvisioner, TFEClient, PlanAction,
    WORKSPACE_PREFIX, format_plan_text, format_plan_markdown,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def repo_root(tmp_path):
    """Create a temp repo structure with account dirs."""
    accounts = tmp_path / "accounts"
    accounts.mkdir()

    # Valid account
    acc1 = accounts / "111222333444"
    acc1.mkdir()
    (acc1 / "security-groups.yaml").write_text(
        'account_id: "111222333444"\nenvironment: "prod"\nsecurity_groups:\n  web-app:\n    description: "Web"\n'
    )

    # Another valid account
    acc2 = accounts / "555666777888"
    acc2.mkdir()
    (acc2 / "security-groups.yaml").write_text(
        'account_id: "555666777888"\nenvironment: "dev"\nsecurity_groups:\n  api-svc:\n    description: "API"\n'
    )

    # Example dir (should be ignored — not 12 digits)
    example = accounts / "_example"
    example.mkdir()
    (example / "security-groups.yaml").write_text('account_id: "123456789012"\n')

    # Dir without yaml (should be ignored)
    empty = accounts / "999999999999"
    empty.mkdir()

    # Guardrails (needed by validator, not by provisioner — but keep repo realistic)
    (tmp_path / "guardrails.yaml").write_text("validation:\n  blocked_cidrs:\n    - '0.0.0.0/0'\n")

    return tmp_path


@pytest.fixture
def mock_client():
    """Create a mock TFE client."""
    client = MagicMock(spec=TFEClient)
    client.org = "test-org"
    return client


@pytest.fixture
def provisioner(repo_root, mock_client):
    """Create a provisioner with mocked client."""
    return WorkspaceProvisioner(
        repo_root=str(repo_root),
        org="test-org",
        client=mock_client,
        vcs_repo="mbrow73/aws-security-groups",
        vcs_oauth_token_id="ot-abc123",
        terraform_version="1.6.0",
    )


# ---------------------------------------------------------------------------
# Account Discovery
# ---------------------------------------------------------------------------

class TestAccountDiscovery:
    def test_discovers_valid_accounts(self, provisioner):
        accounts = provisioner.discover_accounts()
        assert accounts == ["111222333444", "555666777888"]

    def test_ignores_non_numeric_dirs(self, provisioner):
        accounts = provisioner.discover_accounts()
        assert "_example" not in accounts

    def test_ignores_dirs_without_yaml(self, provisioner):
        accounts = provisioner.discover_accounts()
        assert "999999999999" not in accounts

    def test_empty_accounts_dir(self, tmp_path):
        (tmp_path / "accounts").mkdir()
        p = WorkspaceProvisioner(repo_root=str(tmp_path), org="test")
        assert p.discover_accounts() == []

    def test_no_accounts_dir(self, tmp_path):
        p = WorkspaceProvisioner(repo_root=str(tmp_path), org="test")
        assert p.discover_accounts() == []


# ---------------------------------------------------------------------------
# Workspace Config Generation
# ---------------------------------------------------------------------------

class TestWorkspaceConfig:
    def test_workspace_naming(self, provisioner):
        config = provisioner.build_workspace_config("111222333444")
        assert config.name == "sg-111222333444"

    def test_working_directory(self, provisioner):
        config = provisioner.build_workspace_config("111222333444")
        assert config.working_directory == "accounts/111222333444"

    def test_trigger_patterns(self, provisioner):
        config = provisioner.build_workspace_config("111222333444")
        assert "accounts/111222333444/**/*" in config.trigger_patterns
        assert "modules/**/*" in config.trigger_patterns
        assert "prefix-lists.yaml" in config.trigger_patterns
        assert "guardrails.yaml" in config.trigger_patterns

    def test_vcs_config_passthrough(self, provisioner):
        config = provisioner.build_workspace_config("111222333444")
        assert config.vcs_repo == "mbrow73/aws-security-groups"
        assert config.vcs_oauth_token_id == "ot-abc123"

    def test_tags_include_managed_tags(self, provisioner):
        config = provisioner.build_workspace_config("111222333444")
        assert "sg-platform" in config.tags
        assert "managed-by:sg-pipeline" in config.tags


# ---------------------------------------------------------------------------
# Plan: New Workspaces
# ---------------------------------------------------------------------------

class TestPlanNewWorkspaces:
    def test_plan_new_workspace_no_client(self, repo_root):
        """Without TFE client, plan assumes all workspaces need creation."""
        p = WorkspaceProvisioner(repo_root=str(repo_root), org="test", client=None)
        actions = p.plan(changed_accounts=["111222333444"])
        creates = [a for a in actions if a.action == "create"]
        triggers = [a for a in actions if a.action == "trigger_run"]
        assert len(creates) == 1
        assert creates[0].workspace == "sg-111222333444"
        assert len(triggers) == 1

    def test_plan_new_workspace_with_client(self, provisioner, mock_client):
        """With TFE client that returns 404, plan creates workspace."""
        mock_client.get_workspace.return_value = None
        actions = provisioner.plan(changed_accounts=["111222333444"])
        creates = [a for a in actions if a.action == "create"]
        assert len(creates) == 1
        assert creates[0].account_id == "111222333444"
        mock_client.get_workspace.assert_called_with("sg-111222333444")

    def test_plan_creates_trigger_for_new_workspace(self, provisioner, mock_client):
        """New workspace should also get a run trigger."""
        mock_client.get_workspace.return_value = None
        actions = provisioner.plan(changed_accounts=["111222333444"])
        triggers = [a for a in actions if a.action == "trigger_run"]
        assert len(triggers) == 1
        assert triggers[0].reason == "New workspace — initial run"


# ---------------------------------------------------------------------------
# Plan: Existing Workspaces
# ---------------------------------------------------------------------------

class TestPlanExistingWorkspaces:
    def _make_existing_workspace(self, account_id, **overrides):
        """Build a fake TFE workspace response."""
        defaults = {
            "working-directory": f"accounts/{account_id}",
            "terraform-version": "1.6.0",
            "auto-apply": False,
            "trigger-patterns": [
                f"accounts/{account_id}/**/*",
                "modules/**/*",
                "prefix-lists.yaml",
                "guardrails.yaml",
            ],
        }
        defaults.update(overrides)
        return {
            "data": {
                "id": f"ws-{account_id[:8]}",
                "attributes": defaults,
            }
        }

    def test_existing_workspace_no_drift(self, provisioner, mock_client):
        """Existing workspace in sync — only trigger run for changed account."""
        mock_client.get_workspace.return_value = self._make_existing_workspace("111222333444")
        actions = provisioner.plan(changed_accounts=["111222333444"])
        creates = [a for a in actions if a.action == "create"]
        updates = [a for a in actions if a.action == "update"]
        triggers = [a for a in actions if a.action == "trigger_run"]
        assert len(creates) == 0
        assert len(updates) == 0
        assert len(triggers) == 1
        assert triggers[0].workspace == "sg-111222333444"

    def test_existing_workspace_with_drift(self, provisioner, mock_client):
        """Existing workspace with drifted terraform version — update + trigger."""
        mock_client.get_workspace.return_value = self._make_existing_workspace(
            "111222333444", **{"terraform-version": "1.5.0"}
        )
        actions = provisioner.plan(changed_accounts=["111222333444"])
        updates = [a for a in actions if a.action == "update"]
        triggers = [a for a in actions if a.action == "trigger_run"]
        assert len(updates) == 1
        assert "terraform-version" in updates[0].details["drift"]
        assert len(triggers) == 1

    def test_existing_workspace_trigger_pattern_drift(self, provisioner, mock_client):
        """Drifted trigger patterns get caught."""
        mock_client.get_workspace.return_value = self._make_existing_workspace(
            "111222333444", **{"trigger-patterns": ["old/pattern"]}
        )
        actions = provisioner.plan(changed_accounts=["111222333444"])
        updates = [a for a in actions if a.action == "update"]
        assert len(updates) == 1
        assert "trigger-patterns" in updates[0].details["drift"]

    def test_no_trigger_when_account_not_changed(self, provisioner, mock_client):
        """Existing workspace with no changes — no trigger (sync mode)."""
        mock_client.get_workspace.return_value = self._make_existing_workspace("111222333444")
        # Plan all accounts without specifying changed
        actions = provisioner.plan(changed_accounts=None)
        triggers = [a for a in actions if a.action == "trigger_run"]
        assert len(triggers) == 0


# ---------------------------------------------------------------------------
# Plan: Edge Cases
# ---------------------------------------------------------------------------

class TestPlanEdgeCases:
    def test_skip_nonexistent_account(self, provisioner, mock_client):
        """Changed account that doesn't have a directory is skipped."""
        actions = provisioner.plan(changed_accounts=["000000000000"])
        skips = [a for a in actions if a.action == "skip"]
        assert len(skips) == 1
        assert "not found" in skips[0].reason

    def test_multiple_accounts(self, provisioner, mock_client):
        """Multiple changed accounts generate independent actions."""
        mock_client.get_workspace.return_value = None
        actions = provisioner.plan(changed_accounts=["111222333444", "555666777888"])
        creates = [a for a in actions if a.action == "create"]
        assert len(creates) == 2
        workspaces = {a.workspace for a in creates}
        assert workspaces == {"sg-111222333444", "sg-555666777888"}

    def test_sync_all_accounts(self, provisioner, mock_client):
        """Sync mode plans all discovered accounts."""
        mock_client.get_workspace.return_value = None
        actions = provisioner.plan(changed_accounts=None)
        creates = [a for a in actions if a.action == "create"]
        assert len(creates) == 2  # both valid accounts


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

class TestApply:
    def test_apply_create(self, provisioner, mock_client):
        """Apply creates workspace and sets yaml_file variable."""
        mock_client.create_workspace.return_value = {
            "data": {"id": "ws-new123", "attributes": {}}
        }
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new",
            details={"config": {}},
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "created"
        mock_client.create_workspace.assert_called_once()
        mock_client.set_variable.assert_called_once_with(
            "ws-new123", "yaml_file",
            "accounts/111222333444/security-groups.yaml",
            category="terraform"
        )

    def test_apply_trigger_run(self, provisioner, mock_client):
        """Apply triggers a run on existing workspace."""
        mock_client.create_run.return_value = {
            "data": {"id": "run-abc123", "attributes": {}}
        }
        actions = [PlanAction(
            action="trigger_run", workspace="sg-111222333444",
            account_id="111222333444", reason="changed",
            details={"workspace_id": "ws-existing"},
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "triggered"
        assert results[0]["run_id"] == "run-abc123"

    def test_apply_create_then_trigger(self, provisioner, mock_client):
        """Create + trigger in sequence — trigger uses the newly created workspace ID."""
        mock_client.create_workspace.return_value = {
            "data": {"id": "ws-brand-new", "attributes": {}}
        }
        mock_client.create_run.return_value = {
            "data": {"id": "run-xyz789", "attributes": {}}
        }
        actions = [
            PlanAction(action="create", workspace="sg-111222333444",
                       account_id="111222333444", reason="new",
                       details={"config": {}}),
            PlanAction(action="trigger_run", workspace="sg-111222333444",
                       account_id="111222333444", reason="initial run",
                       details={}),  # no workspace_id — should use cached ID from create
        ]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "created"
        assert results[1]["status"] == "triggered"
        # Verify the run was triggered on the newly created workspace
        mock_client.create_run.assert_called_once()
        call_args = mock_client.create_run.call_args
        assert call_args[0][0] == "ws-brand-new"

    def test_apply_error_handling(self, provisioner, mock_client):
        """Apply continues on error and reports failures."""
        mock_client.create_workspace.side_effect = Exception("API timeout")
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new",
            details={"config": {}},
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "error"
        assert "API timeout" in results[0]["error"]

    def test_apply_without_client_raises(self, repo_root):
        """Apply without TFE client raises RuntimeError."""
        p = WorkspaceProvisioner(repo_root=str(repo_root), org="test", client=None)
        with pytest.raises(RuntimeError, match="Cannot apply without"):
            p.apply([])


# ---------------------------------------------------------------------------
# Output Formatting
# ---------------------------------------------------------------------------

class TestFormatting:
    def test_text_no_actions(self):
        assert "No actions needed" in format_plan_text([])

    def test_text_with_create(self):
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="New",
            details={"config": {"working_directory": "accounts/111222333444"}},
        )]
        output = format_plan_text(actions)
        assert "Workspaces to create: 1" in output
        assert "sg-111222333444" in output

    def test_markdown_no_actions(self):
        output = format_plan_markdown([])
        assert "No changes needed" in output

    def test_markdown_with_create(self):
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="New",
            details={"config": {
                "working_directory": "accounts/111222333444",
                "terraform_version": "1.6.0",
                "auto_apply": False,
                "trigger_patterns": ["accounts/111222333444/**/*"],
            }},
        )]
        output = format_plan_markdown(actions)
        assert "Create 1 workspace" in output
        assert "sg-111222333444" in output

    def test_json_serializable(self):
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="New",
            details={"config": {}},
        )]
        # Should not raise
        json.dumps([asdict(a) for a in actions])
