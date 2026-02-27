"""
Tests for TFE Workspace Provisioner (CloudIaC API)

Tests provisioner logic without hitting real CloudIaC — mocks the API client
and validates plan generation, auth flow, and action sequencing.
"""

import json
import os
import sys
import base64
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from dataclasses import asdict
from urllib.error import HTTPError
from io import BytesIO

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from tfe_workspace import (
    WorkspaceRequest, VariableSetRequest, VariableSetKeyRequest,
    VariableSetAttachRequest, WorkspaceProvisioner, CloudIaCClient, PlanAction,
    WORKSPACE_SUFFIX_PREFIX, format_plan_text, format_plan_markdown,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def repo_root(tmp_path):
    """Create a temp repo structure with account dirs."""
    accounts = tmp_path / "accounts"
    accounts.mkdir()

    acc1 = accounts / "111222333444"
    acc1.mkdir()
    (acc1 / "security-groups.yaml").write_text(
        'account_id: "111222333444"\nenvironment: "prod"\nsecurity_groups:\n  web-app:\n    description: "Web"\n'
    )

    acc2 = accounts / "555666777888"
    acc2.mkdir()
    (acc2 / "security-groups.yaml").write_text(
        'account_id: "555666777888"\nenvironment: "dev"\nsecurity_groups:\n  api-svc:\n    description: "API"\n'
    )

    # Should be ignored
    example = accounts / "_example"
    example.mkdir()
    (example / "security-groups.yaml").write_text('account_id: "123456789012"\n')

    empty = accounts / "999999999999"
    empty.mkdir()

    (tmp_path / "guardrails.yaml").write_text("validation:\n  blocked_cidrs:\n    - '0.0.0.0/0'\n")
    return tmp_path


@pytest.fixture
def mock_client():
    client = MagicMock(spec=CloudIaCClient)
    return client


@pytest.fixture
def provisioner(repo_root, mock_client):
    return WorkspaceProvisioner(
        repo_root=str(repo_root),
        client=mock_client,
        car_id="car-test-123",
        project_id="prj-test-456",
        repository="org-eng/aws-security-groups",
        creds_provider="aws",
        creds_auth="arn:aws:iam::123456789012:role/tfe-sg-platform",
        sid="sgplat01",
    )


# ---------------------------------------------------------------------------
# Account Discovery
# ---------------------------------------------------------------------------

class TestAccountDiscovery:
    def test_discovers_valid_accounts(self, provisioner):
        assert provisioner.discover_accounts() == ["111222333444", "555666777888"]

    def test_ignores_non_numeric_dirs(self, provisioner):
        assert "_example" not in provisioner.discover_accounts()

    def test_ignores_dirs_without_yaml(self, provisioner):
        assert "999999999999" not in provisioner.discover_accounts()

    def test_empty_accounts_dir(self, tmp_path):
        (tmp_path / "accounts").mkdir()
        p = WorkspaceProvisioner(repo_root=str(tmp_path))
        assert p.discover_accounts() == []

    def test_no_accounts_dir(self, tmp_path):
        p = WorkspaceProvisioner(repo_root=str(tmp_path))
        assert p.discover_accounts() == []


# ---------------------------------------------------------------------------
# Workspace Request Generation
# ---------------------------------------------------------------------------

class TestWorkspaceRequest:
    def test_suffix_naming(self, provisioner):
        req = provisioner.build_workspace_request("111222333444")
        assert req.suffix == "sg-111222333444"

    def test_env_from_yaml(self, provisioner):
        req = provisioner.build_workspace_request("111222333444")
        assert req.env == "prod"

    def test_dev_env_from_yaml(self, provisioner):
        req = provisioner.build_workspace_request("555666777888")
        assert req.env == "dev"

    def test_car_id_passthrough(self, provisioner):
        req = provisioner.build_workspace_request("111222333444")
        assert req.car_id == "car-test-123"

    def test_project_id_passthrough(self, provisioner):
        req = provisioner.build_workspace_request("111222333444")
        assert req.project_id == "prj-test-456"

    def test_repository_passthrough(self, provisioner):
        req = provisioner.build_workspace_request("111222333444")
        assert req.attach_repository == "org-eng/aws-security-groups"

    def test_creds_provider(self, provisioner):
        req = provisioner.build_workspace_request("111222333444")
        assert req.dynamic_credentials_provider == "aws"

    def test_creds_auth(self, provisioner):
        req = provisioner.build_workspace_request("111222333444")
        assert req.dynamic_credentials_auth == "arn:aws:iam::123456789012:role/tfe-sg-platform"

    def test_to_dict(self, provisioner):
        req = provisioner.build_workspace_request("111222333444")
        d = req.to_dict()
        assert d["car_id"] == "car-test-123"
        assert d["env"] == "prod"
        assert d["suffix"] == "sg-111222333444"
        assert d["project_id"] == "prj-test-456"
        assert d["attach_repository"] == "org-eng/aws-security-groups"
        assert d["dynamic_credentials_provider"] == "aws"

    def test_default_env_when_yaml_missing_env(self, tmp_path):
        accounts = tmp_path / "accounts"
        accounts.mkdir()
        acc = accounts / "111111111111"
        acc.mkdir()
        (acc / "security-groups.yaml").write_text('account_id: "111111111111"\nsecurity_groups: {}\n')
        p = WorkspaceProvisioner(repo_root=str(tmp_path), car_id="x", project_id="y", repository="z")
        req = p.build_workspace_request("111111111111")
        assert req.env == "dev"


# ---------------------------------------------------------------------------
# Dynamic Credentials Auth
# ---------------------------------------------------------------------------

class TestDynamicCredsAuth:
    def test_role_name_builds_arn(self, repo_root):
        """Role name (no arn: prefix) gets templated into full ARN with account ID."""
        p = WorkspaceProvisioner(
            repo_root=str(repo_root), car_id="x", project_id="y",
            repository="z", creds_auth="TfcSgPlatformRole",
        )
        req = p.build_workspace_request("111222333444")
        assert req.dynamic_credentials_auth == "arn:aws:iam::111222333444:role/TfcSgPlatformRole"

    def test_role_name_different_accounts(self, repo_root):
        """Each account gets its own ARN from the same role name."""
        p = WorkspaceProvisioner(
            repo_root=str(repo_root), car_id="x", project_id="y",
            repository="z", creds_auth="TfcSgPlatformRole",
        )
        req1 = p.build_workspace_request("111222333444")
        req2 = p.build_workspace_request("555666777888")
        assert "111222333444" in req1.dynamic_credentials_auth
        assert "555666777888" in req2.dynamic_credentials_auth
        assert req1.dynamic_credentials_auth != req2.dynamic_credentials_auth

    def test_full_arn_passthrough(self, repo_root):
        """Full ARN passed as-is (backward compat / override)."""
        p = WorkspaceProvisioner(
            repo_root=str(repo_root), car_id="x", project_id="y",
            repository="z", creds_auth="arn:aws:iam::999999999999:role/CustomRole",
        )
        req = p.build_workspace_request("111222333444")
        assert req.dynamic_credentials_auth == "arn:aws:iam::999999999999:role/CustomRole"

    def test_empty_creds_auth(self, repo_root):
        """Empty creds_auth returns empty string."""
        p = WorkspaceProvisioner(
            repo_root=str(repo_root), car_id="x", project_id="y",
            repository="z", creds_auth="",
        )
        req = p.build_workspace_request("111222333444")
        assert req.dynamic_credentials_auth == ""


# ---------------------------------------------------------------------------
# Plan: New Workspaces
# ---------------------------------------------------------------------------

class TestPlanNewWorkspaces:
    def test_plan_without_client(self, repo_root):
        p = WorkspaceProvisioner(repo_root=str(repo_root), client=None,
                                 car_id="car-1", project_id="prj-1", repository="org/repo")
        actions = p.plan(changed_accounts=["111222333444"])
        creates = [a for a in actions if a.action == "create"]
        assert len(creates) == 1
        assert creates[0].workspace == "sg-111222333444"
        assert "dry-run" in creates[0].reason.lower()

    def test_plan_with_client(self, provisioner, mock_client):
        actions = provisioner.plan(changed_accounts=["111222333444"])
        creates = [a for a in actions if a.action == "create"]
        assert len(creates) == 1
        assert creates[0].account_id == "111222333444"

    def test_plan_includes_request_details(self, provisioner, mock_client):
        actions = provisioner.plan(changed_accounts=["111222333444"])
        req = actions[0].details.get("request", {})
        assert req["car_id"] == "car-test-123"
        assert req["env"] == "prod"
        assert req["suffix"] == "sg-111222333444"


# ---------------------------------------------------------------------------
# Plan: Edge Cases
# ---------------------------------------------------------------------------

class TestPlanEdgeCases:
    def test_skip_nonexistent_account(self, provisioner):
        actions = provisioner.plan(changed_accounts=["000000000000"])
        skips = [a for a in actions if a.action == "skip"]
        assert len(skips) == 1
        assert "not found" in skips[0].reason

    def test_multiple_accounts(self, provisioner, mock_client):
        actions = provisioner.plan(changed_accounts=["111222333444", "555666777888"])
        creates = [a for a in actions if a.action == "create"]
        assert len(creates) == 2
        workspaces = {a.workspace for a in creates}
        assert workspaces == {"sg-111222333444", "sg-555666777888"}

    def test_sync_all_accounts(self, provisioner, mock_client):
        actions = provisioner.plan(changed_accounts=None)
        creates = [a for a in actions if a.action == "create"]
        assert len(creates) == 2


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

class TestApply:
    def test_apply_full_provisioning_flow(self, provisioner, mock_client):
        """Full 4-step flow: workspace → varset → key → attach."""
        mock_client.create_workspace.return_value = {"id": "ws-new123"}
        mock_client.create_variable_set.return_value = {"id": "vs-abc123"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}

        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new",
            details={"request": {}},
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "created"
        assert len(results[0]["steps"]) == 4

        mock_client.create_workspace.assert_called_once()
        mock_client.create_variable_set.assert_called_once()
        mock_client.create_variable_set_key.assert_called_once_with(
            "vs-abc123", mock_client.create_variable_set_key.call_args[0][1]
        )
        mock_client.attach_variable_set.assert_called_once()

    def test_apply_varset_key_has_correct_values(self, provisioner, mock_client):
        """Variable set key should be account_id, not sensitive, terraform var (not env)."""
        mock_client.create_workspace.return_value = {"id": "ws-new"}
        mock_client.create_variable_set.return_value = {"id": "vs-123"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}

        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new", details={},
        )]
        provisioner.apply(actions)

        key_request = mock_client.create_variable_set_key.call_args[0][1]
        assert key_request.key == "account_id"
        assert key_request.value == "111222333444"
        assert key_request.sensitive is False
        assert key_request.env is False

    def test_apply_workspace_exists_continues(self, provisioner, mock_client):
        """409 on workspace create should continue with varset flow."""
        ws_error = HTTPError(
            url="http://test", code=409, msg="Conflict",
            hdrs={}, fp=BytesIO(b"already exists")
        )
        mock_client.create_workspace.side_effect = ws_error
        mock_client.create_variable_set.return_value = {"id": "vs-abc123"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}

        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new", details={},
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "created"
        assert results[0]["steps"][0]["status"] == "exists"
        mock_client.create_variable_set.assert_called_once()

    def test_apply_varset_exists_returns_partial(self, provisioner, mock_client):
        """409 on varset create returns partial since we can't get the ID."""
        mock_client.create_workspace.return_value = {"id": "ws-new"}
        varset_error = HTTPError(
            url="http://test", code=409, msg="Conflict",
            hdrs={}, fp=BytesIO(b"already exists")
        )
        mock_client.create_variable_set.side_effect = varset_error

        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new", details={},
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "partial"
        mock_client.create_variable_set_key.assert_not_called()
        mock_client.attach_variable_set.assert_not_called()

    def test_apply_error_handling(self, provisioner, mock_client):
        mock_client.create_workspace.side_effect = Exception("API timeout")
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new", details={},
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "error"
        assert "API timeout" in results[0]["error"]

    def test_apply_http_error(self, provisioner, mock_client):
        error = HTTPError(
            url="http://test", code=500, msg="Server Error",
            hdrs={}, fp=BytesIO(b"internal error")
        )
        mock_client.create_workspace.side_effect = error
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new", details={},
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "error"

    def test_apply_without_client_raises(self, repo_root):
        p = WorkspaceProvisioner(repo_root=str(repo_root), client=None)
        with pytest.raises(RuntimeError, match="Cannot apply without"):
            p.apply([])

    def test_apply_skip(self, provisioner, mock_client):
        actions = [PlanAction(
            action="skip", workspace="sg-000000000000",
            account_id="000000000000", reason="not found",
        )]
        results = provisioner.apply(actions)
        assert results[0]["status"] == "skipped"

    def test_apply_varset_uses_correct_sid(self, provisioner, mock_client):
        """Variable set request should use the static SID."""
        mock_client.create_workspace.return_value = {"id": "ws-new"}
        mock_client.create_variable_set.return_value = {"id": "vs-123"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}

        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new", details={},
        )]
        provisioner.apply(actions)

        varset_request = mock_client.create_variable_set.call_args[0][0]
        assert varset_request.sid == "sgplat01"

    def test_apply_attach_uses_workspace_name(self, provisioner, mock_client):
        """Attach request should use the workspace name (sg-<account_id>)."""
        mock_client.create_workspace.return_value = {"id": "ws-new"}
        mock_client.create_variable_set.return_value = {"id": "vs-123"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}

        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="new", details={},
        )]
        provisioner.apply(actions)

        attach_request = mock_client.attach_variable_set.call_args[0][1]
        assert attach_request.workspace_name == "sg-111222333444"


# ---------------------------------------------------------------------------
# CloudIaC Client Auth
# ---------------------------------------------------------------------------

class TestCloudIaCAuth:
    def test_auth_requires_credentials(self):
        client = CloudIaCClient(
            base_url="https://cldiac.example.com",
            auth_url="https://auth.example.com",
        )
        with pytest.raises(RuntimeError, match="CLDIAC_USER and CLDIAC_PASSWORD required"):
            client.authenticate()

    def test_auth_uses_cached_token(self):
        client = CloudIaCClient(
            base_url="https://cldiac.example.com",
            auth_url="https://auth.example.com",
            token="pre-existing-token",
        )
        assert client.authenticate() == "pre-existing-token"

    @patch("tfe_workspace.urlopen")
    def test_auth_basic_auth_header(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"id_token": "tok-123"}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = CloudIaCClient(
            base_url="https://cldiac.example.com",
            auth_url="https://auth.example.com",
            auth_env="E1",
            username="svc-sg-platform",
            password="secret123",
        )
        token = client.authenticate()
        assert token == "tok-123"

        # Verify the request
        call_args = mock_urlopen.call_args[0][0]
        expected_creds = base64.b64encode(b"svc-sg-platform:secret123").decode()
        assert call_args.get_header("Authorization") == f"Basic {expected_creds}"
        assert call_args.get_header("Environment") == "E1"
        assert "/api/v1/login" in call_args.full_url

    @patch("tfe_workspace.urlopen")
    def test_auth_missing_id_token(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"access_token": "wrong"}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = CloudIaCClient(
            base_url="https://cldiac.example.com",
            auth_url="https://auth.example.com",
            username="user",
            password="pass",
        )
        with pytest.raises(RuntimeError, match="missing id_token"):
            client.authenticate()


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
            details={"request": {
                "car_id": "car-1", "env": "prod", "project_id": "prj-1",
                "attach_repository": "org/repo",
                "dynamic_credentials_provider": "aws",
                "dynamic_credentials_auth": "arn:aws:iam::1:role/x",
            }},
        )]
        output = format_plan_text(actions)
        assert "sg-111222333444" in output
        assert "car-1" in output
        assert "prod" in output

    def test_markdown_no_actions(self):
        assert "in sync" in format_plan_markdown([])

    def test_markdown_with_create(self):
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="New",
            details={"request": {
                "car_id": "car-1", "env": "prod", "project_id": "prj-1",
                "attach_repository": "org/repo",
                "dynamic_credentials_provider": "aws",
                "dynamic_credentials_auth": "",
            }},
        )]
        output = format_plan_markdown(actions)
        assert "Create 1" in output
        assert "sg-111222333444" in output

    def test_json_serializable(self):
        actions = [PlanAction(
            action="create", workspace="sg-111222333444",
            account_id="111222333444", reason="New",
            details={"request": {}},
        )]
        json.dumps([asdict(a) for a in actions])  # should not raise


# ---------------------------------------------------------------------------
# Threading / Parallel Apply
# ---------------------------------------------------------------------------

class TestParallelApply:
    def test_apply_multiple_accounts_parallel(self, provisioner, mock_client):
        """Multiple creates execute and all return results."""
        mock_client.authenticate.return_value = "tok-123"
        mock_client.create_workspace.return_value = {"id": "ws-new"}
        mock_client.create_variable_set.return_value = {"id": "vs-new"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}
        actions = [
            PlanAction(action="create", workspace=f"sg-{i}11222333444",
                       account_id=f"{i}11222333444", reason="new", details={})
            for i in range(5)
        ]
        results = provisioner.apply(actions, max_workers=3)
        assert len(results) == 5
        assert all(r["status"] == "created" for r in results)
        assert mock_client.create_workspace.call_count == 5
        assert mock_client.create_variable_set.call_count == 5

    def test_pre_authenticates_before_threads(self, provisioner, mock_client):
        """Auth happens once before threads fan out."""
        mock_client.authenticate.return_value = "tok-123"
        mock_client.create_workspace.return_value = {"id": "ws-new"}
        mock_client.create_variable_set.return_value = {"id": "vs-new"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}
        actions = [
            PlanAction(action="create", workspace="sg-111222333444",
                       account_id="111222333444", reason="new", details={}),
            PlanAction(action="create", workspace="sg-555666777888",
                       account_id="555666777888", reason="new", details={}),
        ]
        provisioner.apply(actions, max_workers=2)
        mock_client.authenticate.assert_called_once()

    def test_partial_failure_doesnt_block_others(self, provisioner, mock_client):
        """One failure doesn't prevent other workspaces from being created."""
        mock_client.authenticate.return_value = "tok-123"
        mock_client.create_variable_set.return_value = {"id": "vs-ok"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}
        call_count = [0]
        def side_effect(req):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("API timeout")
            return {"id": "ws-ok"}
        mock_client.create_workspace.side_effect = side_effect
        actions = [
            PlanAction(action="create", workspace="sg-111222333444",
                       account_id="111222333444", reason="new", details={}),
            PlanAction(action="create", workspace="sg-555666777888",
                       account_id="555666777888", reason="new", details={}),
        ]
        results = provisioner.apply(actions, max_workers=1)  # sequential to control order
        statuses = {r["status"] for r in results}
        assert "error" in statuses
        assert "created" in statuses

    def test_skips_not_threaded(self, provisioner, mock_client):
        """Skip actions execute inline, not in thread pool."""
        mock_client.authenticate.return_value = "tok-123"
        actions = [
            PlanAction(action="skip", workspace="sg-000", account_id="000",
                       reason="not found"),
        ]
        results = provisioner.apply(actions, max_workers=3)
        assert len(results) == 1
        assert results[0]["status"] == "skipped"
        mock_client.create_workspace.assert_not_called()

    def test_empty_actions(self, provisioner, mock_client):
        """Empty action list returns empty results without auth."""
        results = provisioner.apply([], max_workers=3)
        assert results == []
        mock_client.authenticate.assert_not_called()

    def test_results_sorted_by_account_id(self, provisioner, mock_client):
        """Results come back sorted by account_id regardless of completion order."""
        mock_client.authenticate.return_value = "tok-123"
        mock_client.create_workspace.return_value = {"id": "ws-new"}
        mock_client.create_variable_set.return_value = {"id": "vs-new"}
        mock_client.create_variable_set_key.return_value = {}
        mock_client.attach_variable_set.return_value = {}
        actions = [
            PlanAction(action="create", workspace="sg-999888777666",
                       account_id="999888777666", reason="new", details={}),
            PlanAction(action="create", workspace="sg-111222333444",
                       account_id="111222333444", reason="new", details={}),
        ]
        results = provisioner.apply(actions, max_workers=2)
        account_ids = [r["account_id"] for r in results]
        assert account_ids == sorted(account_ids)
