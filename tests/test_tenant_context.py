#!/usr/bin/env python3
"""Tests for shared tenant context resolution."""

import os
import shutil
import sys
import tempfile

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from tenant_context import derive_account_and_tenant, resolve_tenant_context


@pytest.fixture
def repo_root():
    tmpdir = tempfile.mkdtemp()
    with open(os.path.join(tmpdir, 'guardrails.yaml'), 'w') as f:
        f.write('validation: {}\n')
    yield tmpdir
    shutil.rmtree(tmpdir)


def _write_registry(repo_root, tenants):
    registry_dir = os.path.join(repo_root, 'registry')
    os.makedirs(registry_dir, exist_ok=True)
    with open(os.path.join(registry_dir, 'tenants.yaml'), 'w') as f:
        yaml.dump({'tenants': tenants}, f)


def test_legacy_account_path_resolves_default_tenant(repo_root):
    account_id, tenant, layout = derive_account_and_tenant(
        os.path.join(repo_root, 'accounts', '123456789012', 'security-groups.yaml'),
        repo_root,
    )
    assert account_id == '123456789012'
    assert tenant == 'default'
    assert layout == 'legacy'


def test_future_tenant_path_resolves_path_tenant(repo_root):
    account_id, tenant, layout = derive_account_and_tenant(
        os.path.join(repo_root, 'accounts', '123456789012', 'payments-platform', 'security-groups.yaml'),
        repo_root,
    )
    assert account_id == '123456789012'
    assert tenant == 'payments-platform'
    assert layout == 'tenant'


def test_resolves_defined_non_default_tenant_metadata(repo_root):
    _write_registry(repo_root, {
        'payments-platform': {
            'display_name': 'Payments Platform',
            'status': 'active',
            'owner_team': 'payments-networking',
            'github_reviewers': ['payments-reviewers'],
            'slack_channel': '#payments-netsec',
            'allowed_accounts': ['123456789012'],
        },
    })

    context = resolve_tenant_context(
        os.path.join(repo_root, 'accounts', '123456789012', 'payments-platform', 'security-groups.yaml'),
        repo_root,
    )

    assert context.tenant == 'payments-platform'
    assert context.layout == 'tenant'
    assert context.tenant_found is True
    assert context.display_name == 'Payments Platform'
    assert context.status == 'active'
    assert context.owner_team == 'payments-networking'
    assert context.github_reviewers == ['payments-reviewers']
    assert context.slack_channel == '#payments-netsec'
    assert context.account_allowed is True


def test_unknown_tenant_returns_context_without_metadata(repo_root):
    _write_registry(repo_root, {
        'default': {
            'status': 'legacy',
            'allowed_accounts': ['123456789012'],
        },
    })

    context = resolve_tenant_context(
        os.path.join(repo_root, 'accounts', '123456789012', 'payments-platform', 'security-groups.yaml'),
        repo_root,
    )

    assert context.tenant == 'payments-platform'
    assert context.tenant_found is False
    assert context.registry_found is True


def test_account_not_in_allowed_accounts_marks_scope_mismatch(repo_root):
    _write_registry(repo_root, {
        'payments-platform': {
            'status': 'active',
            'allowed_accounts': ['999999999999'],
        },
    })

    context = resolve_tenant_context(
        os.path.join(repo_root, 'accounts', '123456789012', 'payments-platform', 'security-groups.yaml'),
        repo_root,
    )

    assert context.tenant_found is True
    assert context.allowed_accounts == ['999999999999']
    assert context.account_allowed is False
