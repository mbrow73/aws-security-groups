#!/usr/bin/env python3
"""Tests for tenant-aware account config loading."""

import os
import shutil
import sys
import tempfile

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from account_config import load_account_config


@pytest.fixture
def repo_root():
    tmpdir = tempfile.mkdtemp()
    with open(os.path.join(tmpdir, 'guardrails.yaml'), 'w') as f:
        f.write('validation: {}\n')
    yield tmpdir
    shutil.rmtree(tmpdir)


def _write_yaml(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        yaml.safe_dump(data, f)


def _write_registry(repo_root):
    _write_yaml(os.path.join(repo_root, 'registry', 'tenants.yaml'), {
        'tenants': {
            'default': {
                'status': 'legacy',
                'allowed_accounts': ['123456789012'],
            },
            'payments': {
                'status': 'active',
                'allowed_accounts': ['123456789012'],
            },
            'data': {
                'status': 'active',
                'allowed_accounts': ['123456789012'],
            },
        },
    })


def _base_config(sgs):
    return {
        'account_id': '123456789012',
        'environment': 'prod',
        'carid': '600001725',
        'default_region': 'us-east-1',
        'regions': ['us-east-1'],
        'security_groups': sgs,
    }


def test_legacy_layout_loads_unchanged(repo_root):
    _write_registry(repo_root)
    account_dir = os.path.join(repo_root, 'accounts', '123456789012')
    _write_yaml(os.path.join(account_dir, 'security-groups.yaml'), _base_config({
        'app-web': {'description': 'web'},
    }))

    result = load_account_config(account_dir, repo_root)

    assert result.ok
    assert result.layout == 'legacy'
    assert result.config['account_id'] == '123456789012'
    assert sorted(result.config['security_groups'].keys()) == ['app-web']
    assert result.sources[0].tenant == 'default'


def test_tenant_layout_merges_security_groups(repo_root):
    _write_registry(repo_root)
    account_dir = os.path.join(repo_root, 'accounts', '123456789012')
    _write_yaml(os.path.join(account_dir, 'payments', 'security-groups.yaml'), _base_config({
        'payments-web': {'description': 'payments web'},
    }))
    _write_yaml(os.path.join(account_dir, 'data', 'security-groups.yaml'), _base_config({
        'data-api': {'description': 'data api'},
    }))

    result = load_account_config(account_dir, repo_root)

    assert result.ok
    assert result.layout == 'tenant'
    assert sorted(result.config['security_groups'].keys()) == ['data-api', 'payments-web']
    assert sorted(source.tenant for source in result.sources) == ['data', 'payments']


def test_mixed_legacy_and_tenant_layout_errors(repo_root):
    _write_registry(repo_root)
    account_dir = os.path.join(repo_root, 'accounts', '123456789012')
    _write_yaml(os.path.join(account_dir, 'security-groups.yaml'), _base_config({}))
    _write_yaml(os.path.join(account_dir, 'payments', 'security-groups.yaml'), _base_config({}))

    result = load_account_config(account_dir, repo_root)

    assert not result.ok
    assert any('Mixed legacy and tenant layouts' in error for error in result.errors)


def test_duplicate_security_group_names_error(repo_root):
    _write_registry(repo_root)
    account_dir = os.path.join(repo_root, 'accounts', '123456789012')
    _write_yaml(os.path.join(account_dir, 'payments', 'security-groups.yaml'), _base_config({
        'shared-sg': {'description': 'payments'},
    }))
    _write_yaml(os.path.join(account_dir, 'data', 'security-groups.yaml'), _base_config({
        'shared-sg': {'description': 'data'},
    }))

    result = load_account_config(account_dir, repo_root)

    assert not result.ok
    assert any("Duplicate security group 'shared-sg'" in error for error in result.errors)


def test_conflicting_account_metadata_errors(repo_root):
    _write_registry(repo_root)
    account_dir = os.path.join(repo_root, 'accounts', '123456789012')
    _write_yaml(os.path.join(account_dir, 'payments', 'security-groups.yaml'), _base_config({}))
    data_config = _base_config({})
    data_config['environment'] = 'nonprod'
    _write_yaml(os.path.join(account_dir, 'data', 'security-groups.yaml'), data_config)

    result = load_account_config(account_dir, repo_root)

    assert not result.ok
    assert any("Conflicting account metadata 'environment'" in error for error in result.errors)
