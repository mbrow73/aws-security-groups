#!/usr/bin/env python3
"""Tests for security group reference classification."""

import os
import shutil
import sys
import tempfile

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from account_config import load_account_config
from reference_classifier import classify_sg_reference, load_platform_security_groups


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


def _setup_registry(repo_root):
    _write_yaml(os.path.join(repo_root, 'registry', 'tenants.yaml'), {
        'tenants': {
            'payments': {'status': 'active', 'allowed_accounts': ['123456789012']},
            'data': {'status': 'active', 'allowed_accounts': ['123456789012']},
        },
    })
    _write_yaml(os.path.join(repo_root, 'registry', 'platform-security-groups.yaml'), {
        'platform_security_groups': {
            'vpc-endpoints': {
                'owner_authority': 'platform-sg',
                'provision': 'automatic',
            },
        },
    })


def _setup_tenant_account(repo_root):
    _setup_registry(repo_root)
    account_dir = os.path.join(repo_root, 'accounts', '123456789012')
    _write_yaml(os.path.join(account_dir, 'payments', 'security-groups.yaml'), {
        'account_id': '123456789012',
        'environment': 'prod',
        'carid': '600001725',
        'security_groups': {
            'payments-web': {'description': 'web'},
            'payments-api': {'description': 'api'},
        },
    })
    _write_yaml(os.path.join(account_dir, 'data', 'security-groups.yaml'), {
        'account_id': '123456789012',
        'environment': 'prod',
        'carid': '600001725',
        'security_groups': {
            'data-api': {'description': 'data'},
        },
    })
    return account_dir


def test_classifies_platform_builtin(repo_root):
    account_dir = _setup_tenant_account(repo_root)
    loaded = load_account_config(account_dir, repo_root)
    platform_sgs = load_platform_security_groups(repo_root)

    result = classify_sg_reference(loaded, platform_sgs, 'payments-web', 'vpc-endpoints')

    assert result.ref_class == 'platform_builtin'
    assert result.owner_authority == 'platform-sg'


def test_classifies_same_tenant(repo_root):
    account_dir = _setup_tenant_account(repo_root)
    loaded = load_account_config(account_dir, repo_root)

    result = classify_sg_reference(loaded, {}, 'payments-web', 'payments-api')

    assert result.ref_class == 'same_tenant'
    assert result.source_tenant == 'payments'
    assert result.target_tenant == 'payments'


def test_classifies_cross_tenant(repo_root):
    account_dir = _setup_tenant_account(repo_root)
    loaded = load_account_config(account_dir, repo_root)

    result = classify_sg_reference(loaded, {}, 'payments-web', 'data-api')

    assert result.ref_class == 'cross_tenant'
    assert result.source_tenant == 'payments'
    assert result.target_tenant == 'data'


def test_classifies_unknown(repo_root):
    account_dir = _setup_tenant_account(repo_root)
    loaded = load_account_config(account_dir, repo_root)

    result = classify_sg_reference(loaded, {}, 'payments-web', 'missing-sg')

    assert result.ref_class == 'unknown'
