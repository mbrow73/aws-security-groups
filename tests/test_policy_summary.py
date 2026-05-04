#!/usr/bin/env python3
"""Tests for policy summary artifact generation."""

import os
import shutil
import sys
import tempfile

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from policy_summary import build_policy_summary


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


def test_policy_summary_reports_tenants_refs_and_requirements(repo_root):
    _write_yaml(os.path.join(repo_root, 'registry', 'review-authorities.yaml'), {
        'authorities': {
            'payments-sg': {'ghe_host': 'github.aexp.com', 'org': 'amex-eng', 'team_slug': 'payments'},
            'data-sg': {'ghe_host': 'github.aexp.com', 'org': 'amex-eng', 'team_slug': 'data'},
            'platform-sg': {'ghe_host': 'github.aexp.com', 'org': 'amex-eng', 'team_slug': 'nsae'},
        },
    })
    _write_yaml(os.path.join(repo_root, 'registry', 'platform-security-groups.yaml'), {
        'platform_security_groups': {
            'vpc-endpoints': {'owner_authority': 'platform-sg'},
        },
    })
    _write_yaml(os.path.join(repo_root, 'registry', 'tenants.yaml'), {
        'tenants': {
            'payments': {'status': 'active', 'review_authority': 'payments-sg', 'allowed_accounts': ['123456789012']},
            'data': {
                'status': 'active',
                'review_authority': 'data-sg',
                'allowed_accounts': ['123456789012'],
                'reference_grants': [{
                    'name': 'allow-https-to-data-api',
                    'target_sgs': ['data-api'],
                    'source_tenants': ['payments'],
                    'protocols': ['tcp'],
                    'ports': [443],
                    'directions': ['egress'],
                    'decision': 'auto_approved',
                    'expires': None,
                }],
            },
        },
    })
    account_dir = os.path.join(repo_root, 'accounts', '123456789012')
    _write_yaml(os.path.join(account_dir, 'payments', 'security-groups.yaml'), {
        'account_id': '123456789012',
        'environment': 'prod',
        'carid': '600001725',
        'security_groups': {
            'payments-web': {
                'description': 'web',
                'egress': [
                    {'protocol': 'tcp', 'from_port': 443, 'to_port': 443, 'security_groups': ['vpc-endpoints']},
                    {'protocol': 'tcp', 'from_port': 443, 'to_port': 443, 'security_groups': ['data-api']},
                ],
            },
        },
    })
    _write_yaml(os.path.join(account_dir, 'data', 'security-groups.yaml'), {
        'account_id': '123456789012',
        'environment': 'prod',
        'carid': '600001725',
        'security_groups': {'data-api': {'description': 'api'}},
    })

    summary = build_policy_summary(account_dir, repo_root)

    assert summary['layout'] == 'tenant'
    assert summary['tenants'] == ['data', 'payments']
    classes = {ref['target_sg']: ref['ref_class'] for ref in summary['references']}
    assert classes['vpc-endpoints'] == 'platform_builtin'
    assert classes['data-api'] == 'cross_tenant_granted'
    assert summary['required_review_authorities'] == {'data-sg': 2, 'payments-sg': 2}


def test_policy_summary_only_requires_changed_tenant_authority(repo_root):
    test_policy_summary_reports_tenants_refs_and_requirements(repo_root)
    account_dir = os.path.join(repo_root, 'accounts', '123456789012')

    summary = build_policy_summary(
        account_dir,
        repo_root,
        changed_files=['accounts/123456789012/payments/security-groups.yaml'],
    )

    assert summary['changed_tenants'] == ['payments']
    classes = {ref['target_sg']: ref['ref_class'] for ref in summary['references']}
    assert classes['vpc-endpoints'] == 'platform_builtin'
    assert classes['data-api'] == 'cross_tenant_granted'
    assert summary['required_review_authorities'] == {'payments-sg': 2}
