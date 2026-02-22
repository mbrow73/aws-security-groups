#!/usr/bin/env python3
"""
Tests for the security group validation script.

Run: python -m pytest tests/test_validate.py -v
"""

import os
import sys
import tempfile
import shutil
import pytest
import yaml

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from validate import SecurityGroupValidator, ValidationSummary


@pytest.fixture
def repo_root():
    """Create a temporary repo root with guardrails and prefix-lists."""
    tmpdir = tempfile.mkdtemp()
    
    guardrails = {
        'validation': {
            'blocked_cidrs': ['0.0.0.0/0', '::/0'],
            'blocked_ports': [23, 135, 139, 445],
            'port_ranges': {'max_range_size': 1000},
            'rules': {
                'max_ingress_rules': 60,
                'max_egress_rules': 60,
            },
            'naming': {
                'security_group_pattern': r'^[a-z0-9][a-z0-9-]*[a-z0-9]$',
                'max_name_length': 63,
                'required_tags': [],  # disabled for unit tests
            },
        },
        'type_overrides': {},
    }
    
    prefix_lists = {
        'prefix_lists': {
            'corporate-networks': {
                'description': 'Corporate office CIDRs',
                'entries': ['10.100.0.0/16'],
            },
        },
    }
    
    with open(os.path.join(tmpdir, 'guardrails.yaml'), 'w') as f:
        yaml.dump(guardrails, f)
    with open(os.path.join(tmpdir, 'prefix-lists.yaml'), 'w') as f:
        yaml.dump(prefix_lists, f)
    
    yield tmpdir
    shutil.rmtree(tmpdir)


def _write_sg_yaml(repo_root, account_id, data):
    """Helper to write a security-groups.yaml file and return the account dir path."""
    account_dir = os.path.join(repo_root, 'accounts', account_id)
    os.makedirs(account_dir, exist_ok=True)
    with open(os.path.join(account_dir, 'security-groups.yaml'), 'w') as f:
        yaml.dump(data, f)
    return account_dir


def _validate(repo_root, account_id, data):
    """Helper to write yaml, validate, and return summary."""
    account_dir = _write_sg_yaml(repo_root, account_id, data)
    validator = SecurityGroupValidator(account_dir)
    return validator.validate()


# ============================================================
# Schema validation tests
# ============================================================

class TestSchemaValidation:
    def test_missing_required_fields(self, repo_root):
        data = {'environment': 'prod'}  # has content but missing required fields
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'schema_required_fields' in rules

    def test_security_groups_wrong_type(self, repo_root):
        data = {'account_id': '100000000001', 'security_groups': 'not-a-dict'}
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'schema_type' in rules

    def test_unknown_top_level_key(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {},
            'enviroment': 'prod',  # typo
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'schema_unknown_key' in rules
        assert any('enviroment' in e.message for e in summary.errors)

    def test_unknown_sg_key(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingresss': [],  # typo
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'schema_unknown_sg_key' in rules

    def test_unknown_rule_key(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'cidr_blocks': ['10.0.0.0/24'],
                        'descriptin': 'typo',  # typo
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'schema_unknown_rule_key' in rules


# ============================================================
# Environment validation tests
# ============================================================

class TestEnvironmentValidation:
    def test_valid_environments(self, repo_root):
        for env in ['prod', 'test', 'dev']:
            data = {
                'account_id': '100000000001',
                'environment': env,
                'security_groups': {},
            }
            summary = _validate(repo_root, '100000000001', data)
            env_errors = [e for e in summary.errors if e.rule and 'environment' in e.rule]
            assert len(env_errors) == 0, f"'{env}' should be valid"

    def test_invalid_environment(self, repo_root):
        data = {
            'account_id': '100000000001',
            'environment': 'production',  # should be 'prod'
            'security_groups': {},
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'schema_invalid_environment' in rules

    def test_environment_wrong_type(self, repo_root):
        data = {
            'account_id': '100000000001',
            'environment': 123,
            'security_groups': {},
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'schema_environment_type' in rules


# ============================================================
# Duplicate rule detection tests
# ============================================================

class TestDuplicateRules:
    def test_duplicate_ingress_rules(self, repo_root):
        rule = {
            'protocol': 'tcp',
            'from_port': 443,
            'to_port': 443,
            'cidr_blocks': ['10.0.0.0/24'],
        }
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [rule, rule],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_duplicate' in rules

    def test_no_false_positive_duplicates(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [
                        {'protocol': 'tcp', 'from_port': 443, 'to_port': 443, 'cidr_blocks': ['10.0.0.0/24']},
                        {'protocol': 'tcp', 'from_port': 8080, 'to_port': 8080, 'cidr_blocks': ['10.0.0.0/24']},
                    ],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        dup_errors = [e for e in summary.errors if e.rule == 'rule_duplicate']
        assert len(dup_errors) == 0

    def test_duplicate_egress_rules(self, repo_root):
        rule = {
            'protocol': 'tcp',
            'from_port': 443,
            'to_port': 443,
            'cidr_blocks': ['0.0.0.0/0'],
        }
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'egress': [rule, rule],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        dup_errors = [e for e in summary.errors if e.rule == 'rule_duplicate']
        assert len(dup_errors) == 1


# ============================================================
# CIDR type validation tests
# ============================================================

class TestCidrTypeValidation:
    def test_bare_string_cidr(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'cidr_blocks': '10.0.0.0/24',  # bare string, not list
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_cidr_type' in rules
        # Should still validate the CIDR itself
        assert not any(e.rule == 'rule_invalid_cidr' for e in summary.errors)

    def test_cidr_wrong_type(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'cidr_blocks': 12345,  # number
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_cidr_type' in rules

    def test_cidr_list_item_wrong_type(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'cidr_blocks': [10],  # number in list
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_cidr_item_type' in rules


# ============================================================
# Self field validation tests
# ============================================================

class TestSelfFieldValidation:
    def test_self_wrong_type(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'self': 'yes',  # should be bool
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_self_type' in rules

    def test_self_valid_bool(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'self': True,
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        self_errors = [e for e in summary.errors if e.rule == 'rule_self_type']
        assert len(self_errors) == 0


# ============================================================
# Empty rule list tests
# ============================================================

class TestEmptyRuleLists:
    def test_empty_ingress(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        warn_rules = [w.rule for w in summary.warnings]
        assert 'sg_empty_rules' in warn_rules

    def test_empty_egress(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'egress': [],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        warn_rules = [w.rule for w in summary.warnings]
        assert 'sg_empty_rules' in warn_rules


# ============================================================
# Ref type validation tests
# ============================================================

class TestRefTypeValidation:
    def test_security_groups_ref_wrong_type(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'security_groups': 'sg-12345',  # should be list
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_sg_ref_type' in rules

    def test_prefix_list_ref_wrong_type(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'prefix_list_ids': 'corporate-networks',  # should be list
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_prefix_list_type' in rules


# ============================================================
# Clean pass test
# ============================================================

class TestCleanPass:
    def test_valid_config_no_errors(self, repo_root):
        data = {
            'account_id': '100000000001',
            'environment': 'prod',
            'security_groups': {
                'web-app-sg': {
                    'description': 'Web application security group',
                    'ingress': [
                        {
                            'protocol': 'tcp',
                            'from_port': 443,
                            'to_port': 443,
                            'cidr_blocks': ['10.0.0.0/24'],
                            'description': 'HTTPS from app subnet',
                        },
                    ],
                    'egress': [
                        {
                            'protocol': 'tcp',
                            'from_port': 443,
                            'to_port': 443,
                            'cidr_blocks': ['10.0.0.0/24'],
                            'description': 'HTTPS to backend',
                        },
                    ],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        assert not summary.has_errors, f"Expected no errors, got: {[e.message for e in summary.errors]}"
        assert summary.get_exit_code() == 0


# ============================================================
# Guardrail tests (existing functionality, regression)
# ============================================================

class TestGuardrails:
    def test_blocked_port(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 23,
                        'to_port': 23,
                        'cidr_blocks': ['10.0.0.0/24'],
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_blocked_port' in rules

    def test_quad_zero_ingress_blocked(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 443,
                        'to_port': 443,
                        'cidr_blocks': ['0.0.0.0/0'],
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_blocked_cidr' in rules or 'rule_open_internet' in rules

    def test_broad_port_range(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 0,
                        'to_port': 65535,
                        'cidr_blocks': ['10.0.0.0/24'],
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        rules = [e.rule for e in summary.errors]
        assert 'rule_port_range_too_large' in rules

    def test_high_risk_ssh_from_cidr(self, repo_root):
        data = {
            'account_id': '100000000001',
            'security_groups': {
                'my-sg': {
                    'description': 'test',
                    'ingress': [{
                        'protocol': 'tcp',
                        'from_port': 22,
                        'to_port': 22,
                        'cidr_blocks': ['10.0.0.0/24'],
                    }],
                },
            },
        }
        summary = _validate(repo_root, '100000000001', data)
        warn_rules = [w.rule for w in summary.warnings]
        assert 'high_risk_pattern' in warn_rules
