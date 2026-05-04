#!/usr/bin/env python3
"""
AWS Security Group YAML Validator

Validates security group configurations against organizational guardrails and best practices.

Usage:
    python validate.py <account_directory>
    python validate.py accounts/123456789012
"""

import yaml
import json
import sys
import argparse
import ipaddress
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from account_config import load_account_config
from reference_classifier import classify_sg_reference, load_platform_security_groups, load_tenant_registry
from tenant_context import resolve_tenant_context


@dataclass
class ValidationResult:
    level: str
    message: str
    rule: str
    context: Optional[str] = None
    line: Optional[int] = None


@dataclass
class ValidationSummary:
    errors: List[ValidationResult]
    warnings: List[ValidationResult]
    info: List[ValidationResult]

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.info = []

    def add_result(self, result: ValidationResult):
        if result.level == 'error':
            self.errors.append(result)
        elif result.level == 'warning':
            self.warnings.append(result)
        else:
            self.info.append(result)

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0

    def get_exit_code(self) -> int:
        if self.has_errors:
            return 1
        elif self.has_warnings:
            return 2
        return 0


class SecurityGroupValidator:
    RESERVED_NAME_PREFIXES = [
        'default',
        'baseline',
        'aws-',
        'amazon-',
    ]

    ALLOWED_TOP_LEVEL_KEYS = {
        'account_id', 'environment', 'carid', 'default_region', 'regions', 'tags', 'security_groups'
    }
    ALLOWED_SG_KEYS = {
        'description', 'region', 'regions', 'vpc_id', 'tags', 'ingress', 'egress'
    }
    ALLOWED_RULE_KEYS = {
        'description', 'protocol', 'from_port', 'to_port',
        'cidr_blocks', 'ipv6_cidr_blocks', 'security_groups',
        'prefix_list_ids', 'self'
    }

    def __init__(self, account_dir: str):
        self.account_dir = Path(account_dir)
        self.config_file = self.account_dir / 'security-groups.yaml'
        self.repo_root = self._find_repo_root()
        self.guardrails = self._load_guardrails()
        self.prefix_lists = self._load_prefix_lists()
        self.account_config = load_account_config(self.account_dir, self.repo_root)
        self.platform_security_groups = load_platform_security_groups(self.repo_root)
        self.reference_tenant_registry = load_tenant_registry(self.repo_root)
        self.tenant_context = resolve_tenant_context(self.config_file, self.repo_root)
        self.account_id = self.tenant_context.account_id

    def _find_repo_root(self) -> Path:
        current = self.account_dir.resolve()
        while current != current.parent:
            if (current / 'guardrails.yaml').exists():
                return current
            current = current.parent
        return self.account_dir.parent.resolve()

    def _load_guardrails(self) -> Dict[str, Any]:
        guardrails_file = self.repo_root / 'guardrails.yaml'
        if guardrails_file.exists():
            with open(guardrails_file, 'r') as f:
                return yaml.safe_load(f)
        return {
            'validation': {
                'allowed_regions': ['us-east-1', 'us-west-2'],
                'blocked_cidrs': ['0.0.0.0/0', '::/0'],
                'blocked_ports': [22, 3389, 20, 21, 23, 25, 110, 143, 445, 135, 137, 138, 139],
                'max_rules_per_sg': 60,
                'naming': {
                    'security_group_pattern': r'^[a-z0-9][a-z0-9-]*[a-z0-9]$',
                    'max_name_length': 63
                }
            }
        }

    def _load_prefix_lists(self) -> Dict[str, Any]:
        allowlist_path = self.repo_root / 'known-prefix-lists.yaml'
        shared_path = self.repo_root / 'shared-prefix-lists.yaml'
        legacy_path = self.repo_root / 'prefix-lists.yaml'
        try:
            names = set()
            if allowlist_path.exists():
                with open(allowlist_path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                names.update(data.get('known_prefix_lists', []))
            if shared_path.exists():
                with open(shared_path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                names.update((data.get('shared_prefix_lists', {}) or {}).keys())
            if names:
                return {"prefix_lists": {name: {} for name in sorted(names)}}
            elif legacy_path.exists():
                with open(legacy_path, 'r') as f:
                    return yaml.safe_load(f)
            else:
                return {"prefix_lists": {}}
        except Exception:
            return {"prefix_lists": {}}

    def validate(self) -> ValidationSummary:
        summary = ValidationSummary()

        for error in self.account_config.errors:
            summary.add_result(ValidationResult(
                level='error',
                message=error,
                rule='account_config_loader'
            ))

        for warning in self.account_config.warnings:
            summary.add_result(ValidationResult(
                level='warning',
                message=warning,
                rule='account_config_loader'
            ))

        if self.account_config.errors:
            return summary

        data = self.account_config.config

        if not data:
            summary.add_result(ValidationResult(
                level='error',
                message="Configuration file is empty",
                rule='yaml_content'
            ))
            return summary

        self._validate_schema(data, summary)
        self._validate_account_id(data, summary)
        self._validate_registry_schema(summary)
        self._validate_tenant_registry(data, summary)
        self._validate_regions(data, summary)
        self._validate_security_groups(data, summary)
        self._validate_naming_conventions(data, summary)
        self._validate_prefix_list_references(data, summary)
        self._validate_unicode_characters(data, summary)

        return summary

    def _validate_registry_schema(self, summary: ValidationSummary):
        tenants = self.reference_tenant_registry or {}
        review_authorities = self._load_review_authorities_registry()
        platform_sgs = self.platform_security_groups or {}

        self._validate_review_authorities_registry(review_authorities, summary)
        self._validate_tenants_registry_schema(tenants, review_authorities.get('authorities', {}), summary)
        self._validate_platform_sg_registry(platform_sgs, review_authorities.get('authorities', {}), summary)

    def _load_review_authorities_registry(self) -> Dict[str, Any]:
        path = self.repo_root / 'registry' / 'review-authorities.yaml'
        if not path.exists():
            return {}
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f) or {}
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _validate_review_authorities_registry(self, registry: Dict[str, Any], summary: ValidationSummary):
        authorities = registry.get('authorities', {}) if isinstance(registry, dict) else {}
        rules = registry.get('rules', {}) if isinstance(registry, dict) else {}
        if authorities and not isinstance(authorities, dict):
            summary.add_result(ValidationResult(level='error', message='review-authorities.yaml authorities must be a mapping/object', rule='registry_review_authorities_invalid'))
            return
        for slug, authority in authorities.items():
            context = f"review_authority.{slug}"
            if not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', slug):
                summary.add_result(ValidationResult(level='error', message=f"Review authority slug '{slug}' must be lowercase kebab-case", rule='registry_review_authority_slug', context=context))
            if not isinstance(authority, dict):
                summary.add_result(ValidationResult(level='error', message=f"Review authority '{slug}' must be a mapping/object", rule='registry_review_authority_invalid', context=context))
                continue
            for field in ['ghe_host', 'org', 'team_slug']:
                if not isinstance(authority.get(field), str) or not authority.get(field).strip():
                    summary.add_result(ValidationResult(level='error', message=f"Review authority '{slug}' missing required field '{field}'", rule=f'registry_review_authority_{field}', context=context))
        if rules and not isinstance(rules, dict):
            summary.add_result(ValidationResult(level='error', message='review-authorities.yaml rules must be a mapping/object', rule='registry_review_rules_invalid'))
            return
        for rule_name, rule in rules.items():
            context = f"review_rule.{rule_name}"
            if not isinstance(rule, dict):
                summary.add_result(ValidationResult(level='error', message=f"Review rule '{rule_name}' must be a mapping/object", rule='registry_review_rule_invalid', context=context))
                continue
            authority = rule.get('authority')
            if authority not in authorities:
                summary.add_result(ValidationResult(level='error', message=f"Review rule '{rule_name}' references unknown authority '{authority}'", rule='registry_review_rule_authority', context=context))
            approvals = rule.get('required_authority_approvals')
            if not isinstance(approvals, int) or approvals < 1:
                summary.add_result(ValidationResult(level='error', message=f"Review rule '{rule_name}' must require at least one authority approval", rule='registry_review_rule_approvals', context=context))

    def _validate_tenants_registry_schema(self, tenants: Dict[str, Any], authorities: Dict[str, Any], summary: ValidationSummary):
        allowed_statuses = {'active', 'legacy', 'deprecated', 'disabled'}
        for slug, tenant in tenants.items():
            context = f"tenant.{slug}"
            if not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', slug):
                summary.add_result(ValidationResult(level='error', message=f"Tenant slug '{slug}' must be lowercase kebab-case", rule='registry_tenant_slug', context=context))
            if not isinstance(tenant, dict):
                summary.add_result(ValidationResult(level='error', message=f"Tenant '{slug}' must be a mapping/object", rule='registry_tenant_invalid', context=context))
                continue
            if tenant.get('status') not in allowed_statuses:
                summary.add_result(ValidationResult(level='error', message=f"Tenant '{slug}' has invalid status '{tenant.get('status')}'", rule='registry_tenant_status', context=context))
            authority = tenant.get('review_authority')
            if authority and authority not in authorities:
                summary.add_result(ValidationResult(level='error', message=f"Tenant '{slug}' references unknown review_authority '{authority}'", rule='registry_tenant_review_authority', context=context))
            for account_id in tenant.get('allowed_accounts', []) or []:
                if not isinstance(account_id, str) or not re.match(r'^\d{12}$', account_id):
                    summary.add_result(ValidationResult(level='error', message=f"Tenant '{slug}' has invalid AWS account ID '{account_id}'", rule='registry_tenant_allowed_account', context=context))
            for carid in tenant.get('carids', []) or []:
                if not isinstance(carid, str) or not re.match(r'^\d+$', carid):
                    summary.add_result(ValidationResult(level='error', message=f"Tenant '{slug}' has invalid CARID '{carid}'", rule='registry_tenant_carid', context=context))

    def _validate_platform_sg_registry(self, platform_sgs: Dict[str, Any], authorities: Dict[str, Any], summary: ValidationSummary):
        for slug, sg in platform_sgs.items():
            context = f"platform_security_group.{slug}"
            if not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', slug):
                summary.add_result(ValidationResult(level='error', message=f"Platform SG slug '{slug}' must be lowercase kebab-case", rule='registry_platform_sg_slug', context=context))
            if not isinstance(sg, dict):
                summary.add_result(ValidationResult(level='error', message=f"Platform SG '{slug}' must be a mapping/object", rule='registry_platform_sg_invalid', context=context))
                continue
            if sg.get('owner_authority') not in authorities:
                summary.add_result(ValidationResult(level='error', message=f"Platform SG '{slug}' references unknown owner_authority '{sg.get('owner_authority')}'", rule='registry_platform_sg_owner_authority', context=context))
            if sg.get('provision') not in ['automatic', 'manual']:
                summary.add_result(ValidationResult(level='error', message=f"Platform SG '{slug}' has invalid provision '{sg.get('provision')}'", rule='registry_platform_sg_provision', context=context))
            if sg.get('source') not in ['vpc_cidr']:
                summary.add_result(ValidationResult(level='error', message=f"Platform SG '{slug}' has invalid source '{sg.get('source')}'", rule='registry_platform_sg_source', context=context))
            if sg.get('review_class') not in ['platform_builtin']:
                summary.add_result(ValidationResult(level='error', message=f"Platform SG '{slug}' has invalid review_class '{sg.get('review_class')}'", rule='registry_platform_sg_review_class', context=context))

    def _validate_schema(self, data: Dict[str, Any], summary: ValidationSummary):
        if not isinstance(data, dict):
            summary.add_result(ValidationResult(
                level='error',
                message=f"Top-level YAML must be a mapping/object, got {type(data).__name__}",
                rule='schema_type'
            ))
            return

        required_fields = ['account_id', 'environment', 'carid', 'security_groups']
        for field in required_fields:
            if field not in data:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Missing required field: {field}",
                    rule='schema_required_fields'
                ))

        for key in data.keys():
            if key not in self.ALLOWED_TOP_LEVEL_KEYS:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Unknown top-level key '{key}'",
                    rule='schema_unknown_key',
                    context=key
                ))

        if 'carid' in data and not re.match(r'^\d+$', str(data['carid'])):
            summary.add_result(ValidationResult(
                level='error',
                message=f"carid must be numeric, got: {data['carid']}",
                rule='schema_carid_format'
            ))

        if 'environment' in data:
            if not isinstance(data['environment'], str):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"environment must be a string, got: {type(data['environment']).__name__}",
                    rule='schema_environment_type'
                ))
            elif not data['environment'].strip():
                summary.add_result(ValidationResult(
                    level='error',
                    message="environment cannot be empty",
                    rule='schema_invalid_environment'
                ))

        if 'security_groups' in data and not isinstance(data['security_groups'], dict):
            summary.add_result(ValidationResult(
                level='error',
                message=f"security_groups must be a mapping/object, got: {type(data['security_groups']).__name__}",
                rule='schema_type'
            ))

        if 'tags' in data and not isinstance(data['tags'], dict):
            summary.add_result(ValidationResult(
                level='error',
                message=f"tags must be a mapping/object, got: {type(data['tags']).__name__}",
                rule='schema_type'
            ))

    def _validate_account_id(self, data: Dict[str, Any], summary: ValidationSummary):
        if 'account_id' not in data:
            return
        account_id = str(data['account_id'])
        if not re.match(r'^\d{12}$', account_id):
            summary.add_result(ValidationResult(
                level='error',
                message=f"account_id must be a 12-digit AWS account number, got: {account_id}",
                rule='account_id_format'
            ))
        if self.account_id and account_id != self.account_id:
            summary.add_result(ValidationResult(
                level='error',
                message=f"account_id in YAML ({account_id}) does not match directory name ({self.account_id})",
                rule='account_id_consistency'
            ))

    def _validate_tenant_registry(self, data: Dict[str, Any], summary: ValidationSummary):
        context = self.tenant_context

        if context.registry_error:
            summary.add_result(ValidationResult(
                level='error',
                message=context.registry_error,
                rule='tenant_registry_invalid'
            ))
            return

        if not context.registry_found:
            return

        self._validate_reference_grants(summary)

        if not context.tenant_found:
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Tenant '{context.tenant}' is not defined in registry/tenants.yaml",
                rule='tenant_registry_missing_tenant',
                context=context.tenant
            ))
            if context.tenant == 'default':
                summary.add_result(ValidationResult(
                    level='warning',
                    message="Implicit tenant 'default' is not defined in registry/tenants.yaml",
                    rule='tenant_registry_missing_default',
                    context=context.tenant
                ))
            return

        status = context.status
        if status in ['deprecated', 'disabled']:
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Tenant '{context.tenant}' has status '{status}' in registry/tenants.yaml",
                rule='tenant_registry_status',
                context=context.tenant
            ))

        if context.allowed_accounts and data.get('account_id') and not context.account_allowed:
            account_id = str(data['account_id'])
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Account {account_id} is not listed under tenant '{context.tenant}' allowed_accounts in registry/tenants.yaml",
                rule='tenant_registry_account_scope',
                context=account_id
            ))

    def _validate_reference_grants(self, summary: ValidationSummary):
        tenants = self.reference_tenant_registry or {}
        if not tenants:
            return

        sg_tenant_map = {}
        tenant_sgs = {}
        for source in self.account_config.sources:
            sgs = source.data.get('security_groups', {}) or {}
            if not isinstance(sgs, dict):
                continue
            tenant_sgs.setdefault(source.tenant, set()).update(sgs.keys())
            for sg_name in sgs:
                sg_tenant_map[sg_name] = source.tenant

        for tenant_slug, tenant in tenants.items():
            if not isinstance(tenant, dict):
                continue
            grants = tenant.get('reference_grants', []) or []
            if not isinstance(grants, list):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Tenant '{tenant_slug}' reference_grants must be a list",
                    rule='reference_grant_invalid',
                    context=tenant_slug
                ))
                continue

            seen_names = set()
            for index, grant in enumerate(grants):
                context = f"tenant.{tenant_slug}.reference_grants[{index}]"
                if not isinstance(grant, dict):
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Reference grant for tenant '{tenant_slug}' must be a mapping/object",
                        rule='reference_grant_invalid',
                        context=context
                    ))
                    continue

                name = grant.get('name')
                if not isinstance(name, str) or not name.strip():
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Reference grant for tenant '{tenant_slug}' must include a non-empty name",
                        rule='reference_grant_name',
                        context=context
                    ))
                elif name in seen_names:
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Duplicate reference grant name '{name}' for tenant '{tenant_slug}'",
                        rule='reference_grant_duplicate_name',
                        context=context
                    ))
                else:
                    seen_names.add(name)

                self._validate_reference_grant_list_field(grant, 'target_sgs', context, summary)
                self._validate_reference_grant_list_field(grant, 'source_tenants', context, summary)
                self._validate_reference_grant_list_field(grant, 'protocols', context, summary)
                self._validate_reference_grant_list_field(grant, 'ports', context, summary, item_type=int)
                self._validate_reference_grant_list_field(grant, 'directions', context, summary)

                if grant.get('decision') != 'auto_approved':
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Reference grant '{name or index}' for tenant '{tenant_slug}' must use decision 'auto_approved'",
                        rule='reference_grant_decision',
                        context=context
                    ))

                for protocol in grant.get('protocols', []) or []:
                    if str(protocol).lower() not in ['tcp', 'udp', 'icmp']:
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"Reference grant '{name or index}' has unsupported protocol '{protocol}'",
                            rule='reference_grant_protocol',
                            context=context
                        ))

                for direction in grant.get('directions', []) or []:
                    if str(direction).lower() not in ['ingress', 'egress']:
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"Reference grant '{name or index}' has invalid direction '{direction}'",
                            rule='reference_grant_direction',
                            context=context
                        ))

                for port in grant.get('ports', []) or []:
                    if not isinstance(port, int) or port < 0 or port > 65535:
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"Reference grant '{name or index}' has invalid port '{port}'",
                            rule='reference_grant_port',
                            context=context
                        ))

                for source_tenant in grant.get('source_tenants', []) or []:
                    if source_tenant != '*' and source_tenant not in tenants:
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"Reference grant '{name or index}' references unknown source tenant '{source_tenant}'",
                            rule='reference_grant_source_tenant',
                            context=context
                        ))

                if tenant_slug in tenant_sgs:
                    for target_sg in grant.get('target_sgs', []) or []:
                        if target_sg not in tenant_sgs.get(tenant_slug, set()):
                            summary.add_result(ValidationResult(
                                level='error',
                                message=f"Reference grant '{name or index}' target SG '{target_sg}' is not owned by tenant '{tenant_slug}' in this account",
                                rule='reference_grant_target_sg',
                                context=context
                            ))

                expires = grant.get('expires')
                if expires:
                    try:
                        from datetime import date
                        expiry = date.fromisoformat(str(expires))
                        if expiry < date.today():
                            summary.add_result(ValidationResult(
                                level='warning',
                                message=f"Reference grant '{name or index}' for tenant '{tenant_slug}' is expired ({expires})",
                                rule='reference_grant_expired',
                                context=context
                            ))
                    except ValueError:
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"Reference grant '{name or index}' has invalid expires date '{expires}'",
                            rule='reference_grant_expires',
                            context=context
                        ))

    def _validate_reference_grant_list_field(self, grant: Dict[str, Any], field: str, context: str, summary: ValidationSummary, item_type=str):
        value = grant.get(field)
        if not isinstance(value, list) or not value:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Reference grant field '{field}' must be a non-empty list",
                rule=f"reference_grant_{field}",
                context=context
            ))
            return
        for item in value:
            if item_type is int:
                if not isinstance(item, int):
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Reference grant field '{field}' must contain integers",
                        rule=f"reference_grant_{field}",
                        context=context
                    ))
            elif not isinstance(item, str) or not item.strip():
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Reference grant field '{field}' must contain non-empty strings",
                    rule=f"reference_grant_{field}",
                    context=context
                ))

    def _validate_regions(self, data: Dict[str, Any], summary: ValidationSummary):
        allowed_regions = self.guardrails.get('validation', {}).get('allowed_regions', ['us-east-1', 'us-west-2'])

        def validate_region_value(region, rule_invalid, rule_disallowed, message_prefix, context=None):
            if not isinstance(region, str) or not re.match(r'^[a-z]{2}-[a-z]+-\d+$', region):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"{message_prefix}: {region}",
                    rule=rule_invalid,
                    context=context
                ))
            elif region not in allowed_regions:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"{message_prefix} '{region}' is not allowed. Allowed regions: {', '.join(allowed_regions)}",
                    rule=rule_disallowed,
                    context=context
                ))

        if 'default_region' in data:
            validate_region_value(data['default_region'], 'invalid_default_region', 'disallowed_default_region', 'default_region')

        if 'regions' in data:
            regions = data['regions']
            if not isinstance(regions, list) or not regions:
                summary.add_result(ValidationResult(
                    level='error',
                    message='regions must be a non-empty list of AWS regions',
                    rule='invalid_regions_list'
                ))
            else:
                for region in regions:
                    validate_region_value(region, 'invalid_regions_value', 'disallowed_regions_value', 'Account region')

        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return
        for sg_name, sg in data['security_groups'].items():
            if not isinstance(sg, dict):
                continue
            if 'region' in sg and 'regions' in sg:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' cannot define both 'region' and 'regions'",
                    rule='conflicting_sg_region_keys',
                    context=f"security_group.{sg_name}"
                ))
            if 'region' in sg:
                validate_region_value(sg['region'], 'invalid_sg_region', 'disallowed_sg_region', f"Region in security group '{sg_name}'", f"security_group.{sg_name}")
            if 'regions' in sg:
                regions = sg['regions']
                if not isinstance(regions, list) or not regions:
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Security group '{sg_name}' regions must be a non-empty list",
                        rule='invalid_sg_regions_list',
                        context=f"security_group.{sg_name}"
                    ))
                else:
                    for region in regions:
                        validate_region_value(region, 'invalid_sg_regions_value', 'disallowed_sg_regions_value', f"Region in security group '{sg_name}'", f"security_group.{sg_name}")

    def _validate_security_groups(self, data: Dict[str, Any], summary: ValidationSummary):
        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return

        max_rules = self.guardrails.get('validation', {}).get('max_rules_per_sg', 60)

        for sg_name, sg in data['security_groups'].items():
            context = f"security_group.{sg_name}"

            if not isinstance(sg, dict):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' must be an object, got {type(sg).__name__}",
                    rule='sg_type',
                    context=context
                ))
                continue

            for key in sg.keys():
                if key not in self.ALLOWED_SG_KEYS:
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Unknown security group key '{key}' in '{sg_name}'",
                        rule='schema_unknown_sg_key',
                        context=context
                    ))

            if 'description' not in sg:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' is missing required 'description' field",
                    rule='sg_required_description',
                    context=context
                ))
            elif not isinstance(sg['description'], str) or not sg['description'].strip():
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' description must be a non-empty string",
                    rule='sg_required_description',
                    context=context
                ))

            if 'tags' in sg and not isinstance(sg['tags'], dict):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' tags must be a mapping/object",
                    rule='schema_type',
                    context=context
                ))

            ingress = sg.get('ingress', [])
            egress = sg.get('egress', [])

            if not isinstance(ingress, list):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"'ingress' in security group '{sg_name}' must be a list",
                    rule='sg_ingress_type',
                    context=context
                ))
                ingress = []
            elif len(ingress) == 0:
                summary.add_result(ValidationResult(
                    level='info',
                    message=f"Security group '{sg_name}' has an empty ingress list",
                    rule='sg_empty_rules',
                    context=context
                ))

            if not isinstance(egress, list):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"'egress' in security group '{sg_name}' must be a list",
                    rule='sg_egress_type',
                    context=context
                ))
                egress = []
            elif len(egress) == 0:
                summary.add_result(ValidationResult(
                    level='info',
                    message=f"Security group '{sg_name}' has an empty egress list",
                    rule='sg_empty_rules',
                    context=context
                ))

            total_rules = len(ingress) + len(egress)
            if total_rules > max_rules:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' has {total_rules} rules, exceeding max allowed {max_rules}",
                    rule='sg_rule_count_limit',
                    context=context
                ))

            self._check_duplicate_rules(sg_name, 'ingress', ingress, summary)
            self._check_duplicate_rules(sg_name, 'egress', egress, summary)
            self._check_shadowed_rules(sg_name, 'ingress', ingress, summary)
            self._check_shadowed_rules(sg_name, 'egress', egress, summary)

            for i, rule in enumerate(ingress):
                self._validate_security_group_rule(sg_name, 'ingress', i, rule, summary)
            for i, rule in enumerate(egress):
                self._validate_security_group_rule(sg_name, 'egress', i, rule, summary)

    def _normalize_rule(self, rule: Dict[str, Any]) -> str:
        rule_copy = dict(rule)
        rule_copy.pop('description', None)
        return json.dumps(rule_copy, sort_keys=True)

    def _check_shadowed_rules(self, sg_name: str, rule_type: str, rules: List[Dict[str, Any]], summary: ValidationSummary):
        context_base = f"security_group.{sg_name}.{rule_type}"
        for i, narrow in enumerate(rules):
            if not isinstance(narrow, dict):
                continue
            for j, broad in enumerate(rules):
                if i == j or not isinstance(broad, dict):
                    continue
                if self._rule_is_shadowed_by(narrow, broad):
                    broad_desc = self._describe_rule_brief(broad)
                    narrow_desc = self._describe_rule_brief(narrow)
                    summary.add_result(ValidationResult(
                        level='warning',
                        message=(
                            f"Shadowed rule: {sg_name} {rule_type}[{i}] ({narrow_desc}) is fully covered by "
                            f"{rule_type}[{j}] ({broad_desc}). Remove the redundant rule if it is not intentional."
                        ),
                        rule='rule_shadowed',
                        context=f"{context_base}[{i}]"
                    ))
                    break

    def _rule_is_shadowed_by(self, narrow: Dict[str, Any], broad: Dict[str, Any]) -> bool:
        broad_proto = broad.get('protocol', '')
        narrow_proto = narrow.get('protocol', '')
        if broad_proto not in ('all', '-1') and broad_proto != narrow_proto:
            return False
        if broad_proto not in ('all', '-1'):
            if broad_proto in ('tcp', 'udp') and narrow_proto in ('tcp', 'udp'):
                try:
                    b_from = int(broad.get('from_port', -1))
                    b_to = int(broad.get('to_port', -1))
                    n_from = int(narrow.get('from_port', -1))
                    n_to = int(narrow.get('to_port', -1))
                except (ValueError, TypeError):
                    return False
                if b_from > n_from or b_to < n_to:
                    return False
        return self._sources_covered(narrow, broad)

    def _sources_covered(self, narrow: Dict[str, Any], broad: Dict[str, Any]) -> bool:
        narrow_cidrs = narrow.get('cidr_blocks', [])
        narrow_v6 = narrow.get('ipv6_cidr_blocks', [])
        narrow_sgs = narrow.get('security_groups', [])
        narrow_pls = narrow.get('prefix_list_ids', [])
        narrow_self = narrow.get('self', False)

        broad_cidrs = broad.get('cidr_blocks', [])
        broad_v6 = broad.get('ipv6_cidr_blocks', [])
        broad_sgs = broad.get('security_groups', [])
        broad_pls = broad.get('prefix_list_ids', [])
        broad_self = broad.get('self', False)

        if isinstance(narrow_cidrs, str): narrow_cidrs = [narrow_cidrs]
        if isinstance(broad_cidrs, str): broad_cidrs = [broad_cidrs]
        if isinstance(narrow_v6, str): narrow_v6 = [narrow_v6]
        if isinstance(broad_v6, str): broad_v6 = [broad_v6]
        if not isinstance(narrow_sgs, list): narrow_sgs = []
        if not isinstance(broad_sgs, list): broad_sgs = []
        if not isinstance(narrow_pls, list): narrow_pls = []
        if not isinstance(broad_pls, list): broad_pls = []

        for n_cidr in narrow_cidrs:
            if not self._cidr_covered_by_any(n_cidr, broad_cidrs):
                return False
        for n_cidr in narrow_v6:
            if not self._cidr_covered_by_any(n_cidr, broad_v6):
                return False
        if narrow_self and not broad_self:
            return False
        for sg in narrow_sgs:
            if sg not in broad_sgs:
                return False
        for pl in narrow_pls:
            if pl not in broad_pls:
                return False
        return bool(narrow_cidrs or narrow_v6 or narrow_sgs or narrow_pls or narrow_self)

    def _cidr_covered_by_any(self, narrow_cidr: str, broad_cidrs: list) -> bool:
        try:
            narrow_net = ipaddress.ip_network(narrow_cidr, strict=False)
        except (ValueError, TypeError):
            return False
        for b_cidr in broad_cidrs:
            try:
                broad_net = ipaddress.ip_network(b_cidr, strict=False)
                if narrow_net.subnet_of(broad_net):
                    return True
            except (ValueError, TypeError):
                continue
        return False

    def _describe_rule_brief(self, rule: Dict[str, Any]) -> str:
        proto = rule.get('protocol', '?')
        parts = [proto]
        from_p = rule.get('from_port')
        to_p = rule.get('to_port')
        if from_p is not None and to_p is not None:
            if from_p == to_p:
                parts.append(f"port {from_p}")
            else:
                parts.append(f"ports {from_p}-{to_p}")
        sources = []
        cidr_blocks = rule.get('cidr_blocks', [])
        if isinstance(cidr_blocks, list):
            sources.extend(str(c) for c in cidr_blocks)
        ipv6_blocks = rule.get('ipv6_cidr_blocks', [])
        if isinstance(ipv6_blocks, list):
            sources.extend(str(c) for c in ipv6_blocks)
        if rule.get('self'):
            sources.append('self')
        if isinstance(rule.get('security_groups'), list):
            sources.extend(rule.get('security_groups', []))
        if isinstance(rule.get('prefix_list_ids'), list):
            sources.extend(rule.get('prefix_list_ids', []))
        if sources:
            parts.append(f"from {', '.join(sources[:3])}")
            if len(sources) > 3:
                parts.append(f"+{len(sources)-3} more")
        return ' '.join(parts)

    def _check_duplicate_rules(self, sg_name: str, rule_type: str, rules: List[Dict[str, Any]], summary: ValidationSummary):
        seen = {}
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            normalized = self._normalize_rule(rule)
            if normalized in seen:
                first_index = seen[normalized]
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Duplicate rule: {sg_name} {rule_type}[{i}] is identical to {rule_type}[{first_index}]. Remove the duplicate rule.",
                    rule='rule_duplicate',
                    context=f"security_group.{sg_name}.{rule_type}[{i}]"
                ))
            else:
                seen[normalized] = i

    def _validate_security_group_rule(self, sg_name: str, rule_type: str, rule_index: int, rule: Dict[str, Any], summary: ValidationSummary):
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        if not isinstance(rule, dict):
            summary.add_result(ValidationResult(
                level='error',
                message=f"Rule in {sg_name} {rule_type}[{rule_index}] must be an object, got {type(rule).__name__}",
                rule='rule_type',
                context=context
            ))
            return

        for key in rule.keys():
            if key not in self.ALLOWED_RULE_KEYS:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Unknown rule key '{key}' in {sg_name} {rule_type}[{rule_index}]",
                    rule='schema_unknown_rule_key',
                    context=context
                ))

        if 'protocol' not in rule:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Rule in {sg_name} {rule_type}[{rule_index}] is missing 'protocol'",
                rule='rule_required_protocol',
                context=context
            ))
            return

        protocol = rule['protocol']
        valid_protocols = ['tcp', 'udp', 'icmp', 'icmpv6', 'ah', 'esp', 'gre', 'all', '-1']
        if protocol not in valid_protocols:
            try:
                proto_num = int(protocol)
                if not (0 <= proto_num <= 255):
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Invalid protocol '{protocol}' in {sg_name} {rule_type}[{rule_index}]",
                        rule='rule_invalid_protocol',
                        context=context
                    ))
            except ValueError:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Invalid protocol '{protocol}' in {sg_name} {rule_type}[{rule_index}]",
                    rule='rule_invalid_protocol',
                    context=context
                ))

        if protocol in ['tcp', 'udp']:
            self._validate_port_range(sg_name, rule_type, rule_index, rule, summary)

        self._validate_rule_sources(sg_name, rule_type, rule_index, rule, summary)

    def _validate_port_range(self, sg_name: str, rule_type: str, rule_index: int, rule: Dict[str, Any], summary: ValidationSummary):
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        from_port = rule.get('from_port')
        to_port = rule.get('to_port')
        if from_port is None or to_port is None:
            summary.add_result(ValidationResult(
                level='error',
                message=f"TCP/UDP rule in {sg_name} {rule_type}[{rule_index}] requires 'from_port' and 'to_port'",
                rule='rule_required_ports',
                context=context
            ))
            return

        parsed_ports = {}
        for port_field, port_value in [('from_port', from_port), ('to_port', to_port)]:
            try:
                port_num = int(port_value)
                if not (0 <= port_num <= 65535):
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Invalid {port_field} '{port_value}' in {sg_name} {rule_type}[{rule_index}] (must be 0-65535)",
                        rule='rule_invalid_port',
                        context=context
                    ))
                parsed_ports[port_field] = port_num
            except (ValueError, TypeError):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Invalid {port_field} '{port_value}' in {sg_name} {rule_type}[{rule_index}] (must be a number)",
                    rule='rule_invalid_port_type',
                    context=context
                ))
                return

        from_port = parsed_ports['from_port']
        to_port = parsed_ports['to_port']
        if from_port > to_port:
            summary.add_result(ValidationResult(
                level='error',
                message=f"from_port ({from_port}) cannot be greater than to_port ({to_port}) in {sg_name} {rule_type}[{rule_index}]",
                rule='rule_invalid_port_range',
                context=context
            ))

        if (to_port - from_port) > 1000:
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Large port range ({from_port}-{to_port}) in {sg_name} {rule_type}[{rule_index}] may be overly broad",
                rule='rule_port_range_too_large',
                context=context
            ))

        blocked_ports = self.guardrails.get('validation', {}).get('blocked_ports', [])
        for port in range(from_port, to_port + 1):
            if port in blocked_ports:
                port_desc = self._get_port_description(port)
                if port in [135, 139]:
                    reason = "commonly exploited for lateral movement attacks"
                    suggestion = "Remove this rule unless the security team has explicitly approved it."
                elif port == 23:
                    reason = "telnet is plain text and insecure"
                    suggestion = "Use SSH or Session Manager instead."
                elif port == 3389:
                    reason = "RDP is commonly brute-forced and high risk"
                    suggestion = "Use Systems Manager Session Manager for Windows access."
                elif port in [21, 25]:
                    reason = "the protocol is considered insecure"
                    suggestion = "Use a secure alternative."
                else:
                    reason = "it is blocked by guardrail policy"
                    suggestion = "Remove the rule or get explicit approval."
                summary.add_result(ValidationResult(
                    level='warning',
                    message=f"Guardrail warning: {port_desc} in {sg_name} {rule_type}[{rule_index}] is discouraged — {reason}. {suggestion}",
                    rule='rule_blocked_port',
                    context=context
                ))

        cidr_list = rule.get('cidr_blocks', [])
        if not isinstance(cidr_list, list):
            cidr_list = [cidr_list] if isinstance(cidr_list, str) else []
        has_cidr_source = bool(cidr_list)
        has_broad_cidr = any(c in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] for c in cidr_list)
        if rule_type == 'ingress' and has_cidr_source:
            if from_port <= 22 <= to_port:
                summary.add_result(ValidationResult(
                    level='warning',
                    message=f"SSH (port 22) ingress from CIDR in {sg_name} {rule_type}[{rule_index}] is high risk",
                    rule='high_risk_pattern',
                    context=context
                ))
            if from_port <= 3389 <= to_port:
                summary.add_result(ValidationResult(
                    level='warning',
                    message=f"RDP (port 3389) ingress from CIDR in {sg_name} {rule_type}[{rule_index}] is high risk",
                    rule='high_risk_pattern',
                    context=context
                ))
        db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 27017: 'MongoDB', 6379: 'Redis'}
        if rule_type == 'ingress' and has_cidr_source:
            for db_port, db_name in db_ports.items():
                if from_port <= db_port <= to_port:
                    summary.add_result(ValidationResult(
                        level='warning',
                        message=f"{db_name} (port {db_port}) ingress from CIDR in {sg_name} {rule_type}[{rule_index}] deserves review",
                        rule='high_risk_pattern',
                        context=context
                    ))
        if rule_type == 'ingress' and has_broad_cidr:
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Broad internal CIDR ingress in {sg_name} {rule_type}[{rule_index}] may be overly permissive",
                rule='broad_cidr_pattern',
                context=context
            ))

    def _validate_rule_sources(self, sg_name: str, rule_type: str, rule_index: int, rule: Dict[str, Any], summary: ValidationSummary):
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"

        selector_fields = ['cidr_blocks', 'ipv6_cidr_blocks', 'security_groups', 'self', 'prefix_list_ids']
        active_selectors = []
        for field in selector_fields:
            value = rule.get(field)
            if field == 'self':
                if value is True:
                    active_selectors.append(field)
            elif value not in (None, [], ''):
                active_selectors.append(field)

        if not active_selectors:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Rule in {sg_name} {rule_type}[{rule_index}] must specify one selector (cidr_blocks, ipv6_cidr_blocks, security_groups, prefix_list_ids, or self)",
                rule='rule_selector_missing',
                context=context
            ))
            return
        if len(active_selectors) > 1:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Rule in {sg_name} {rule_type}[{rule_index}] mixes multiple selector types: {', '.join(active_selectors)}",
                rule='rule_selector_multiple',
                context=context
            ))

        for cidr_field in ['cidr_blocks', 'ipv6_cidr_blocks']:
            if cidr_field in rule:
                is_ipv6 = cidr_field == 'ipv6_cidr_blocks'
                cidr_value = rule[cidr_field]
                if isinstance(cidr_value, str):
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"'{cidr_field}' in {sg_name} {rule_type}[{rule_index}] must be a list, not a bare string",
                        rule='rule_cidr_type',
                        context=context
                    ))
                    self._validate_cidr_block(sg_name, rule_type, rule_index, cidr_value, is_ipv6, summary, rule)
                elif not isinstance(cidr_value, list):
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"'{cidr_field}' in {sg_name} {rule_type}[{rule_index}] must be a list, got {type(cidr_value).__name__}",
                        rule='rule_cidr_type',
                        context=context
                    ))
                else:
                    if len(cidr_value) > 1:
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"'{cidr_field}' in {sg_name} {rule_type}[{rule_index}] has {len(cidr_value)} entries. Split into separate rules, one CIDR per rule.",
                            rule='rule_multi_cidr',
                            context=context
                        ))
                    for cidr in cidr_value:
                        if not isinstance(cidr, str):
                            summary.add_result(ValidationResult(
                                level='error',
                                message=f"CIDR in {sg_name} {rule_type}[{rule_index}] must be a string, got {type(cidr).__name__}",
                                rule='rule_cidr_item_type',
                                context=context
                            ))
                        else:
                            self._validate_cidr_block(sg_name, rule_type, rule_index, cidr, is_ipv6, summary, rule)

        if 'self' in rule and not isinstance(rule['self'], bool):
            summary.add_result(ValidationResult(
                level='error',
                message=f"'self' in {sg_name} {rule_type}[{rule_index}] must be true or false",
                rule='rule_self_type',
                context=context
            ))

        if 'security_groups' in rule:
            if not isinstance(rule['security_groups'], list):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"'security_groups' in {sg_name} {rule_type}[{rule_index}] must be a list",
                    rule='rule_sg_ref_type',
                    context=context
                ))
            else:
                seen_refs = set()
                for sg_ref in rule['security_groups']:
                    if not isinstance(sg_ref, str) or not sg_ref.strip():
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"security group references in {sg_name} {rule_type}[{rule_index}] must be non-empty strings",
                            rule='rule_sg_ref_type',
                            context=context
                        ))
                        continue
                    if sg_ref in seen_refs:
                        summary.add_result(ValidationResult(
                            level='warning',
                            message=f"Duplicate security group reference '{sg_ref}' in {sg_name} {rule_type}[{rule_index}]",
                            rule='rule_sg_ref_duplicate',
                            context=context
                        ))
                    seen_refs.add(sg_ref)
                    self._validate_security_group_reference(sg_name, rule_type, rule_index, rule, sg_ref, summary)

        if 'prefix_list_ids' in rule:
            if not isinstance(rule['prefix_list_ids'], list):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"'prefix_list_ids' in {sg_name} {rule_type}[{rule_index}] must be a list",
                    rule='rule_prefix_list_type',
                    context=context
                ))
            else:
                seen_pl = set()
                for prefix_list_id in rule['prefix_list_ids']:
                    if not isinstance(prefix_list_id, str) or not prefix_list_id.strip():
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"prefix_list_ids in {sg_name} {rule_type}[{rule_index}] must be non-empty strings",
                            rule='rule_prefix_list_type',
                            context=context
                        ))
                        continue
                    if prefix_list_id in seen_pl:
                        summary.add_result(ValidationResult(
                            level='warning',
                            message=f"Duplicate prefix list reference '{prefix_list_id}' in {sg_name} {rule_type}[{rule_index}]",
                            rule='rule_prefix_list_duplicate',
                            context=context
                        ))
                    seen_pl.add(prefix_list_id)
                    self._validate_prefix_list_reference(sg_name, rule_type, rule_index, prefix_list_id, summary)

    def _validate_cidr_block(self, sg_name: str, rule_type: str, rule_index: int, cidr: str, is_ipv6: bool, summary: ValidationSummary, rule: Dict[str, Any] = None):
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        try:
            if is_ipv6:
                ipaddress.IPv6Network(cidr, strict=False)
            else:
                ipaddress.IPv4Network(cidr, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Invalid CIDR block '{cidr}' in {sg_name} {rule_type}[{rule_index}]: {e}",
                rule='rule_invalid_cidr',
                context=context
            ))
            return

        blocked_cidrs = self.guardrails.get('validation', {}).get('blocked_cidrs', [])
        if cidr in blocked_cidrs:
            if rule_type == 'ingress':
                message = f"{cidr} ingress is not allowed. Use a specific CIDR, security group reference, or prefix list instead."
            else:
                message = f"{cidr} egress is unrestricted outbound access. Scope it to a specific CIDR, SG reference, or prefix list."
            summary.add_result(ValidationResult(
                level='error',
                message=message,
                rule='rule_blocked_cidr',
                context=context
            ))

        if (not is_ipv6 and cidr == '0.0.0.0/0') or (is_ipv6 and cidr == '::/0'):
            if rule_type == 'ingress':
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"{cidr} ingress opens the rule to the entire internet. Use a specific CIDR, security group reference, or prefix list instead.",
                    rule='rule_open_internet',
                    context=context
                ))
            elif rule_type == 'egress':
                r_from = rule.get('from_port', 0) if rule else 0
                r_to = rule.get('to_port', 0) if rule else 0
                if r_from == 443 and r_to == 443:
                    return
                port_display = f"port {r_from}" if r_from == r_to else f"ports {r_from}-{r_to}"
                summary.add_result(ValidationResult(
                    level='warning',
                    message=f"Egress to {cidr} on {port_display} is broad and deserves review.",
                    rule='rule_open_egress',
                    context=context
                ))

    def _validate_security_group_reference(self, sg_name: str, rule_type: str, rule_index: int, rule: Dict[str, Any], sg_ref: str, summary: ValidationSummary):
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        if sg_ref.startswith('sg-'):
            if not re.match(r'^sg-[0-9a-fA-F]{8,}$', sg_ref):
                summary.add_result(ValidationResult(
                    level='warning',
                    message=f"Security group ID '{sg_ref}' in {sg_name} {rule_type}[{rule_index}] does not match expected sg- format",
                    rule='rule_sg_reference_format',
                    context=context
                ))
            return
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_-]*$', sg_ref):
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Security group reference '{sg_ref}' in {sg_name} {rule_type}[{rule_index}] may be invalid",
                rule='rule_sg_reference_format',
                context=context
            ))

        classification = classify_sg_reference(
            self.account_config,
            self.platform_security_groups,
            sg_name,
            sg_ref,
            tenant_registry=self.reference_tenant_registry,
            direction=rule_type,
            protocol=rule.get('protocol'),
            from_port=rule.get('from_port'),
            to_port=rule.get('to_port'),
        )
        if classification.ref_class == 'platform_builtin':
            summary.add_result(ValidationResult(
                level='info',
                message=f"Security group reference '{sg_ref}' in {sg_name} {rule_type}[{rule_index}] targets platform built-in SG owned by {classification.owner_authority or 'platform'}",
                rule='sg_ref_platform_builtin',
                context=context
            ))
        elif classification.ref_class == 'same_tenant':
            summary.add_result(ValidationResult(
                level='info',
                message=f"Security group reference '{sg_ref}' in {sg_name} {rule_type}[{rule_index}] stays within tenant '{classification.source_tenant}'",
                rule='sg_ref_same_tenant',
                context=context
            ))
        elif classification.ref_class == 'cross_tenant':
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Security group reference '{sg_ref}' in {sg_name} {rule_type}[{rule_index}] crosses tenant boundary: {classification.source_tenant or 'unknown'} -> {classification.target_tenant}",
                rule='sg_ref_cross_tenant',
                context=context
            ))
        elif classification.ref_class == 'cross_tenant_granted':
            summary.add_result(ValidationResult(
                level='info',
                message=f"Security group reference '{sg_ref}' in {sg_name} {rule_type}[{rule_index}] crosses tenant boundary but matches target-owned reference grant '{classification.grant_name}'",
                rule='sg_ref_cross_tenant_granted',
                context=context
            ))
        elif classification.ref_class == 'unknown':
            summary.add_result(ValidationResult(
                level='error',
                message=f"Unknown security group reference '{sg_ref}' in {sg_name} {rule_type}[{rule_index}]. Define it in this account or add it as a platform built-in SG.",
                rule='sg_ref_unknown',
                context=context
            ))

    def _validate_prefix_list_reference(self, sg_name: str, rule_type: str, rule_index: int, prefix_list_id: str, summary: ValidationSummary):
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        if prefix_list_id.startswith('pl-'):
            summary.add_result(ValidationResult(
                level='info',
                message=f"Using AWS managed prefix list '{prefix_list_id}' in {sg_name} {rule_type}[{rule_index}]",
                rule='rule_aws_prefix_list',
                context=context
            ))
        elif prefix_list_id not in self.prefix_lists.get('prefix_lists', {}):
            summary.add_result(ValidationResult(
                level='error',
                message=f"Undefined prefix list '{prefix_list_id}' in {sg_name} {rule_type}[{rule_index}]",
                rule='rule_undefined_prefix_list',
                context=context
            ))

    def _validate_naming_conventions(self, data: Dict[str, Any], summary: ValidationSummary):
        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return
        naming_config = self.guardrails.get('validation', {}).get('naming', {})
        sg_pattern = naming_config.get('security_group_pattern', r'^[a-z0-9][a-z0-9_-]*[a-z0-9]$')
        max_length = naming_config.get('max_name_length', 63)
        for sg_name in data['security_groups']:
            if not re.match(sg_pattern, sg_name):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group name '{sg_name}' doesn't match required pattern: {sg_pattern}",
                    rule='naming_pattern_violation',
                    context=f"security_group.{sg_name}"
                ))
            if len(sg_name) > max_length:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group name '{sg_name}' is too long ({len(sg_name)} chars, max {max_length})",
                    rule='naming_length_violation',
                    context=f"security_group.{sg_name}"
                ))
            for pattern in self.RESERVED_NAME_PREFIXES:
                if sg_name.startswith(pattern):
                    summary.add_result(ValidationResult(
                        level='info',
                        message=f"Security group name '{sg_name}' starts with reserved pattern '{pattern}'",
                        rule='naming_reserved_pattern',
                        context=f"security_group.{sg_name}"
                    ))

    def _validate_unicode_characters(self, data: Dict[str, Any], summary: ValidationSummary):
        import string
        printable = set(string.printable)

        def check_ascii(value: str, field_path: str):
            for i, ch in enumerate(value):
                if ch not in printable:
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Non-ASCII character {repr(ch)} (U+{ord(ch):04X}) found in {field_path} at position {i}",
                        rule='unicode_character',
                        context=field_path
                    ))
                    return

        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return
        for sg_name, sg_config in data['security_groups'].items():
            check_ascii(sg_name, f"security_group.{sg_name}.name")
            if not isinstance(sg_config, dict):
                continue
            if 'description' in sg_config and isinstance(sg_config['description'], str):
                check_ascii(sg_config['description'], f"security_group.{sg_name}.description")
            if 'tags' in sg_config and isinstance(sg_config['tags'], dict):
                for tag_key, tag_value in sg_config['tags'].items():
                    if isinstance(tag_key, str):
                        check_ascii(tag_key, f"security_group.{sg_name}.tags.key.{tag_key}")
                    if isinstance(tag_value, str):
                        check_ascii(tag_value, f"security_group.{sg_name}.tags.value.{tag_key}")
            for rule_type in ['ingress', 'egress']:
                if rule_type not in sg_config or not isinstance(sg_config[rule_type], list):
                    continue
                for i, rule in enumerate(sg_config[rule_type]):
                    if not isinstance(rule, dict):
                        continue
                    if 'description' in rule and isinstance(rule['description'], str):
                        check_ascii(rule['description'], f"security_group.{sg_name}.{rule_type}[{i}].description")
                    for cidr_field in ['cidr_blocks', 'ipv6_cidr_blocks']:
                        if cidr_field in rule and isinstance(rule[cidr_field], list):
                            for j, cidr in enumerate(rule[cidr_field]):
                                if isinstance(cidr, str):
                                    check_ascii(cidr, f"security_group.{sg_name}.{rule_type}[{i}].{cidr_field}[{j}]")

    def _validate_prefix_list_references(self, data: Dict[str, Any], summary: ValidationSummary):
        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return
        referenced_prefix_lists = set()
        for _, sg_config in data['security_groups'].items():
            for rule_type in ['ingress', 'egress']:
                if rule_type in sg_config:
                    for rule in sg_config[rule_type]:
                        if 'prefix_list_ids' in rule:
                            for prefix_list_id in rule['prefix_list_ids']:
                                if isinstance(prefix_list_id, str) and not prefix_list_id.startswith('pl-'):
                                    referenced_prefix_lists.add(prefix_list_id)
        defined_prefix_lists = set(self.prefix_lists.get('prefix_lists', {}).keys())
        undefined_prefix_lists = referenced_prefix_lists - defined_prefix_lists
        for prefix_list in undefined_prefix_lists:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Referenced prefix list '{prefix_list}' is not defined in prefix-lists.yaml",
                rule='undefined_prefix_list_reference'
            ))

    def _get_port_description(self, port: int) -> str:
        common_ports = {
            20: 'FTP-DATA (20)', 21: 'FTP (21)', 22: 'SSH (22)', 23: 'Telnet (23)',
            25: 'SMTP (25)', 110: 'POP3 (110)', 135: 'RPC (135)', 137: 'NetBIOS-NS (137)',
            138: 'NetBIOS-DGM (138)', 139: 'NetBIOS-SSN (139)', 143: 'IMAP (143)',
            443: 'HTTPS (443)', 445: 'SMB (445)', 3389: 'RDP (3389)'
        }
        return common_ports.get(port, f'port {port}')

    def format_markdown_output(self, summary: ValidationSummary) -> str:
        output = []
        error_count = len(summary.errors)
        warning_count = len(summary.warnings)
        if error_count == 0 and warning_count == 0:
            output.append("## ✅ Security Group Validation Results")
            output.append(f"**Account:** {self.account_id} | **Status:** All checks passed!")
            return "\n\n".join(output)
        output.append("## 🔍 Security Group Validation Results")
        output.append(f"**Account:** {self.account_id} | **Errors:** {error_count} | **Warnings:** {warning_count}")
        output.append("")

        tag_results = {'errors': [], 'warnings': []}
        schema_results = {'errors': [], 'warnings': []}
        sg_results = {}
        TAG_RULES = {'sg_required_tags'}
        SCHEMA_RULES = {'schema_unknown_key', 'schema_unknown_sg_key', 'schema_unknown_rule_key',
                       'schema_required_fields', 'schema_type', 'schema_invalid_environment',
                       'schema_environment_type', 'file_exists', 'yaml_syntax', 'yaml_content'}

        for result in summary.errors + summary.warnings:
            bucket = 'errors' if result.level == 'error' else 'warnings'
            if result.rule in TAG_RULES:
                tag_results[bucket].append(result)
            elif result.rule in SCHEMA_RULES or (not result.context or 'security_group.' not in result.context):
                schema_results[bucket].append(result)
            else:
                sg_name = result.context.split('.')[1]
                if sg_name not in sg_results:
                    sg_results[sg_name] = {'errors': [], 'warnings': []}
                sg_results[sg_name][bucket].append(result)

        def _render_section(title, results):
            sec_errors = len(results['errors'])
            sec_warnings = len(results['warnings'])
            if sec_errors == 0 and sec_warnings == 0:
                return
            output.append("<details>")
            output.append(f"<summary>{title}</summary>")
            output.append("")
            if results['errors']:
                output.append("### Errors")
                for error in results['errors']:
                    message = error.message[1:].strip() if error.message.startswith('❌') else error.message
                    output.append(f"- ❌ {message}")
                output.append("")
            if results['warnings']:
                output.append("### Warnings")
                for warning in results['warnings']:
                    message = warning.message[2:].strip() if warning.message.startswith('⚠️') else warning.message
                    output.append(f"- ⚠️ {message}")
                output.append("")
            output.append("</details>")
            output.append("")

        sec_errors = len(schema_results['errors'])
        sec_warnings = len(schema_results['warnings'])
        if sec_errors or sec_warnings:
            _render_section(f"⚙️ Configuration Issues — {sec_errors} errors, {sec_warnings} warnings", schema_results)

        sec_errors = len(tag_results['errors'])
        sec_warnings = len(tag_results['warnings'])
        if sec_errors or sec_warnings:
            _render_section(f"🏷️ Tag Compliance — {sec_errors} errors, {sec_warnings} warnings", tag_results)

        for sg_name, results in sg_results.items():
            sec_errors = len(results['errors'])
            sec_warnings = len(results['warnings'])
            if sec_errors == 0 and sec_warnings == 0:
                continue
            emoji = '❌' if sec_errors > 0 else '⚠️'
            _render_section(f"{emoji} {sg_name} — {sec_errors} errors, {sec_warnings} warnings", results)

        return "\n".join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Validate AWS Security Group YAML configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0 - All validations passed
  1 - Validation failures (errors)
  2 - Warnings only (no errors)

Examples:
  python validate.py accounts/123456789012
  python validate.py accounts/production
        """
    )
    parser.add_argument('account_dir', help='Path to the account directory containing security-groups.yaml')
    parser.add_argument('--format', choices=['text', 'json', 'markdown'], default='text', help='Output format (default: text)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Include info-level messages in output')
    parser.add_argument('--warnings-as-errors', action='store_true', help='Treat warnings as errors')
    parser.add_argument('--no-warnings', action='store_true', help='Suppress warning output (only show errors)')
    args = parser.parse_args()

    try:
        validator = SecurityGroupValidator(args.account_dir)
        summary = validator.validate()

        if args.no_warnings:
            summary.warnings = []
        if args.warnings_as_errors and summary.has_warnings and not summary.has_errors:
            summary.errors.extend(summary.warnings)
            summary.warnings = []

        if args.format == 'markdown':
            print(validator.format_markdown_output(summary))
        elif args.format == 'json':
            output = {
                'account_dir': args.account_dir,
                'account_id': validator.account_id,
                'validation_results': {
                    'errors': [asdict(r) for r in summary.errors],
                    'warnings': [asdict(r) for r in summary.warnings],
                    'info': [asdict(r) for r in summary.info] if args.verbose else []
                },
                'summary': {
                    'error_count': len(summary.errors),
                    'warning_count': len(summary.warnings),
                    'info_count': len(summary.info),
                    'exit_code': summary.get_exit_code()
                }
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"🔍 Validating AWS Security Groups for account: {validator.account_id}")
            print(f"📁 Directory: {args.account_dir}")
            print()
            if summary.errors:
                print("❌ Errors:")
                for error in summary.errors:
                    context_str = f" [{error.context}]" if error.context else ""
                    rule_str = f" ({error.rule})" if error.rule else ""
                    print(f"   • {error.message}{context_str}{rule_str}")
                print()
            if summary.warnings:
                print("⚠️  Warnings:")
                for warning in summary.warnings:
                    context_str = f" [{warning.context}]" if warning.context else ""
                    rule_str = f" ({warning.rule})" if warning.rule else ""
                    print(f"   • {warning.message}{context_str}{rule_str}")
                print()
            if args.verbose and summary.info:
                print("ℹ️  Info:")
                for info in summary.info:
                    context_str = f" [{info.context}]" if info.context else ""
                    rule_str = f" ({info.rule})" if info.rule else ""
                    print(f"   • {info.message}{context_str}{rule_str}")
                print()
            print("📊 Summary:")
            print(f"   Errors: {len(summary.errors)}")
            print(f"   Warnings: {len(summary.warnings)}")
            if args.verbose:
                print(f"   Info: {len(summary.info)}")
            if summary.get_exit_code() == 0:
                print("\n✅ All validations passed!")
            elif summary.get_exit_code() == 2:
                print("\n⚠️  Validation completed with warnings")
            else:
                print("\n❌ Validation failed with errors")

        sys.exit(summary.get_exit_code())

    except Exception as e:
        if args.format == 'json':
            print(json.dumps({'error': str(e)}, indent=2))
        else:
            print(f"❌ Validation error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
