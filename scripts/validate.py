#!/usr/bin/env python3
"""
AWS Security Group Platform - Validation Script

Main validation entrypoint that performs comprehensive validation of security group YAML files
against schema, guardrails, and naming conventions.

Usage:
    python validate.py <account_directory_path>

Exit codes:
    0 - All validations passed
    1 - Validation failures (errors)
    2 - Warnings only (no errors)
"""

import sys
import os
import re
import yaml
import ipaddress
import argparse
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field
import json


@dataclass
class ValidationResult:
    """Represents the result of a validation check"""
    level: str  # 'error', 'warning', 'info'
    message: str
    line: Optional[int] = None
    rule: Optional[str] = None
    context: Optional[str] = None


@dataclass
class ValidationSummary:
    """Summary of all validation results"""
    errors: List[ValidationResult] = field(default_factory=list)
    warnings: List[ValidationResult] = field(default_factory=list)
    info: List[ValidationResult] = field(default_factory=list)
    
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
    """Main validator for AWS Security Groups YAML configuration"""
    
    # Port name mapping for blocked/warning ports
    PORT_NAMES = {
        23: "Telnet",
        135: "NetBIOS/RPC",
        139: "NetBIOS/SMB",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        22: "SSH",
        21: "FTP",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S"
    }
    
    def __init__(self, account_dir: str):
        self.account_dir = Path(account_dir).resolve()
        self.repo_root = self._find_repo_root()
        self.guardrails = self._load_guardrails()
        self.prefix_lists = self._load_prefix_lists()
        self.account_id = self._extract_account_id()
    
    def _get_port_description(self, port: int) -> str:
        """Get human-readable port description"""
        if port in self.PORT_NAMES:
            return f"{port} ({self.PORT_NAMES[port]})"
        return str(port)
        
    def _find_repo_root(self) -> Path:
        """Find the repository root by looking for guardrails.yaml"""
        current = self.account_dir
        while current != current.parent:
            if (current / "guardrails.yaml").exists():
                return current
            current = current.parent
        raise FileNotFoundError("Could not find repository root with guardrails.yaml")
    
    def _load_guardrails(self) -> Dict[str, Any]:
        """Load guardrails configuration from repo root"""
        guardrails_path = self.repo_root / "guardrails.yaml"
        try:
            with open(guardrails_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise FileNotFoundError(f"Failed to load guardrails.yaml: {e}")
    
    def _load_prefix_lists(self) -> Dict[str, Any]:
        """Load prefix lists configuration from repo root"""
        prefix_lists_path = self.repo_root / "prefix-lists.yaml"
        try:
            with open(prefix_lists_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            # Prefix lists are optional
            return {"prefix_lists": {}}
    
    def _extract_account_id(self) -> str:
        """Extract account ID from the directory path"""
        # Account directories should be named with 12-digit account IDs
        account_dir_name = self.account_dir.name
        if re.match(r'^\d{12}$', account_dir_name):
            return account_dir_name
        
        # If directory name isn't an account ID, look for it in the YAML
        security_groups_file = self.account_dir / "security-groups.yaml"
        if security_groups_file.exists():
            try:
                with open(security_groups_file, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and 'account_id' in data:
                        return data['account_id']
            except:
                pass
        
        raise ValueError(f"Could not determine account ID from directory '{account_dir_name}'")
    
    def validate(self) -> ValidationSummary:
        """Main validation method - performs all checks"""
        summary = ValidationSummary()
        
        # Check if security-groups.yaml exists
        sg_file = self.account_dir / "security-groups.yaml"
        if not sg_file.exists():
            summary.add_result(ValidationResult(
                level='error',
                message=f"❌ security-groups.yaml not found in {self.account_dir} — this file is required to define security groups for the account.\n   → Create security-groups.yaml with your security group definitions.",
                rule='file_exists'
            ))
            return summary
        
        # Load and parse YAML
        try:
            with open(sg_file, 'r') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            summary.add_result(ValidationResult(
                level='error',
                message=f"YAML syntax error: {e}",
                rule='yaml_syntax'
            ))
            return summary
        
        if not data:
            summary.add_result(ValidationResult(
                level='error',
                message="security-groups.yaml is empty",
                rule='yaml_content'
            ))
            return summary
        
        # Perform all validation checks
        self._validate_schema(data, summary)
        self._validate_account_id(data, summary)
        self._validate_baseline_profiles(data, summary)
        self._validate_security_groups(data, summary)
        self._validate_guardrails(data, summary)
        self._validate_naming_conventions(data, summary)
        self._validate_prefix_list_references(data, summary)
        self._validate_unicode_characters(data, summary)
        
        return summary
    
    # Known top-level keys in security-groups.yaml
    KNOWN_TOP_LEVEL_KEYS = {'account_id', 'environment', 'security_groups', 'baseline_profiles', 'tags'}
    # Known keys within a security group definition
    KNOWN_SG_KEYS = {'description', 'ingress', 'egress', 'tags', 'type'}
    # Known keys within a rule definition
    KNOWN_RULE_KEYS = {'protocol', 'from_port', 'to_port', 'cidr_blocks', 'ipv6_cidr_blocks',
                       'security_groups', 'prefix_list_ids', 'self', 'description'}
    # Valid environments
    VALID_ENVIRONMENTS = {'prod', 'test', 'dev'}

    def _validate_schema(self, data: Dict[str, Any], summary: ValidationSummary):
        """Validate basic YAML schema structure"""
        required_fields = ['account_id', 'security_groups']
        
        for field in required_fields:
            if field not in data:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Required field '{field}' is missing",
                    rule='schema_required_fields'
                ))
        
        # Check for unknown top-level keys (typo detection)
        unknown_keys = set(data.keys()) - self.KNOWN_TOP_LEVEL_KEYS
        for key in sorted(unknown_keys):
            summary.add_result(ValidationResult(
                level='error',
                message=f"❌ Unknown top-level key '{key}' — did you mean one of: {', '.join(sorted(self.KNOWN_TOP_LEVEL_KEYS))}?\n   → Typos in key names are silently ignored and your config won't apply.",
                rule='schema_unknown_key'
            ))
        
        # Validate environment field
        if 'environment' in data:
            env = data['environment']
            if not isinstance(env, str):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"'environment' must be a string, got {type(env).__name__}",
                    rule='schema_environment_type'
                ))
            elif env not in self.VALID_ENVIRONMENTS:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"❌ Invalid environment '{env}' — must be one of: {', '.join(sorted(self.VALID_ENVIRONMENTS))}\n   → This controls environment-specific guardrails and tagging.",
                    rule='schema_invalid_environment'
                ))
        
        if 'security_groups' in data:
            if not isinstance(data['security_groups'], dict):
                summary.add_result(ValidationResult(
                    level='error',
                    message="'security_groups' must be a dictionary/object",
                    rule='schema_type'
                ))
            else:
                # Validate unknown keys within each security group
                for sg_name, sg_config in data['security_groups'].items():
                    if not isinstance(sg_config, dict):
                        continue
                    unknown_sg_keys = set(sg_config.keys()) - self.KNOWN_SG_KEYS
                    for key in sorted(unknown_sg_keys):
                        summary.add_result(ValidationResult(
                            level='error',
                            message=f"❌ Unknown key '{key}' in security group '{sg_name}' — valid keys: {', '.join(sorted(self.KNOWN_SG_KEYS))}\n   → Typos are silently ignored. Check spelling.",
                            rule='schema_unknown_sg_key',
                            context=f"security_group.{sg_name}"
                        ))
                    
                    # Validate unknown keys within each rule
                    for rule_type in ['ingress', 'egress']:
                        if rule_type in sg_config and isinstance(sg_config[rule_type], list):
                            for i, rule in enumerate(sg_config[rule_type]):
                                if not isinstance(rule, dict):
                                    continue
                                unknown_rule_keys = set(rule.keys()) - self.KNOWN_RULE_KEYS
                                for key in sorted(unknown_rule_keys):
                                    summary.add_result(ValidationResult(
                                        level='error',
                                        message=f"❌ Unknown key '{key}' in {sg_name} {rule_type}[{i}] — valid keys: {', '.join(sorted(self.KNOWN_RULE_KEYS))}\n   → This key will be ignored. Check spelling.",
                                        rule='schema_unknown_rule_key',
                                        context=f"security_group.{sg_name}.{rule_type}[{i}]"
                                    ))
    
    def _validate_account_id(self, data: Dict[str, Any], summary: ValidationSummary):
        """Validate account ID format and consistency"""
        if 'account_id' not in data:
            return
        
        account_id = str(data['account_id'])
        
        # Must be 12-digit string
        if not re.match(r'^\d{12}$', account_id):
            summary.add_result(ValidationResult(
                level='error',
                message=f"account_id must be a 12-digit string, got '{account_id}'",
                rule='account_id_format'
            ))
        
        # Should match directory name if directory is account ID
        if re.match(r'^\d{12}$', self.account_dir.name) and account_id != self.account_dir.name:
            summary.add_result(ValidationResult(
                level='warning',
                message=f"account_id '{account_id}' doesn't match directory name '{self.account_dir.name}'",
                rule='account_id_consistency'
            ))
    
    def _validate_baseline_profiles(self, data: Dict[str, Any], summary: ValidationSummary):
        """Validate baseline_profiles configuration"""
        if 'baseline_profiles' not in data:
            return  # baseline_profiles is optional
        
        baseline_profiles = data['baseline_profiles']
        
        # Must be a list
        if not isinstance(baseline_profiles, list):
            summary.add_result(ValidationResult(
                level='error',
                message="'baseline_profiles' must be a list",
                rule='baseline_profiles_type'
            ))
            return
        
        # Valid profile names — must match profiles in terraform-aws-eks-baseline-sgs
        valid_profiles = ['vpc-endpoints', 'eks-internet', 'eks-standard']
        
        # Validate each profile name
        for i, profile in enumerate(baseline_profiles):
            if not isinstance(profile, str):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"baseline_profiles[{i}] must be a string, got {type(profile).__name__}",
                    rule='baseline_profile_type'
                ))
                continue
            
            if profile not in valid_profiles:
                message = (f"❌ Baseline profile '{profile}' does not exist. Available profiles: {', '.join(valid_profiles)}\n"
                          f"   → See terraform-aws-eks-baseline-sgs repo for profile details.")
                summary.add_result(ValidationResult(
                    level='error',
                    message=message,
                    rule='baseline_profile_name'
                ))
        
        # Check for duplicates
        if len(baseline_profiles) != len(set(baseline_profiles)):
            duplicates = [p for p in baseline_profiles if baseline_profiles.count(p) > 1]
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Duplicate baseline profiles found: {', '.join(set(duplicates))}",
                rule='baseline_profile_duplicates'
            ))
        
        # Profile dependency checks
        PROFILE_DEPENDENCIES = {
            'eks-standard': ['vpc-endpoints'],
            'eks-internet': ['vpc-endpoints'],
        }
        
        # Mutually exclusive profiles
        MUTUALLY_EXCLUSIVE = [
            {'eks-standard', 'eks-internet'},  # pick one EKS profile, not both
        ]
        
        for exclusive_set in MUTUALLY_EXCLUSIVE:
            conflicts = exclusive_set.intersection(set(baseline_profiles))
            if len(conflicts) > 1:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"❌ Profiles {', '.join(sorted(conflicts))} cannot be used together — pick one EKS profile per account.\n   → Use 'eks-standard' for intranet-only clusters, 'eks-internet' for internet-facing clusters.",
                    rule='baseline_profile_conflict'
                ))
        
        for profile in baseline_profiles:
            if profile in PROFILE_DEPENDENCIES:
                for dep in PROFILE_DEPENDENCIES[profile]:
                    if dep not in baseline_profiles:
                        summary.add_result(ValidationResult(
                            level='info',
                            message=f"ℹ️ Profile '{profile}' requires '{dep}' — it will be auto-deployed by the platform.",
                            rule='baseline_profile_dependency'
                        ))
        
        # Informational message about what's being deployed
        if baseline_profiles:
            # Show what will actually deploy (including auto-deps)
            effective_profiles = set(baseline_profiles)
            for profile in baseline_profiles:
                if profile in PROFILE_DEPENDENCIES:
                    effective_profiles.update(PROFILE_DEPENDENCIES[profile])
            
            summary.add_result(ValidationResult(
                level='info',
                message=f"Will deploy baseline profiles: {', '.join(sorted(effective_profiles))}",
                rule='baseline_profiles_info'
            ))
    
    def _validate_security_groups(self, data: Dict[str, Any], summary: ValidationSummary):
        """Validate individual security groups"""
        if 'security_groups' not in data or not data['security_groups']:
            return
        if not isinstance(data['security_groups'], dict):
            return  # already caught by schema validation
        
        for sg_name, sg_config in data['security_groups'].items():
            self._validate_security_group(sg_name, sg_config, summary)
    
    def _safe_sort_tuple(self, val) -> tuple:
        """Safely convert a field to a sorted tuple for hashing, handling type errors."""
        if isinstance(val, list):
            try:
                return tuple(sorted(str(v) for v in val))
            except TypeError:
                return (str(val),)
        elif val is None:
            return ()
        else:
            return (str(val),)

    def _normalize_rule(self, rule: Dict[str, Any]) -> tuple:
        """Create a hashable representation of a rule for duplicate detection"""
        return (
            rule.get('protocol'),
            rule.get('from_port'),
            rule.get('to_port'),
            self._safe_sort_tuple(rule.get('cidr_blocks', [])),
            self._safe_sort_tuple(rule.get('ipv6_cidr_blocks', [])),
            self._safe_sort_tuple(rule.get('security_groups', [])),
            self._safe_sort_tuple(rule.get('prefix_list_ids', [])),
            rule.get('self', False),
        )

    def _validate_security_group(self, sg_name: str, sg_config: Dict[str, Any], summary: ValidationSummary):
        """Validate a single security group configuration"""
        context = f"security_group.{sg_name}"
        
        if not isinstance(sg_config, dict):
            summary.add_result(ValidationResult(
                level='error',
                message=f"Security group '{sg_name}' must be a dictionary/object, got {type(sg_config).__name__}",
                rule='sg_type',
                context=context
            ))
            return
        
        # Required fields
        if 'description' not in sg_config or not sg_config['description'].strip():
            summary.add_result(ValidationResult(
                level='error',
                message=f"❌ Security group '{sg_name}' must have a non-empty description — descriptions help identify the purpose and scope of the security group.\n   → Add a clear description explaining what this security group protects.",
                rule='sg_required_description',
                context=context
            ))
        
        # Validate ingress rules
        if 'ingress' in sg_config:
            if isinstance(sg_config['ingress'], list):
                if len(sg_config['ingress']) == 0:
                    summary.add_result(ValidationResult(
                        level='warning',
                        message=f"⚠️ Security group '{sg_name}' has an empty ingress list — remove it or add rules.",
                        rule='sg_empty_rules',
                        context=context
                    ))
                else:
                    for i, rule in enumerate(sg_config['ingress']):
                        self._validate_security_group_rule(sg_name, 'ingress', i, rule, summary)
                    self._check_duplicate_rules(sg_name, 'ingress', sg_config['ingress'], summary)
            else:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' ingress must be a list",
                    rule='sg_ingress_type',
                    context=context
                ))
        
        # Validate egress rules
        if 'egress' in sg_config:
            if isinstance(sg_config['egress'], list):
                if len(sg_config['egress']) == 0:
                    summary.add_result(ValidationResult(
                        level='warning',
                        message=f"⚠️ Security group '{sg_name}' has an empty egress list — remove it or add rules.",
                        rule='sg_empty_rules',
                        context=context
                    ))
                else:
                    for i, rule in enumerate(sg_config['egress']):
                        self._validate_security_group_rule(sg_name, 'egress', i, rule, summary)
                    self._check_duplicate_rules(sg_name, 'egress', sg_config['egress'], summary)
            else:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' egress must be a list",
                    rule='sg_egress_type',
                    context=context
                ))
        
        # Check rule count limits
        total_ingress = len(sg_config.get('ingress', []))
        total_egress = len(sg_config.get('egress', []))
        max_ingress = self.guardrails.get('validation', {}).get('rules', {}).get('max_ingress_rules', 60)
        max_egress = self.guardrails.get('validation', {}).get('rules', {}).get('max_egress_rules', 60)
        
        if total_ingress > max_ingress:
            summary.add_result(ValidationResult(
                level='error',
                message=f"❌ Security group '{sg_name}' has {total_ingress} ingress rules, maximum is {max_ingress} — too many rules make security groups hard to manage and can impact performance.\n   → Consolidate similar rules or split into multiple security groups by function.",
                rule='sg_rule_count_limit',
                context=context
            ))
        
        if total_egress > max_egress:
            summary.add_result(ValidationResult(
                level='error',
                message=f"❌ Security group '{sg_name}' has {total_egress} egress rules, maximum is {max_egress} — too many rules make security groups hard to manage and can impact performance.\n   → Consolidate similar rules or split into multiple security groups by function.",
                rule='sg_rule_count_limit',
                context=context
            ))
        
        # Check for required tags
        required_tags = self.guardrails.get('validation', {}).get('naming', {}).get('required_tags', [])
        sg_tags = sg_config.get('tags', {})
        
        for required_tag in required_tags:
            if required_tag not in sg_tags:
                message = (f"❌ Missing required tag '{required_tag}' — all security groups must include corporate mandatory tags for compliance tracking.\n"
                          f"   → Required tags: <company>-app-env, <company>-data-classification, <company>-app-carid, <company>-ops-supportgroup, <company>-app-supportgroup, <company>-provisioner-repo, <company>-iam-access-control, <company>-provisioner-workspace")
                summary.add_result(ValidationResult(
                    level='error',
                    message=message,
                    rule='sg_required_tags',
                    context=context
                ))
    
    def _check_duplicate_rules(self, sg_name: str, rule_type: str, rules: List[Dict[str, Any]], 
                              summary: ValidationSummary):
        """Detect duplicate rules within a security group"""
        seen = {}
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            normalized = self._normalize_rule(rule)
            if normalized in seen:
                first_index = seen[normalized]
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"❌ Duplicate rule: {sg_name} {rule_type}[{i}] is identical to {rule_type}[{first_index}] — AWS will silently dedupe this but it indicates a copy-paste error.\n   → Remove the duplicate rule.",
                    rule='rule_duplicate',
                    context=f"security_group.{sg_name}.{rule_type}[{i}]"
                ))
            else:
                seen[normalized] = i

    def _validate_security_group_rule(self, sg_name: str, rule_type: str, rule_index: int, 
                                    rule: Dict[str, Any], summary: ValidationSummary):
        """Validate a single security group rule"""
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        
        # Required fields for rules
        if 'protocol' not in rule:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Rule in {sg_name} {rule_type}[{rule_index}] is missing 'protocol'",
                rule='rule_required_protocol',
                context=context
            ))
            return
        
        protocol = rule['protocol']
        
        # Validate protocol
        valid_protocols = ['tcp', 'udp', 'icmp', 'icmpv6', 'ah', 'esp', 'gre', 'all', '-1']
        if protocol not in valid_protocols:
            # Check if it's a protocol number
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
        
        # Validate ports for TCP/UDP
        if protocol in ['tcp', 'udp']:
            self._validate_port_range(sg_name, rule_type, rule_index, rule, summary)
        
        # Validate CIDR blocks, security groups, and prefix lists
        self._validate_rule_sources(sg_name, rule_type, rule_index, rule, summary)
    
    def _validate_port_range(self, sg_name: str, rule_type: str, rule_index: int, 
                            rule: Dict[str, Any], summary: ValidationSummary):
        """Validate port ranges in security group rules"""
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        
        from_port = rule.get('from_port')
        to_port = rule.get('to_port')
        
        # Check if ports are required
        if from_port is None or to_port is None:
            summary.add_result(ValidationResult(
                level='error',
                message=f"TCP/UDP rule in {sg_name} {rule_type}[{rule_index}] requires 'from_port' and 'to_port'",
                rule='rule_required_ports',
                context=context
            ))
            return
        
        # Validate port numbers
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
            except (ValueError, TypeError):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Invalid {port_field} '{port_value}' in {sg_name} {rule_type}[{rule_index}] (must be a number)",
                    rule='rule_invalid_port_type',
                    context=context
                ))
                return
        
        from_port = int(from_port)
        to_port = int(to_port)
        
        # Validate port range
        if from_port > to_port:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Invalid port range in {sg_name} {rule_type}[{rule_index}]: from_port ({from_port}) > to_port ({to_port})",
                rule='rule_invalid_port_range',
                context=context
            ))
            return
        
        # Check port range size limits
        port_range_size = to_port - from_port + 1
        max_range_size = self.guardrails.get('validation', {}).get('port_ranges', {}).get('max_range_size', 1000)
        
        if port_range_size > max_range_size:
            message = (f"❌ Port range {from_port}-{to_port} is too broad ({port_range_size} ports, max {max_range_size}) — this effectively opens all ports.\n"
                      f"   → Narrow to specific ports your application needs (e.g., 443, 8080).\n"
                      f"   → If this is for EKS node communication, set type: \"eks-nodes\" to allow ephemeral ranges.")
            summary.add_result(ValidationResult(
                level='error',
                message=message,
                rule='rule_port_range_too_large',
                context=context
            ))
        
        # Check for blocked ports
        blocked_ports = self.guardrails.get('validation', {}).get('blocked_ports', [])
        for port in range(from_port, to_port + 1):
            if port in blocked_ports:
                port_desc = self._get_port_description(port)
                if port in [135, 139]:
                    reason = "commonly exploited for lateral movement attacks. Not needed for cloud workloads"
                    suggestion = "Remove this rule. If you need Windows RPC, contact the security team."
                elif port == 23:
                    reason = "transmits data in plain text, easily intercepted by attackers"
                    suggestion = "Use SSH (port 22) or AWS Systems Manager Session Manager instead."
                elif port == 3389:
                    reason = "commonly brute-forced and vulnerable to exploits"
                    suggestion = "Use AWS Systems Manager Session Manager for Windows access."
                elif port in [21, 25]:
                    reason = "insecure protocols that transmit credentials in plain text"
                    suggestion = "Use secure alternatives (SFTP, encrypted email protocols)."
                else:
                    reason = "blocked for security reasons"
                    suggestion = "Remove this rule or contact the security team if required."
                
                message = (f"❌ Port {port_desc} is blocked — {reason}.\n"
                          f"   → {suggestion}")
                summary.add_result(ValidationResult(
                    level='error',
                    message=message,
                    rule='rule_blocked_port',
                    context=context
                ))
        
        # High-signal security warnings — only patterns that are genuinely risky
        cidr_list = rule.get('cidr_blocks', [])
        if not isinstance(cidr_list, list):
            cidr_list = [cidr_list] if isinstance(cidr_list, str) else []
        has_cidr_source = bool(cidr_list)
        has_broad_cidr = any(c in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] for c in cidr_list)
        
        # 1. SSH/RDP from a CIDR range (from a SG is fine)
        if rule_type == 'ingress' and has_cidr_source:
            if from_port <= 22 <= to_port:
                summary.add_result(ValidationResult(
                    level='warning',
                    message=f"⚠️ HIGH: SSH (port 22) ingress from CIDR — any host in that range gets SSH access. PCI DSS Req 1.3.2",
                    rule='high_risk_pattern',
                    context=context
                ))
            if from_port <= 3389 <= to_port:
                summary.add_result(ValidationResult(
                    level='warning',
                    message=f"⚠️ HIGH: RDP (port 3389) ingress from CIDR — any host in that range gets RDP access. PCI DSS Req 1.3.2",
                    rule='high_risk_pattern',
                    context=context
                ))
        
        # 2. Database ports from a CIDR range
        db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 27017: 'MongoDB', 6379: 'Redis'}
        if rule_type == 'ingress' and has_cidr_source:
            for db_port, db_name in db_ports.items():
                if from_port <= db_port <= to_port:
                    summary.add_result(ValidationResult(
                        level='warning',
                        message=f"⚠️ HIGH: {db_name} (port {db_port}) ingress from CIDR — CIDR-based database access is a common audit finding. PCI DSS Req 1.3.1",
                        rule='high_risk_pattern',
                        context=context
                    ))
        
        # 3. Broad internal CIDR (10.0.0.0/8 etc.)
        if rule_type == 'ingress' and has_broad_cidr:
            summary.add_result(ValidationResult(
                level='warning',
                message=f"⚠️ MEDIUM: Ingress from overly broad internal CIDR (e.g. 10.0.0.0/8) — scope to specific VPC or subnet CIDRs. PCI DSS Req 1.2.1",
                rule='broad_cidr_pattern',
                context=context
            ))
    
    def _validate_rule_sources(self, sg_name: str, rule_type: str, rule_index: int, 
                             rule: Dict[str, Any], summary: ValidationSummary):
        """Validate CIDR blocks, security groups, and prefix lists in rules"""
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        
        # Check for at least one source/destination
        source_fields = ['cidr_blocks', 'ipv6_cidr_blocks', 'security_groups', 'self', 'prefix_list_ids']
        has_source = any(field in rule for field in source_fields)
        
        if not has_source:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Rule in {sg_name} {rule_type}[{rule_index}] must specify at least one source/destination",
                rule='rule_missing_source',
                context=context
            ))
            return
        
        # Validate CIDR blocks
        for cidr_field in ['cidr_blocks', 'ipv6_cidr_blocks']:
            if cidr_field in rule:
                is_ipv6 = cidr_field == 'ipv6_cidr_blocks'
                cidr_value = rule[cidr_field]
                
                # Type check — must be a list
                if isinstance(cidr_value, str):
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"❌ '{cidr_field}' in {sg_name} {rule_type}[{rule_index}] must be a list, not a bare string.\n   → Change: {cidr_field}: \"{cidr_value}\"\n   → To:     {cidr_field}: [\"{cidr_value}\"]",
                        rule='rule_cidr_type',
                        context=context
                    ))
                    # Still validate the single CIDR so they get useful feedback
                    self._validate_cidr_block(sg_name, rule_type, rule_index, cidr_value, is_ipv6, summary, rule)
                elif not isinstance(cidr_value, list):
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"'{cidr_field}' in {sg_name} {rule_type}[{rule_index}] must be a list, got {type(cidr_value).__name__}",
                        rule='rule_cidr_type',
                        context=context
                    ))
                else:
                    for cidr in cidr_value:
                        if not isinstance(cidr, str):
                            summary.add_result(ValidationResult(
                                level='error',
                                message=f"CIDR block in {sg_name} {rule_type}[{rule_index}] must be a string, got {type(cidr).__name__}: {cidr}",
                                rule='rule_cidr_item_type',
                                context=context
                            ))
                        else:
                            self._validate_cidr_block(sg_name, rule_type, rule_index, cidr, is_ipv6, summary, rule)
        
        # Validate 'self' field
        if 'self' in rule:
            if not isinstance(rule['self'], bool):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"'self' in {sg_name} {rule_type}[{rule_index}] must be true or false, got \"{rule['self']}\"",
                    rule='rule_self_type',
                    context=context
                ))
        
        # Validate security group references
        if 'security_groups' in rule:
            if not isinstance(rule['security_groups'], list):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"'security_groups' in {sg_name} {rule_type}[{rule_index}] must be a list",
                    rule='rule_sg_ref_type',
                    context=context
                ))
            else:
                for sg_ref in rule['security_groups']:
                    self._validate_security_group_reference(sg_name, rule_type, rule_index, sg_ref, summary)
        
        # Validate prefix list references
        if 'prefix_list_ids' in rule:
            if not isinstance(rule['prefix_list_ids'], list):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"'prefix_list_ids' in {sg_name} {rule_type}[{rule_index}] must be a list",
                    rule='rule_prefix_list_type',
                    context=context
                ))
            else:
                for prefix_list_id in rule['prefix_list_ids']:
                    self._validate_prefix_list_reference(sg_name, rule_type, rule_index, prefix_list_id, summary)
    
    def _validate_cidr_block(self, sg_name: str, rule_type: str, rule_index: int, 
                           cidr: str, is_ipv6: bool, summary: ValidationSummary, rule: Dict[str, Any] = None):
        """Validate a CIDR block"""
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        
        # Validate CIDR format
        try:
            if is_ipv6:
                network = ipaddress.IPv6Network(cidr, strict=False)
            else:
                network = ipaddress.IPv4Network(cidr, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Invalid CIDR block '{cidr}' in {sg_name} {rule_type}[{rule_index}]: {e}",
                rule='rule_invalid_cidr',
                context=context
            ))
            return
        
        # Check against blocked CIDRs
        blocked_cidrs = self.guardrails.get('validation', {}).get('blocked_cidrs', [])
        if cidr in blocked_cidrs:
            if rule_type == 'ingress':
                message = (f"❌ {cidr} ingress is not allowed — this opens the port to the entire internet.\n"
                          f"   → Use a specific CIDR, security group reference, or prefix list instead.\n"
                          f"   → Example: prefix_list_ids: [\"corporate-networks\"]")
            else:
                message = (f"❌ {cidr} egress detected — unrestricted outbound access. Consider scoping to specific CIDRs or prefix lists.\n"
                          f"   → Use security group references or prefix_list_ids: [\"corporate-networks\"]")
            
            summary.add_result(ValidationResult(
                level='error',
                message=message,
                rule='rule_blocked_cidr',
                context=context
            ))
        
        # Special handling for 0.0.0.0/0 and ::/0
        if (not is_ipv6 and cidr == '0.0.0.0/0') or (is_ipv6 and cidr == '::/0'):
            # Check if this is allowed for this security group type
            sg_type = self._get_security_group_type(sg_name)
            type_overrides = self.guardrails.get('type_overrides', {}).get(sg_type, {})
            
            if 'required_egress' in type_overrides and rule_type == 'egress':
                # Check if this matches a required egress rule
                for required_rule in type_overrides['required_egress']:
                    if required_rule.get('cidr_blocks', []) == ['0.0.0.0/0']:
                        # This is an allowed exception
                        return
            
            if rule_type == 'ingress':
                message = (f"❌ {cidr} ingress is not allowed — this opens the port to the entire internet.\n"
                          f"   → Use a specific CIDR, security group reference, or prefix list instead.\n"
                          f"   → Example: prefix_list_ids: [\"corporate-networks\"]")
                summary.add_result(ValidationResult(
                    level='error',
                    message=message,
                    rule='rule_open_internet',
                    context=context
                ))
            elif rule_type == 'egress':
                r_from = rule.get('from_port', 0) if rule else 0
                r_to = rule.get('to_port', 0) if rule else 0
                if r_from == 443 and r_to == 443:
                    return  # HTTPS egress to internet is normal
                # Non-443 egress to 0.0.0.0/0 is worth flagging
                port_display = f"port {r_from}" if r_from == r_to else f"ports {r_from}-{r_to}"
                message = (f"⚠️ MEDIUM: Egress to {cidr} on {port_display} — unrestricted non-HTTPS outbound. PCI DSS Req 1.3.4")
                summary.add_result(ValidationResult(
                    level='warning',
                    message=message,
                    rule='rule_open_egress',
                    context=context
                ))
    
    def _validate_security_group_reference(self, sg_name: str, rule_type: str, rule_index: int, 
                                         sg_ref: str, summary: ValidationSummary):
        """Validate security group reference"""
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        
        # Should be either a security group ID (sg-xxxxxxxx) or a name reference
        if not (sg_ref.startswith('sg-') or sg_ref.isalnum() or '-' in sg_ref):
            summary.add_result(ValidationResult(
                level='warning',
                message=f"Security group reference '{sg_ref}' in {sg_name} {rule_type}[{rule_index}] may be invalid",
                rule='rule_sg_reference_format',
                context=context
            ))
    
    def _validate_prefix_list_reference(self, sg_name: str, rule_type: str, rule_index: int, 
                                      prefix_list_id: str, summary: ValidationSummary):
        """Validate prefix list reference"""
        context = f"security_group.{sg_name}.{rule_type}[{rule_index}]"
        
        # Check if it's a managed prefix list ID or a name from our config
        if prefix_list_id.startswith('pl-'):
            # AWS managed prefix list ID
            summary.add_result(ValidationResult(
                level='info',
                message=f"Using AWS managed prefix list '{prefix_list_id}' in {sg_name} {rule_type}[{rule_index}]",
                rule='rule_aws_prefix_list',
                context=context
            ))
        else:
            # Should be defined in our prefix-lists.yaml
            if prefix_list_id not in self.prefix_lists.get('prefix_lists', {}):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Undefined prefix list '{prefix_list_id}' in {sg_name} {rule_type}[{rule_index}]",
                    rule='rule_undefined_prefix_list',
                    context=context
                ))
    
    def _validate_guardrails(self, data: Dict[str, Any], summary: ValidationSummary):
        """Apply type-specific guardrail overrides"""
        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return
        
        for sg_name, sg_config in data['security_groups'].items():
            sg_type = self._get_security_group_type(sg_name)
            self._apply_type_specific_validation(sg_name, sg_config, sg_type, summary)
    
    def _get_security_group_type(self, sg_name: str) -> str:
        """Determine security group type from name patterns"""
        sg_name_lower = sg_name.lower()
        
        if 'eks' in sg_name_lower and 'node' in sg_name_lower:
            return 'eks-nodes'
        elif 'nlb' in sg_name_lower or 'network-lb' in sg_name_lower:
            return 'nlb'
        elif 'web' in sg_name_lower or 'http' in sg_name_lower:
            return 'web'
        elif 'alb' in sg_name_lower or 'application-lb' in sg_name_lower:
            return 'alb'
        elif 'rds' in sg_name_lower or 'database' in sg_name_lower or 'db' in sg_name_lower:
            return 'database'
        else:
            return 'general'
    
    def _apply_type_specific_validation(self, sg_name: str, sg_config: Dict[str, Any], 
                                      sg_type: str, summary: ValidationSummary):
        """Apply type-specific validation rules"""
        type_overrides = self.guardrails.get('type_overrides', {}).get(sg_type, {})
        context = f"security_group.{sg_name}"
        
        # Check allowed protocols
        if 'allowed_protocols' in type_overrides:
            allowed_protocols = type_overrides['allowed_protocols']
            
            for rule_type in ['ingress', 'egress']:
                if rule_type in sg_config:
                    for i, rule in enumerate(sg_config[rule_type]):
                        protocol = rule.get('protocol')
                        if protocol and protocol not in allowed_protocols:
                            summary.add_result(ValidationResult(
                                level='error',
                                message=f"Protocol '{protocol}' not allowed for {sg_type} type in {sg_name} {rule_type}[{i}]",
                                rule='type_protocol_restriction',
                                context=context
                            ))
        
        # Check required egress rules (e.g., for EKS nodes)
        if 'required_egress' in type_overrides:
            required_rules = type_overrides['required_egress']
            egress_rules = sg_config.get('egress', [])
            
            # Removed: "missing recommended rule" warnings — teams define their own egress.
            # Re-enable if org wants to enforce mandatory egress patterns per SG type.
            pass
        
        # Check rule count overrides
        if 'max_rules' in type_overrides:
            total_rules = len(sg_config.get('ingress', [])) + len(sg_config.get('egress', []))
            if total_rules > type_overrides['max_rules']:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group '{sg_name}' has {total_rules} rules, maximum for {sg_type} is {type_overrides['max_rules']}",
                    rule='type_rule_count_override',
                    context=context
                ))
    
    def _has_matching_rule(self, rules: List[Dict[str, Any]], required_rule: Dict[str, Any]) -> bool:
        """Check if a required rule exists in the rule list"""
        for rule in rules:
            if (rule.get('protocol') == required_rule.get('protocol') and
                rule.get('from_port') == required_rule.get('from_port') and
                rule.get('to_port') == required_rule.get('to_port') and
                rule.get('cidr_blocks') == required_rule.get('cidr_blocks')):
                return True
        return False
    
    def _validate_naming_conventions(self, data: Dict[str, Any], summary: ValidationSummary):
        """Validate naming conventions for security groups"""
        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return
        
        naming_config = self.guardrails.get('validation', {}).get('naming', {})
        sg_pattern = naming_config.get('security_group_pattern', r'^[a-z0-9][a-z0-9-]*[a-z0-9]$')
        max_length = naming_config.get('max_name_length', 63)
        
        for sg_name in data['security_groups']:
            # Check pattern
            if not re.match(sg_pattern, sg_name):
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group name '{sg_name}' doesn't match required pattern: {sg_pattern}",
                    rule='naming_pattern_violation',
                    context=f"security_group.{sg_name}"
                ))
            
            # Check length
            if len(sg_name) > max_length:
                summary.add_result(ValidationResult(
                    level='error',
                    message=f"Security group name '{sg_name}' is too long ({len(sg_name)} chars, max {max_length})",
                    rule='naming_length_violation',
                    context=f"security_group.{sg_name}"
                ))
            
            # Check for reserved words/patterns
            reserved_patterns = ['default', 'baseline', 'aws-', 'amazon-']
            for pattern in reserved_patterns:
                if sg_name.startswith(pattern):
                    summary.add_result(ValidationResult(
                        level='warning',
                        message=f"Security group name '{sg_name}' starts with reserved pattern '{pattern}'",
                        rule='naming_reserved_pattern',
                        context=f"security_group.{sg_name}"
                    ))
    

    def _validate_unicode_characters(self, data: Dict[str, Any], summary: ValidationSummary):
        """Validate that all string fields contain only ASCII-printable characters.
        
        Non-ASCII characters (unicode, emoji, zero-width chars, homoglyphs) in security
        group names, descriptions, tags, and CIDR values can cause TFE/Terraform errors
        or create confusing/misleading configurations.
        """
        import string
        PRINTABLE = set(string.printable)
        
        def check_ascii(value: str, field_path: str):
            """Check a string value for non-ASCII/non-printable characters."""
            for i, ch in enumerate(value):
                if ch not in PRINTABLE:
                    # Get a readable representation of the offending character
                    char_repr = repr(ch)
                    cp = ord(ch)
                    summary.add_result(ValidationResult(
                        level='error',
                        message=f"Non-ASCII character {char_repr} (U+{cp:04X}) found in {field_path} at position {i} — only ASCII-printable characters are allowed. Non-ASCII characters cause TFE/Terraform errors.",
                        rule='unicode_character',
                        context=field_path
                    ))
                    return  # One error per field is enough
        
        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return
        
        for sg_name, sg_config in data['security_groups'].items():
            # Check SG name
            check_ascii(sg_name, f"security_group.{sg_name}.name")
            
            if not isinstance(sg_config, dict):
                continue
            
            # Check description
            if 'description' in sg_config and isinstance(sg_config['description'], str):
                check_ascii(sg_config['description'], f"security_group.{sg_name}.description")
            
            # Check tags
            if 'tags' in sg_config and isinstance(sg_config['tags'], dict):
                for tag_key, tag_value in sg_config['tags'].items():
                    if isinstance(tag_key, str):
                        check_ascii(tag_key, f"security_group.{sg_name}.tags.key.{tag_key}")
                    if isinstance(tag_value, str):
                        check_ascii(tag_value, f"security_group.{sg_name}.tags.value.{tag_key}")
            
            # Check rules
            for rule_type in ['ingress', 'egress']:
                if rule_type not in sg_config or not isinstance(sg_config[rule_type], list):
                    continue
                for i, rule in enumerate(sg_config[rule_type]):
                    if not isinstance(rule, dict):
                        continue
                    # Check rule description
                    if 'description' in rule and isinstance(rule['description'], str):
                        check_ascii(rule['description'], f"security_group.{sg_name}.{rule_type}[{i}].description")
                    # Check CIDR blocks
                    for cidr_field in ['cidr_blocks', 'ipv6_cidr_blocks']:
                        if cidr_field in rule and isinstance(rule[cidr_field], list):
                            for j, cidr in enumerate(rule[cidr_field]):
                                if isinstance(cidr, str):
                                    check_ascii(cidr, f"security_group.{sg_name}.{rule_type}[{i}].{cidr_field}[{j}]")

    def _validate_prefix_list_references(self, data: Dict[str, Any], summary: ValidationSummary):
        """Validate that all referenced prefix lists are defined"""
        if 'security_groups' not in data or not isinstance(data['security_groups'], dict):
            return
        
        referenced_prefix_lists = set()
        
        for sg_name, sg_config in data['security_groups'].items():
            for rule_type in ['ingress', 'egress']:
                if rule_type in sg_config:
                    for rule in sg_config[rule_type]:
                        if 'prefix_list_ids' in rule:
                            for prefix_list_id in rule['prefix_list_ids']:
                                if not prefix_list_id.startswith('pl-'):
                                    referenced_prefix_lists.add(prefix_list_id)
        
        # Check that all referenced prefix lists are defined
        defined_prefix_lists = set(self.prefix_lists.get('prefix_lists', {}).keys())
        undefined_prefix_lists = referenced_prefix_lists - defined_prefix_lists
        
        for prefix_list in undefined_prefix_lists:
            summary.add_result(ValidationResult(
                level='error',
                message=f"Referenced prefix list '{prefix_list}' is not defined in prefix-lists.yaml",
                rule='undefined_prefix_list_reference'
            ))
    
    def format_markdown_output(self, summary: ValidationSummary) -> str:
        """Format validation results as markdown for PR comments"""
        output = []
        
        # Header with summary
        error_count = len(summary.errors)
        warning_count = len(summary.warnings)
        
        if error_count == 0 and warning_count == 0:
            output.append("## ✅ Security Group Validation Results")
            output.append(f"**Account:** {self.account_id} | **Status:** All checks passed!")
            return "\n\n".join(output)
        
        output.append("## 🔍 Security Group Validation Results")
        output.append(f"**Account:** {self.account_id} | **Errors:** {error_count} | **Warnings:** {warning_count}")
        output.append("")
        
        # Categorize results: tags, schema/global, and per-SG rule issues
        tag_results = {'errors': [], 'warnings': []}
        schema_results = {'errors': [], 'warnings': []}
        sg_results = {}
        
        # Tag and schema rule names
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
        
        # Helper to render a dropdown section
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
                    message = error.message
                    if message.startswith('❌'):
                        message = message[1:].strip()
                    output.append(f"- ❌ {message}")
                output.append("")
            if results['warnings']:
                output.append("### Warnings")
                for warning in results['warnings']:
                    message = warning.message
                    if message.startswith('⚠️'):
                        message = message[2:].strip()
                    output.append(f"- ⚠️ {message}")
                output.append("")
            output.append("</details>")
            output.append("")
        
        # 1. Schema/config issues
        s_e = len(schema_results['errors'])
        s_w = len(schema_results['warnings'])
        if s_e or s_w:
            _render_section(f"⚙️ Configuration Issues — {s_e} errors, {s_w} warnings", schema_results)
        
        # 2. Tag compliance
        t_e = len(tag_results['errors'])
        t_w = len(tag_results['warnings'])
        if t_e or t_w:
            _render_section(f"🏷️ Tag Compliance — {t_e} errors, {t_w} warnings", tag_results)
        
        # 3. Per-SG rule issues
        for sg_name, results in sg_results.items():
            sg_e = len(results['errors'])
            sg_w = len(results['warnings'])
            if sg_e == 0 and sg_w == 0:
                continue
            emoji = "❌" if sg_e > 0 else "⚠️"
            _render_section(f"{emoji} {sg_name} — {sg_e} errors, {sg_w} warnings", results)
        
        return "\n".join(output)


def main():
    """Main entry point"""
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
    
    parser.add_argument(
        'account_dir',
        help='Path to the account directory containing security-groups.yaml'
    )
    
    parser.add_argument(
        '--format',
        choices=['text', 'json', 'markdown'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Include info-level messages in output'
    )
    
    parser.add_argument(
        '--warnings-as-errors',
        action='store_true',
        help='Treat warnings as errors'
    )
    
    parser.add_argument(
        '--no-warnings',
        action='store_true',
        help='Suppress warning output (only show errors)'
    )
    
    args = parser.parse_args()
    
    try:
        validator = SecurityGroupValidator(args.account_dir)
        summary = validator.validate()
        
        # Suppress warnings if requested
        if args.no_warnings:
            summary.warnings = []
        
        # Adjust exit code if warnings should be treated as errors
        if args.warnings_as_errors and summary.has_warnings and not summary.has_errors:
            # Convert warnings to errors
            summary.errors.extend(summary.warnings)
            summary.warnings = []
        
        # Output results
        if args.format == 'markdown':
            print(validator.format_markdown_output(summary))
        elif args.format == 'json':
            output = {
                'account_dir': args.account_dir,
                'account_id': validator.account_id,
                'validation_results': {
                    'errors': [
                        {
                            'level': r.level,
                            'message': r.message,
                            'rule': r.rule,
                            'context': r.context,
                            'line': r.line
                        } for r in summary.errors
                    ],
                    'warnings': [
                        {
                            'level': r.level,
                            'message': r.message,
                            'rule': r.rule,
                            'context': r.context,
                            'line': r.line
                        } for r in summary.warnings
                    ],
                    'info': [
                        {
                            'level': r.level,
                            'message': r.message,
                            'rule': r.rule,
                            'context': r.context,
                            'line': r.line
                        } for r in summary.info
                    ] if args.verbose else []
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
            # Text output
            print(f"🔍 Validating AWS Security Groups for account: {validator.account_id}")
            print(f"📁 Directory: {args.account_dir}")
            print()
            
            # Print errors
            if summary.errors:
                print("❌ Errors:")
                for error in summary.errors:
                    context_str = f" [{error.context}]" if error.context else ""
                    rule_str = f" ({error.rule})" if error.rule else ""
                    print(f"   • {error.message}{context_str}{rule_str}")
                print()
            
            # Print warnings
            if summary.warnings:
                print("⚠️  Warnings:")
                for warning in summary.warnings:
                    context_str = f" [{warning.context}]" if warning.context else ""
                    rule_str = f" ({warning.rule})" if warning.rule else ""
                    print(f"   • {warning.message}{context_str}{rule_str}")
                print()
            
            # Print info if verbose
            if args.verbose and summary.info:
                print("ℹ️  Info:")
                for info in summary.info:
                    context_str = f" [{info.context}]" if info.context else ""
                    rule_str = f" ({info.rule})" if info.rule else ""
                    print(f"   • {info.message}{context_str}{rule_str}")
                print()
            
            # Summary
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