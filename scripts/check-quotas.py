#!/usr/bin/env python3
"""
AWS Security Group Platform - Quota Checker

Pre-checks AWS quota limits for security groups before deployment to prevent failures.
Warns when approaching limits (80% utilization).

Usage:
    python check-quotas.py <account_id> [--region region] [--vpc-id vpc-id]

Exit codes:
    0 - All quota checks passed
    1 - Quota limits would be exceeded
    2 - Warning: approaching quota limits (80%+)
"""

import sys
import os
import boto3
import argparse
import json
import yaml
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from dataclasses import dataclass
from botocore.exceptions import ClientError, NoCredentialsError


@dataclass
class QuotaResult:
    """Represents the result of a quota check"""
    service: str
    quota_name: str
    current_usage: int
    proposed_usage: int
    quota_limit: int
    utilization_percent: float
    level: str  # 'ok', 'warning', 'error'
    message: str


class QuotaChecker:
    """AWS Quota checker for Security Groups"""
    
    def __init__(self, account_id: str, region: str = None, vpc_id: str = None):
        self.account_id = account_id
        self.region = region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        self.vpc_id = vpc_id
        
        # Initialize AWS clients
        try:
            self.ec2_client = boto3.client('ec2', region_name=self.region)
            self.servicequotas_client = boto3.client('service-quotas', region_name=self.region)
        except NoCredentialsError:
            raise Exception("AWS credentials not configured. Please configure AWS CLI or environment variables.")
        
        # Load guardrails for quota limits
        self.guardrails = self._load_guardrails()
        
        # Default quota limits (AWS defaults)
        self.default_quotas = {
            'security_groups_per_vpc': 2500,
            'rules_per_security_group': 120,  # 60 inbound + 60 outbound
            'security_groups_per_account': 10000,
        }
    
    def _load_guardrails(self) -> Dict[str, Any]:
        """Load guardrails configuration for quota limits"""
        try:
            # Find repo root
            current = Path.cwd()
            while current != current.parent:
                guardrails_path = current / "guardrails.yaml"
                if guardrails_path.exists():
                    with open(guardrails_path, 'r') as f:
                        return yaml.safe_load(f)
                current = current.parent
            
            # Fallback to default empty config
            return {"quotas": {}}
        except Exception:
            return {"quotas": {}}
    
    def get_service_quota(self, service_code: str, quota_code: str) -> Optional[int]:
        """Get service quota from AWS Service Quotas API"""
        try:
            response = self.servicequotas_client.get_service_quota(
                ServiceCode=service_code,
                QuotaCode=quota_code
            )
            return int(response['Quota']['Value'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchResourceException':
                return None
            raise
    
    def get_current_vpc_usage(self, vpc_id: str) -> Dict[str, int]:
        """Get current security group usage for a specific VPC"""
        try:
            # Get security groups in the VPC
            response = self.ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ]
            )
            
            security_groups = response['SecurityGroups']
            total_sgs = len(security_groups)
            total_rules = 0
            max_rules_per_sg = 0
            
            # Count rules in each security group
            for sg in security_groups:
                sg_rules = len(sg.get('IpPermissions', [])) + len(sg.get('IpPermissionsEgress', []))
                total_rules += sg_rules
                max_rules_per_sg = max(max_rules_per_sg, sg_rules)
            
            return {
                'security_groups': total_sgs,
                'total_rules': total_rules,
                'max_rules_per_sg': max_rules_per_sg
            }
            
        except ClientError as e:
            raise Exception(f"Failed to get VPC usage: {e}")
    
    def get_account_usage(self) -> Dict[str, int]:
        """Get current security group usage for the entire account"""
        try:
            # Get all security groups in the account/region
            paginator = self.ec2_client.get_paginator('describe_security_groups')
            
            total_sgs = 0
            total_rules = 0
            
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    total_sgs += 1
                    sg_rules = len(sg.get('IpPermissions', [])) + len(sg.get('IpPermissionsEgress', []))
                    total_rules += sg_rules
            
            return {
                'security_groups': total_sgs,
                'total_rules': total_rules
            }
            
        except ClientError as e:
            raise Exception(f"Failed to get account usage: {e}")
    
    def discover_vpcs(self) -> List[Dict[str, str]]:
        """Discover VPCs in the account"""
        try:
            response = self.ec2_client.describe_vpcs()
            vpcs = []
            
            for vpc in response['Vpcs']:
                vpc_info = {
                    'VpcId': vpc['VpcId'],
                    'CidrBlock': vpc['CidrBlock'],
                    'State': vpc['State'],
                    'IsDefault': vpc.get('IsDefault', False)
                }
                
                # Add Name tag if available
                for tag in vpc.get('Tags', []):
                    if tag['Key'] == 'Name':
                        vpc_info['Name'] = tag['Value']
                        break
                
                if vpc['State'] == 'available':
                    vpcs.append(vpc_info)
            
            return vpcs
            
        except ClientError as e:
            raise Exception(f"Failed to discover VPCs: {e}")
    
    def load_proposed_changes(self) -> Dict[str, Any]:
        """Load proposed security group changes from account directory"""
        account_dir = Path(f"accounts/{self.account_id}")
        sg_file = account_dir / "security-groups.yaml"
        
        if not sg_file.exists():
            return {'security_groups': {}}
        
        try:
            with open(sg_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise Exception(f"Failed to load proposed changes: {e}")
    
    def calculate_proposed_usage(self, proposed_config: Dict[str, Any]) -> Dict[str, int]:
        """Calculate resource usage from proposed configuration"""
        security_groups = proposed_config.get('security_groups', {})
        
        proposed_sgs = len(security_groups)
        proposed_rules = 0
        max_rules_per_sg = 0
        
        for sg_name, sg_config in security_groups.items():
            sg_rules = len(sg_config.get('ingress', [])) + len(sg_config.get('egress', []))
            proposed_rules += sg_rules
            max_rules_per_sg = max(max_rules_per_sg, sg_rules)
        
        return {
            'security_groups': proposed_sgs,
            'total_rules': proposed_rules,
            'max_rules_per_sg': max_rules_per_sg
        }
    
    def check_quotas(self, target_vpc_id: str = None) -> List[QuotaResult]:
        """Main quota checking logic"""
        results = []
        
        # Load proposed changes
        proposed_config = self.load_proposed_changes()
        proposed_usage = self.calculate_proposed_usage(proposed_config)
        
        if not proposed_usage['security_groups']:
            # No changes proposed
            return [QuotaResult(
                service='ec2',
                quota_name='No Changes',
                current_usage=0,
                proposed_usage=0,
                quota_limit=0,
                utilization_percent=0,
                level='ok',
                message='No security group changes proposed'
            )]
        
        # Determine which VPCs to check
        vpcs_to_check = []
        if target_vpc_id:
            vpcs_to_check = [target_vpc_id]
        elif self.vpc_id:
            vpcs_to_check = [self.vpc_id]
        else:
            # Check all VPCs
            discovered_vpcs = self.discover_vpcs()
            vpcs_to_check = [vpc['VpcId'] for vpc in discovered_vpcs]
        
        # Check quotas for each VPC
        for vpc_id in vpcs_to_check:
            results.extend(self._check_vpc_quotas(vpc_id, proposed_usage))
        
        # Check account-level quotas
        results.extend(self._check_account_quotas(proposed_usage))
        
        return results
    
    def _check_vpc_quotas(self, vpc_id: str, proposed_usage: Dict[str, int]) -> List[QuotaResult]:
        """Check quotas specific to a VPC"""
        results = []
        
        # Get current VPC usage
        current_usage = self.get_current_vpc_usage(vpc_id)
        
        # Get quota limits
        quota_limits = self.guardrails.get('quotas', {})
        sg_per_vpc_limit = quota_limits.get('security_groups_per_vpc', self.default_quotas['security_groups_per_vpc'])
        
        # Try to get from Service Quotas API
        try:
            api_limit = self.get_service_quota('ec2', 'L-E79EC296')  # VPC security groups per VPC
            if api_limit:
                sg_per_vpc_limit = api_limit
        except Exception:
            pass  # Use default
        
        # Check security groups per VPC
        new_usage = current_usage['security_groups'] + proposed_usage['security_groups']
        utilization = (new_usage / sg_per_vpc_limit) * 100
        
        if new_usage > sg_per_vpc_limit:
            level = 'error'
            message = f"Would exceed security groups per VPC limit in {vpc_id}"
        elif utilization >= 80:
            level = 'warning'
            message = f"Approaching security groups per VPC limit in {vpc_id} ({utilization:.1f}%)"
        else:
            level = 'ok'
            message = f"Security groups per VPC usage in {vpc_id} is within limits"
        
        results.append(QuotaResult(
            service='ec2',
            quota_name=f'Security Groups per VPC ({vpc_id})',
            current_usage=current_usage['security_groups'],
            proposed_usage=new_usage,
            quota_limit=sg_per_vpc_limit,
            utilization_percent=utilization,
            level=level,
            message=message
        ))
        
        # Check rules per security group (check the largest proposed SG)
        if proposed_usage['max_rules_per_sg'] > 0:
            rules_per_sg_limit = quota_limits.get('rules_per_security_group', self.default_quotas['rules_per_security_group'])
            
            # Try to get from Service Quotas API
            try:
                api_limit = self.get_service_quota('ec2', 'L-0EA8095F')  # Rules per security group
                if api_limit:
                    rules_per_sg_limit = api_limit
            except Exception:
                pass  # Use default
            
            max_proposed_rules = proposed_usage['max_rules_per_sg']
            utilization = (max_proposed_rules / rules_per_sg_limit) * 100
            
            if max_proposed_rules > rules_per_sg_limit:
                level = 'error'
                message = f"Proposed security group would exceed rules per SG limit ({max_proposed_rules} > {rules_per_sg_limit})"
            elif utilization >= 80:
                level = 'warning'
                message = f"Largest proposed security group approaches rules per SG limit ({utilization:.1f}%)"
            else:
                level = 'ok'
                message = f"Rules per security group usage is within limits"
            
            results.append(QuotaResult(
                service='ec2',
                quota_name='Rules per Security Group',
                current_usage=0,  # N/A for individual SGs
                proposed_usage=max_proposed_rules,
                quota_limit=rules_per_sg_limit,
                utilization_percent=utilization,
                level=level,
                message=message
            ))
        
        return results
    
    def _check_account_quotas(self, proposed_usage: Dict[str, int]) -> List[QuotaResult]:
        """Check account-level quotas"""
        results = []
        
        # Get current account usage
        account_usage = self.get_account_usage()
        
        # Get quota limits
        quota_limits = self.guardrails.get('quotas', {})
        sg_per_account_limit = quota_limits.get('security_groups_per_account', self.default_quotas['security_groups_per_account'])
        
        # Try to get from Service Quotas API
        try:
            api_limit = self.get_service_quota('ec2', 'L-E79EC296')
            if api_limit:
                sg_per_account_limit = api_limit
        except Exception:
            pass  # Use default
        
        # Check security groups per account
        new_usage = account_usage['security_groups'] + proposed_usage['security_groups']
        utilization = (new_usage / sg_per_account_limit) * 100
        
        if new_usage > sg_per_account_limit:
            level = 'error'
            message = f"Would exceed security groups per account limit"
        elif utilization >= 80:
            level = 'warning'
            message = f"Approaching security groups per account limit ({utilization:.1f}%)"
        else:
            level = 'ok'
            message = f"Security groups per account usage is within limits"
        
        results.append(QuotaResult(
            service='ec2',
            quota_name='Security Groups per Account',
            current_usage=account_usage['security_groups'],
            proposed_usage=new_usage,
            quota_limit=sg_per_account_limit,
            utilization_percent=utilization,
            level=level,
            message=message
        ))
        
        return results
    
    def get_exit_code(self, results: List[QuotaResult]) -> int:
        """Determine exit code based on results"""
        has_errors = any(result.level == 'error' for result in results)
        has_warnings = any(result.level == 'warning' for result in results)
        
        if has_errors:
            return 1
        elif has_warnings:
            return 2
        else:
            return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Check AWS Security Group quota limits',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0 - All quota checks passed
  1 - Quota limits would be exceeded
  2 - Warning: approaching quota limits (80%+)

Examples:
  python check-quotas.py 123456789012
  python check-quotas.py 123456789012 --region us-west-2
  python check-quotas.py 123456789012 --vpc-id vpc-12345678
        """
    )
    
    parser.add_argument(
        'account_id',
        help='AWS Account ID (12 digits)'
    )
    
    parser.add_argument(
        '--region',
        default=None,
        help='AWS region (defaults to AWS_DEFAULT_REGION or us-east-1)'
    )
    
    parser.add_argument(
        '--vpc-id',
        default=None,
        help='Specific VPC ID to check (otherwise checks all VPCs)'
    )
    
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Include additional details in output'
    )
    
    args = parser.parse_args()
    
    # Validate account ID
    if not re.match(r'^\d{12}$', args.account_id):
        print(f"❌ Invalid account ID: {args.account_id} (must be 12 digits)", file=sys.stderr)
        sys.exit(1)
    
    try:
        checker = QuotaChecker(
            account_id=args.account_id,
            region=args.region,
            vpc_id=args.vpc_id
        )
        
        results = checker.check_quotas()
        exit_code = checker.get_exit_code(results)
        
        # Output results
        if args.format == 'json':
            output = {
                'account_id': args.account_id,
                'region': checker.region,
                'vpc_id': args.vpc_id,
                'quota_checks': [
                    {
                        'service': result.service,
                        'quota_name': result.quota_name,
                        'current_usage': result.current_usage,
                        'proposed_usage': result.proposed_usage,
                        'quota_limit': result.quota_limit,
                        'utilization_percent': result.utilization_percent,
                        'level': result.level,
                        'message': result.message
                    } for result in results
                ],
                'summary': {
                    'total_checks': len(results),
                    'errors': sum(1 for r in results if r.level == 'error'),
                    'warnings': sum(1 for r in results if r.level == 'warning'),
                    'exit_code': exit_code
                }
            }
            print(json.dumps(output, indent=2))
        else:
            # Text output
            print(f"🔍 Checking AWS Security Group quotas")
            print(f"📋 Account: {args.account_id}")
            print(f"🌐 Region: {checker.region}")
            if args.vpc_id:
                print(f"🏠 VPC: {args.vpc_id}")
            print()
            
            # Group results by level
            errors = [r for r in results if r.level == 'error']
            warnings = [r for r in results if r.level == 'warning']
            ok_results = [r for r in results if r.level == 'ok']
            
            # Print errors
            if errors:
                print("❌ Quota Violations:")
                for result in errors:
                    print(f"   • {result.message}")
                    if args.verbose:
                        print(f"     Current: {result.current_usage}, After: {result.proposed_usage}, Limit: {result.quota_limit}")
                print()
            
            # Print warnings
            if warnings:
                print("⚠️  Quota Warnings:")
                for result in warnings:
                    print(f"   • {result.message}")
                    if args.verbose:
                        print(f"     Current: {result.current_usage}, After: {result.proposed_usage}, Limit: {result.quota_limit}")
                print()
            
            # Print OK results if verbose
            if args.verbose and ok_results:
                print("✅ Quota Checks Passed:")
                for result in ok_results:
                    print(f"   • {result.message}")
                    print(f"     Current: {result.current_usage}, After: {result.proposed_usage}, Limit: {result.quota_limit}")
                print()
            
            # Summary
            print("📊 Summary:")
            print(f"   Total checks: {len(results)}")
            print(f"   Errors: {len(errors)}")
            print(f"   Warnings: {len(warnings)}")
            print(f"   Passed: {len(ok_results)}")
            
            if exit_code == 0:
                print("\n✅ All quota checks passed!")
            elif exit_code == 2:
                print("\n⚠️  Quota checks completed with warnings")
            else:
                print("\n❌ Quota checks failed - limits would be exceeded")
        
        sys.exit(exit_code)
        
    except Exception as e:
        if args.format == 'json':
            print(json.dumps({'error': str(e)}, indent=2))
        else:
            print(f"❌ Quota check error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()