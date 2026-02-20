#!/usr/bin/env python3
"""
AWS Security Group Platform - Account Discovery

Discovers AWS account directories for GitHub Actions matrix builds.
Can filter to only changed accounts based on git diff.

Usage:
    python discover-accounts.py [--changed-only] [--base-ref main]

Output: JSON array of account information for GitHub Actions matrix
"""

import sys
import os
import subprocess
import json
import argparse
import re
from typing import List, Dict, Any, Set
from pathlib import Path


class AccountDiscoverer:
    """Discovers AWS account directories and their metadata"""
    
    def __init__(self, repo_root: Path = None):
        self.repo_root = repo_root or self._find_repo_root()
        self.accounts_dir = self.repo_root / "accounts"
    
    def _find_repo_root(self) -> Path:
        """Find repository root by looking for .git or guardrails.yaml"""
        current = Path.cwd()
        while current != current.parent:
            if (current / ".git").exists() or (current / "guardrails.yaml").exists():
                return current
            current = current.parent
        return Path.cwd()
    
    def discover_all_accounts(self) -> List[Dict[str, Any]]:
        """Discover all account directories"""
        if not self.accounts_dir.exists():
            return []
        
        accounts = []
        
        for item in self.accounts_dir.iterdir():
            if item.is_dir() and not item.name.startswith('.') and item.name != '_example':
                account_info = self._analyze_account_directory(item)
                if account_info:
                    accounts.append(account_info)
        
        return sorted(accounts, key=lambda x: x['account_id'])
    
    def discover_changed_accounts(self, base_ref: str = "main") -> List[Dict[str, Any]]:
        """Discover accounts that have changes compared to base_ref"""
        changed_paths = self._get_changed_files(base_ref)
        changed_account_dirs = self._extract_account_dirs_from_paths(changed_paths)
        
        accounts = []
        
        for account_dir in changed_account_dirs:
            account_path = self.repo_root / account_dir
            account_info = self._analyze_account_directory(account_path)
            if account_info:
                account_info['change_reason'] = self._determine_change_reason(account_dir, changed_paths)
                accounts.append(account_info)
        
        return sorted(accounts, key=lambda x: x['account_id'])
    
    def _analyze_account_directory(self, account_path: Path) -> Dict[str, Any]:
        """Analyze an account directory and extract metadata"""
        # Validate it looks like an account directory
        if not self._is_valid_account_directory(account_path):
            return None
        
        account_info = {
            'account_id': self._extract_account_id(account_path),
            'directory': str(account_path.relative_to(self.repo_root)),
            'name': account_path.name,
            'has_security_groups': (account_path / "security-groups.yaml").exists(),
            'has_terraform': (account_path / "terraform").exists(),
            'terraform_files': [],
        }
        
        # Extract additional metadata from security-groups.yaml
        sg_file = account_path / "security-groups.yaml"
        if sg_file.exists():
            try:
                import yaml
                with open(sg_file, 'r') as f:
                    sg_config = yaml.safe_load(f) or {}
                
                account_info.update({
                    'environment': sg_config.get('environment', 'unknown'),
                    'vpc_config': sg_config.get('vpc', {}),
                    'security_group_count': len(sg_config.get('security_groups', {})),
                    'tags': sg_config.get('tags', {}),
                })
                
                # Count rules
                total_rules = 0
                for sg_config_item in sg_config.get('security_groups', {}).values():
                    total_rules += len(sg_config_item.get('ingress', []))
                    total_rules += len(sg_config_item.get('egress', []))
                
                account_info['total_rules'] = total_rules
                
            except Exception as e:
                # If we can't parse the YAML, still include the account but mark as problematic
                account_info['parse_error'] = str(e)
                account_info['environment'] = 'unknown'
                account_info['security_group_count'] = 0
                account_info['total_rules'] = 0
        
        # Check for existing Terraform files
        terraform_dir = account_path / "terraform"
        if terraform_dir.exists():
            terraform_files = []
            for tf_file in terraform_dir.glob("*.tf"):
                terraform_files.append(tf_file.name)
            account_info['terraform_files'] = sorted(terraform_files)
        
        # Determine deployment priority/order
        account_info['deployment_priority'] = self._get_deployment_priority(account_info)
        
        return account_info
    
    def _is_valid_account_directory(self, account_path: Path) -> bool:
        """Check if a directory looks like a valid account directory"""
        if not account_path.is_dir():
            return False
        
        # Skip example and hidden directories
        if account_path.name.startswith('.') or account_path.name == '_example':
            return False
        
        # Must be a 12-digit account ID or have security-groups.yaml
        if re.match(r'^\d{12}$', account_path.name):
            return True
        
        if (account_path / "security-groups.yaml").exists():
            return True
        
        return False
    
    def _extract_account_id(self, account_path: Path) -> str:
        """Extract AWS account ID from directory name or config"""
        # Try directory name first
        if re.match(r'^\d{12}$', account_path.name):
            return account_path.name
        
        # Try security-groups.yaml
        sg_file = account_path / "security-groups.yaml"
        if sg_file.exists():
            try:
                import yaml
                with open(sg_file, 'r') as f:
                    config = yaml.safe_load(f) or {}
                    account_id = config.get('account_id')
                    if account_id and re.match(r'^\d{12}$', str(account_id)):
                        return str(account_id)
            except:
                pass
        
        # Fallback - use directory name (may not be account ID)
        return account_path.name
    
    def _get_deployment_priority(self, account_info: Dict[str, Any]) -> int:
        """Determine deployment priority (lower = deploy first)"""
        environment = account_info.get('environment', 'unknown').lower()
        
        # Development environments deploy first
        if 'dev' in environment or 'test' in environment:
            return 1
        # Staging environments deploy second
        elif 'staging' in environment or 'stage' in environment:
            return 2
        # Production environments deploy last
        elif 'prod' in environment:
            return 3
        # Unknown environments deploy with staging
        else:
            return 2
    
    def _get_changed_files(self, base_ref: str) -> Set[str]:
        """Get list of files changed compared to base_ref"""
        try:
            # First, try to fetch the latest base_ref
            subprocess.run(['git', 'fetch', 'origin', base_ref], 
                         capture_output=True, check=False, cwd=self.repo_root)
            
            # Get changed files
            result = subprocess.run([
                'git', 'diff', '--name-only', f'origin/{base_ref}...HEAD'
            ], capture_output=True, text=True, check=True, cwd=self.repo_root)
            
            changed_files = set(result.stdout.strip().split('\n'))
            
            # Filter out empty strings
            return {f for f in changed_files if f.strip()}
            
        except subprocess.CalledProcessError as e:
            # Fallback: compare with HEAD~1 if base_ref comparison fails
            try:
                result = subprocess.run([
                    'git', 'diff', '--name-only', 'HEAD~1'
                ], capture_output=True, text=True, check=True, cwd=self.repo_root)
                
                changed_files = set(result.stdout.strip().split('\n'))
                return {f for f in changed_files if f.strip()}
                
            except subprocess.CalledProcessError:
                # If git operations fail, return empty set
                print(f"Warning: Could not determine changed files: {e}", file=sys.stderr)
                return set()
    
    def _extract_account_dirs_from_paths(self, changed_paths: Set[str]) -> Set[str]:
        """Extract account directories from changed file paths"""
        account_dirs = set()
        
        for path in changed_paths:
            # Look for accounts/*/... pattern
            parts = path.split('/')
            if len(parts) >= 2 and parts[0] == 'accounts' and parts[1] != '_example':
                account_dir = f"accounts/{parts[1]}"
                account_dirs.add(account_dir)
        
        return account_dirs
    
    def _determine_change_reason(self, account_dir: str, changed_paths: Set[str]) -> str:
        """Determine why an account was marked as changed"""
        account_changes = [path for path in changed_paths if path.startswith(account_dir)]
        
        reasons = []
        
        for path in account_changes:
            if path.endswith('security-groups.yaml'):
                reasons.append('security_groups_config')
            elif path.endswith('.tf'):
                reasons.append('terraform_config')
            elif 'terraform/' in path:
                reasons.append('terraform_files')
            else:
                reasons.append('other_files')
        
        return ','.join(set(reasons)) if reasons else 'unknown'


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Discover AWS account directories for deployment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover all accounts
  python discover-accounts.py
  
  # Discover only changed accounts (compared to main)
  python discover-accounts.py --changed-only
  
  # Discover changed accounts compared to develop
  python discover-accounts.py --changed-only --base-ref develop
        """
    )
    
    parser.add_argument(
        '--changed-only',
        action='store_true',
        help='Only discover accounts with changes (for incremental deployments)'
    )
    
    parser.add_argument(
        '--base-ref',
        default='main',
        help='Git reference to compare against for changed files (default: main)'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'matrix'],
        default='matrix',
        help='Output format: json (readable) or matrix (GitHub Actions) (default: matrix)'
    )
    
    parser.add_argument(
        '--filter-environment',
        help='Filter accounts to specific environment(s) (comma-separated)'
    )
    
    parser.add_argument(
        '--exclude-environment',
        help='Exclude specific environment(s) (comma-separated)'
    )
    
    parser.add_argument(
        '--max-parallel',
        type=int,
        help='Limit the number of accounts for parallel processing'
    )
    
    parser.add_argument(
        '--sort-by',
        choices=['account_id', 'environment', 'priority', 'name'],
        default='priority',
        help='Sort accounts by field (default: priority)'
    )
    
    args = parser.parse_args()
    
    try:
        discoverer = AccountDiscoverer()
        
        # Discover accounts
        if args.changed_only:
            accounts = discoverer.discover_changed_accounts(args.base_ref)
            if not accounts:
                print("No changed accounts found", file=sys.stderr)
        else:
            accounts = discoverer.discover_all_accounts()
        
        if not accounts:
            # Output empty matrix for GitHub Actions
            if args.format == 'matrix':
                print('{"include":[]}')
            else:
                print('[]')
            return
        
        # Filter by environment if specified
        if args.filter_environment:
            filter_envs = set(env.strip().lower() for env in args.filter_environment.split(','))
            accounts = [acc for acc in accounts if acc.get('environment', '').lower() in filter_envs]
        
        if args.exclude_environment:
            exclude_envs = set(env.strip().lower() for env in args.exclude_environment.split(','))
            accounts = [acc for acc in accounts if acc.get('environment', '').lower() not in exclude_envs]
        
        # Sort accounts
        if args.sort_by == 'account_id':
            accounts.sort(key=lambda x: x['account_id'])
        elif args.sort_by == 'environment':
            accounts.sort(key=lambda x: x.get('environment', 'zzz'))
        elif args.sort_by == 'priority':
            accounts.sort(key=lambda x: (x.get('deployment_priority', 999), x['account_id']))
        elif args.sort_by == 'name':
            accounts.sort(key=lambda x: x['name'])
        
        # Limit for parallel processing
        if args.max_parallel and len(accounts) > args.max_parallel:
            accounts = accounts[:args.max_parallel]
            print(f"Limited to {args.max_parallel} accounts for parallel processing", file=sys.stderr)
        
        # Output results
        if args.format == 'matrix':
            # GitHub Actions matrix format
            matrix = {
                "include": [
                    {
                        "account_id": acc['account_id'],
                        "directory": acc['directory'],
                        "name": acc['name'],
                        "environment": acc.get('environment', 'unknown'),
                        "has_security_groups": acc['has_security_groups'],
                        "priority": acc.get('deployment_priority', 2)
                    }
                    for acc in accounts
                ]
            }
            print(json.dumps(matrix, separators=(',', ':')))
        else:
            # Pretty JSON format
            print(json.dumps(accounts, indent=2))
        
        # Output summary to stderr for logging
        print(f"Discovered {len(accounts)} accounts", file=sys.stderr)
        if args.changed_only:
            print(f"Changed accounts (vs {args.base_ref}): {', '.join([acc['account_id'] for acc in accounts])}", file=sys.stderr)
        
    except KeyboardInterrupt:
        print("\nAborted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"❌ Discovery error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()