#!/bin/bash
set -euo pipefail

# AWS Security Group Platform - Terraform Cloud Workspace Setup Script
# Creates TFC workspaces for all accounts with proper naming, VCS trigger paths, and settings

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ACCOUNTS_DIR="$REPO_ROOT/accounts"
BASELINE_DIR="$REPO_ROOT/baseline"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# API Base URL
TFC_API_BASE="https://app.terraform.io/api/v2"

# Global variables
TFC_ORG=""
TFC_TOKEN=""
REPO_IDENTIFIER=""
OAUTH_TOKEN_ID=""
DRY_RUN=false
FORCE=false

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Create Terraform Cloud workspaces for the AWS Security Group platform.

OPTIONS:
    -h, --help              Show this help message
    -o, --org ORG           TFC organization name (required)
    -t, --token TOKEN       TFC API token (required)
    -r, --repo REPO         Repository identifier (org/repo-name) (required)
    -T, --oauth-token TOKEN OAuth token ID for VCS connection (required)
    -d, --dry-run          Show what would be created without making changes
    -f, --force            Skip existing workspace checks
    -v, --verbose          Enable verbose logging

EXAMPLES:
    # Interactive mode
    $0

    # With parameters
    $0 --org "my-company" --token "\$TFC_TOKEN" \\
       --repo "my-company/aws-security-groups" \\
       --oauth-token "ot-abc123def456"

    # Dry run to see what would be created
    $0 --dry-run --org "my-company" --token "\$TFC_TOKEN" \\
       --repo "my-company/aws-security-groups" \\
       --oauth-token "ot-abc123def456"

PREREQUISITES:
    - TFC organization exists
    - Repository is connected to TFC via VCS integration
    - API token has workspace management permissions

EOF
}

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

log_error() {
    echo -e "${RED}❌${NC} $1"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -o|--org)
                TFC_ORG="$2"
                shift 2
                ;;
            -t|--token)
                TFC_TOKEN="$2"
                shift 2
                ;;
            -r|--repo)
                REPO_IDENTIFIER="$2"
                shift 2
                ;;
            -T|--oauth-token)
                OAUTH_TOKEN_ID="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Interactive prompts for missing parameters
prompt_for_missing_params() {
    if [[ -z "$TFC_ORG" ]]; then
        read -p "Enter TFC Organization name: " TFC_ORG
    fi

    if [[ -z "$TFC_TOKEN" ]]; then
        echo "Enter TFC API token (will be hidden):"
        read -s TFC_TOKEN
        echo
    fi

    if [[ -z "$REPO_IDENTIFIER" ]]; then
        read -p "Enter repository identifier (org/repo-name): " REPO_IDENTIFIER
    fi

    if [[ -z "$OAUTH_TOKEN_ID" ]]; then
        log "To find your OAuth token ID:"
        log "1. Go to https://app.terraform.io/app/$TFC_ORG/settings/version-control"
        log "2. Find your GitHub connection and note the token ID (ot-xxxxx)"
        echo
        read -p "Enter OAuth token ID: " OAUTH_TOKEN_ID
    fi
}

# Validate prerequisites
validate_prerequisites() {
    log "🔍 Validating prerequisites..."

    # Check if accounts directory exists
    if [[ ! -d "$ACCOUNTS_DIR" ]]; then
        log_error "Accounts directory not found: $ACCOUNTS_DIR"
        exit 1
    fi

    # Check if baseline directory exists
    if [[ ! -d "$BASELINE_DIR" ]]; then
        log_error "Baseline directory not found: $BASELINE_DIR"
        exit 1
    fi

    # Check for required commands
    for cmd in curl jq; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd is required but not installed"
            exit 1
        fi
    done

    # Validate TFC token by checking organization
    log "🔑 Validating TFC token..."
    response=$(curl -s -w "%{http_code}" \
        -H "Authorization: Bearer $TFC_TOKEN" \
        -H "Content-Type: application/vnd.api+json" \
        "$TFC_API_BASE/organizations/$TFC_ORG" \
        -o /tmp/tfc_org_check.json)

    if [[ "$response" != "200" ]]; then
        log_error "Failed to access TFC organization '$TFC_ORG'. Check token and organization name."
        if [[ -f /tmp/tfc_org_check.json ]]; then
            cat /tmp/tfc_org_check.json
        fi
        exit 1
    fi

    log_success "TFC organization '$TFC_ORG' accessible"
}

# Discover account IDs from directory structure
discover_accounts() {
    log "🔎 Discovering AWS accounts..."
    
    local accounts=()
    
    # Find account directories
    if [[ -d "$ACCOUNTS_DIR" ]]; then
        for dir in "$ACCOUNTS_DIR"/*/; do
            if [[ -d "$dir" ]]; then
                local account_name=$(basename "$dir")
                # Skip example directory
                if [[ "$account_name" == "_example" ]]; then
                    continue
                fi
                
                # Check if directory name is a 12-digit account ID
                if [[ "$account_name" =~ ^[0-9]{12}$ ]]; then
                    accounts+=("$account_name")
                else
                    # Try to extract account ID from security-groups.yaml
                    local sg_file="$dir/security-groups.yaml"
                    if [[ -f "$sg_file" ]]; then
                        local account_id=$(yq eval '.account_id' "$sg_file" 2>/dev/null || echo "null")
                        if [[ "$account_id" != "null" && "$account_id" =~ ^[0-9]{12}$ ]]; then
                            accounts+=("$account_id")
                        else
                            log_warning "Could not determine account ID for directory: $account_name"
                        fi
                    fi
                fi
            fi
        done
    fi
    
    if [[ ${#accounts[@]} -eq 0 ]]; then
        log_warning "No AWS accounts discovered. You may need to create account directories first."
    else
        log_success "Discovered ${#accounts[@]} AWS accounts: ${accounts[*]}"
    fi
    
    echo "${accounts[@]}"
}

# Check if workspace exists
workspace_exists() {
    local workspace_name="$1"
    
    response=$(curl -s -w "%{http_code}" \
        -H "Authorization: Bearer $TFC_TOKEN" \
        -H "Content-Type: application/vnd.api+json" \
        "$TFC_API_BASE/organizations/$TFC_ORG/workspaces/$workspace_name" \
        -o /dev/null)
    
    [[ "$response" == "200" ]]
}

# Create TFC workspace
create_workspace() {
    local workspace_name="$1"
    local working_directory="$2"
    local trigger_paths="$3"
    local description="$4"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Would create workspace: $workspace_name"
        log "  Working Directory: $working_directory"
        log "  Trigger Paths: $trigger_paths"
        log "  Description: $description"
        return 0
    fi
    
    # Check if workspace already exists
    if workspace_exists "$workspace_name" && [[ "$FORCE" != "true" ]]; then
        log_warning "Workspace '$workspace_name' already exists, skipping..."
        return 0
    fi
    
    # Prepare workspace payload
    local payload=$(jq -n \
        --arg name "$workspace_name" \
        --arg working_directory "$working_directory" \
        --arg description "$description" \
        --arg oauth_token_id "$OAUTH_TOKEN_ID" \
        --arg repo_identifier "$REPO_IDENTIFIER" \
        --argjson trigger_paths "$trigger_paths" \
        '{
            data: {
                type: "workspaces",
                attributes: {
                    name: $name,
                    description: $description,
                    "working-directory": $working_directory,
                    "auto-apply": true,
                    "speculative-enabled": true,
                    "trigger-prefixes": $trigger_paths,
                    "vcs-repo": {
                        identifier: $repo_identifier,
                        "oauth-token-id": $oauth_token_id,
                        branch: "main",
                        "ingress-submodules": false
                    }
                }
            }
        }')
    
    log "Creating workspace: $workspace_name"
    
    response=$(curl -s -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer $TFC_TOKEN" \
        -H "Content-Type: application/vnd.api+json" \
        -d "$payload" \
        "$TFC_API_BASE/organizations/$TFC_ORG/workspaces" \
        -o /tmp/tfc_create_response.json)
    
    if [[ "$response" == "201" ]]; then
        log_success "Created workspace: $workspace_name"
    else
        log_error "Failed to create workspace: $workspace_name (HTTP $response)"
        if [[ -f /tmp/tfc_create_response.json ]]; then
            cat /tmp/tfc_create_response.json
        fi
        return 1
    fi
}

# Set workspace variables
set_workspace_variables() {
    local workspace_name="$1"
    local account_id="$2"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Would set variables for workspace: $workspace_name"
        return 0
    fi
    
    # Environment variables
    local env_vars=(
        "TFC_AWS_PROVIDER_AUTH:true:false"
        "AWS_DEFAULT_REGION:us-east-1:false"
    )
    
    # Add account-specific IAM role ARN if account ID provided
    if [[ -n "$account_id" ]]; then
        env_vars+=("TFC_AWS_RUN_ROLE_ARN:arn:aws:iam::${account_id}:role/TerraformCloudRole:false")
    fi
    
    # Terraform variables
    local tf_vars=()
    if [[ -n "$account_id" ]]; then
        tf_vars+=("account_id:${account_id}:false")
    fi
    
    # Create environment variables
    for var_def in "${env_vars[@]}"; do
        IFS=':' read -r key value sensitive <<< "$var_def"
        
        local payload=$(jq -n \
            --arg key "$key" \
            --arg value "$value" \
            --argjson sensitive "$sensitive" \
            '{
                data: {
                    type: "vars",
                    attributes: {
                        key: $key,
                        value: $value,
                        category: "env",
                        sensitive: $sensitive
                    }
                }
            }')
        
        response=$(curl -s -w "%{http_code}" \
            -X POST \
            -H "Authorization: Bearer $TFC_TOKEN" \
            -H "Content-Type: application/vnd.api+json" \
            -d "$payload" \
            "$TFC_API_BASE/workspaces/$workspace_name/vars" \
            -o /dev/null)
        
        if [[ "$response" == "201" ]]; then
            log "  ✅ Set environment variable: $key"
        else
            log_warning "  Failed to set environment variable: $key"
        fi
    done
    
    # Create Terraform variables
    for var_def in "${tf_vars[@]}"; do
        IFS=':' read -r key value sensitive <<< "$var_def"
        
        local payload=$(jq -n \
            --arg key "$key" \
            --arg value "$value" \
            --argjson sensitive "$sensitive" \
            '{
                data: {
                    type: "vars",
                    attributes: {
                        key: $key,
                        value: $value,
                        category: "terraform",
                        sensitive: $sensitive
                    }
                }
            }')
        
        response=$(curl -s -w "%{http_code}" \
            -X POST \
            -H "Authorization: Bearer $TFC_TOKEN" \
            -H "Content-Type: application/vnd.api+json" \
            -d "$payload" \
            "$TFC_API_BASE/workspaces/$workspace_name/vars" \
            -o /dev/null)
        
        if [[ "$response" == "201" ]]; then
            log "  ✅ Set Terraform variable: $key"
        else
            log_warning "  Failed to set Terraform variable: $key"
        fi
    done
}

# Create baseline workspace
create_baseline_workspace() {
    log "🏗️ Creating baseline workspace..."
    
    local workspace_name="sg-platform-baseline"
    local working_directory="baseline"
    local trigger_paths='["baseline/"]'
    local description="AWS Security Group Platform - Baseline profiles (opt-in)"
    
    if create_workspace "$workspace_name" "$working_directory" "$trigger_paths" "$description"; then
        set_workspace_variables "$workspace_name" ""
        log_success "Baseline workspace configured"
    else
        log_error "Failed to create baseline workspace"
        return 1
    fi
}

# Create account-specific workspaces
create_account_workspaces() {
    local accounts=($1)
    
    if [[ ${#accounts[@]} -eq 0 ]]; then
        log_warning "No accounts found, skipping account workspace creation"
        return 0
    fi
    
    log "🏗️ Creating account-specific workspaces..."
    
    local success_count=0
    local total_count=${#accounts[@]}
    
    for account_id in "${accounts[@]}"; do
        local workspace_name="sg-platform-${account_id}"
        local working_directory=""  # Root directory for account workspaces
        local trigger_paths="[\"accounts/${account_id}/\"]"
        local description="AWS Security Group Platform - Account ${account_id}"
        
        if create_workspace "$workspace_name" "$working_directory" "$trigger_paths" "$description"; then
            set_workspace_variables "$workspace_name" "$account_id"
            log_success "Account workspace configured: $account_id"
            ((success_count++))
        else
            log_error "Failed to create workspace for account: $account_id"
        fi
    done
    
    log "📊 Account workspaces: $success_count/$total_count successful"
}

# Main setup function
setup_workspaces() {
    log "🚀 Starting TFC workspace setup for AWS Security Group platform"
    
    validate_prerequisites
    
    # Discover accounts
    local accounts=$(discover_accounts)
    
    # Create baseline workspace
    create_baseline_workspace
    
    # Create account workspaces
    create_account_workspaces "$accounts"
    
    log_success "🎉 TFC workspace setup complete!"
    
    if [[ "$DRY_RUN" != "true" ]]; then
        log ""
        log "Next steps:"
        log "1. Configure AWS OIDC providers in each account"
        log "2. Create TerraformCloudRole IAM roles with appropriate permissions"
        log "3. Update organization name in backend.tf files"
        log "4. Test with a small change to verify the workflow"
        log ""
        log "See docs/tfc-setup.md for detailed configuration instructions"
    fi
}

# Main execution
main() {
    parse_args "$@"
    prompt_for_missing_params
    
    # Validate required parameters
    if [[ -z "$TFC_ORG" || -z "$TFC_TOKEN" || -z "$REPO_IDENTIFIER" || -z "$OAUTH_TOKEN_ID" ]]; then
        log_error "Missing required parameters. Use -h for help."
        exit 1
    fi
    
    setup_workspaces
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi