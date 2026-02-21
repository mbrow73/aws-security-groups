# Terraform Cloud Setup Guide

This guide explains how to set up Terraform Cloud (TFC) workspaces for the AWS Security Group platform with the new shared terraform directory architecture.

## 🏗️ Architecture Overview

The platform now uses a shared terraform configuration:
- **All account workspaces** point to the same `terraform/` directory
- **Account-specific variables** determine which account YAML to read
- **Auto-created workspaces** for new accounts via GitHub Actions
- **VCS-driven workflows** for plan and apply operations

```
┌─────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   PR/Push   │───▶│ GitHub Actions   │    │ Terraform Cloud     │
│             │    │ • Validation     │    │ • Shared terraform/ │
│             │    │ • Auto-workspace │    │ • Account variables │
└─────────────┘    └──────────────────┘    └─────────────────────┘
                            │                        │
                            │                        ▼
                            │              ┌─────────────────────┐
                            │              │  yamldecode(file(   │
                            │              │  "accounts/${var.   │
                            │              │  account_id}/..."   │
                            │              └─────────────────────┘
                            │                        │
                            ▼                        ▼
                   ┌─────────────────┐    ┌─────────────────────┐
                   │  New TFC        │    │  AWS Resources      │
                   │  Workspaces     │    │  (Security Groups)  │
                   └─────────────────┘    └─────────────────────┘
```

## 📋 Workspace Structure

### Workspace Naming Convention

- **Account workspaces**: `sg-platform-<ACCOUNT_ID>`

Examples:
- `sg-platform-123456789012`
- `sg-platform-987654321098`

### Shared Configuration

All workspaces use the same configuration files in `terraform/`:

| File | Purpose |
|------|---------|
| `main.tf` | Calls account module with dynamic YAML path |
| `backend.tf` | Generic TFC cloud backend |
| `providers.tf` | AWS provider with account-specific assume role |
| `variables.tf` | `account_id` and `aws_region` variables |

## 🔧 Workspace Configuration

### VCS Trigger Paths

Each account workspace monitors these paths for changes:

| Path | Purpose |
|------|---------|
| `accounts/<ACCOUNT_ID>/` | Account-specific YAML changes |
| `terraform/` | Shared terraform configuration |
| `modules/` | Module updates |
| `baseline/` | Baseline profile changes |

### Required Variables

Each workspace needs these Terraform variables:

| Variable | Value | Example |
|----------|-------|---------|
| `account_id` | Target AWS account ID | `"123456789012"` |
| `aws_region` | AWS region | `"us-east-1"` |

### Environment Variables

For AWS authentication, each workspace needs:

| Variable | Value | Purpose |
|----------|-------|---------|
| `TFC_AWS_PROVIDER_AUTH` | `true` | Enable AWS provider auth |
| `TFC_AWS_RUN_ROLE_ARN` | `arn:aws:iam::ACCOUNT_ID:role/SecurityGroupApplierRole` | Cross-account role |

## 🚀 Automated Setup

### GitHub Actions Auto-Creation

New workspaces are automatically created when:

1. A PR adds a new directory `accounts/123456789012/`
2. The directory contains `security-groups.yaml`
3. The account ID hasn't been seen before

The GitHub Actions workflow will:
- Create the TFC workspace
- Set the working directory to `terraform/`
- Configure VCS trigger paths
- Set the `account_id` variable
- Enable auto-apply

### Manual Setup Script

For bulk setup or initial configuration, use:

```bash
./scripts/setup-tfc-workspaces.sh \
  --org "your-tfc-org" \
  --token "$TFC_TOKEN" \
  --repo "your-org/aws-security-groups" \
  --oauth-token "ot-xxxxxxxxx"
```

## 📝 Prerequisites

### 1. Terraform Cloud Organization

- TFC organization created
- API token with workspace management permissions
- VCS connection to GitHub repository

### 2. AWS IAM Roles

Each AWS account needs a cross-account role for TFC:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::TERRAFORM_CLOUD_ACCOUNT:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:ExternalId": "your-workspace-external-id"
        }
      }
    }
  ]
}
```

Role name: `SecurityGroupApplierRole`

### 3. GitHub Secrets/Variables

Required in repository settings:

| Type | Name | Purpose |
|------|------|---------|
| Secret | `TFC_API_TOKEN` | TFC API access for workspace creation |
| Variable | `TFC_ORGANIZATION` | Your TFC organization name |
| Variable | `TFC_OAUTH_TOKEN_ID` | OAuth token ID for VCS connection |

## 🔍 Workspace Settings

### Working Directory
All account workspaces use `terraform/` as the working directory.

### Auto-Apply
Enabled by default - plans are automatically applied after approval.

### Speculative Plans
Enabled - shows plan results on PRs before merge.

### VCS Integration
- Branch: `main`
- Trigger on: Push to monitored paths
- Include submodules: `false`

## 🎯 Per-Account Variables

Each workspace gets account-specific configuration:

```hcl
# Terraform Variables
account_id = "123456789012"
aws_region = "us-east-1"

# Environment Variables
TFC_AWS_PROVIDER_AUTH = "true"
TFC_AWS_RUN_ROLE_ARN = "arn:aws:iam::123456789012:role/SecurityGroupApplierRole"
AWS_DEFAULT_REGION = "us-east-1"
```

## 🔄 Workflow Process

### For New Accounts

1. Team creates `accounts/123456789012/security-groups.yaml`
2. Opens Pull Request
3. GitHub Actions:
   - Creates TFC workspace automatically
   - Configures workspace settings
   - Sets account_id variable
4. Validation runs (YAML, guardrails, quotas)
5. Security team reviews and approves
6. PR merges
7. TFC detects change and runs plan/apply

### For Existing Accounts

1. Team updates `accounts/123456789012/security-groups.yaml`
2. Opens Pull Request
3. Validation runs
4. TFC shows speculative plan on PR
5. Security team reviews
6. PR merges
7. TFC auto-applies changes

## 🛡️ Security Considerations

### Cross-Account Roles
- Use least privilege permissions
- Limit to security group management only
- Enable CloudTrail logging
- Regular access reviews

### API Tokens
- Store securely in GitHub Secrets
- Use workspace-scoped tokens where possible
- Rotate regularly
- Monitor for unusual activity

### VCS Integration
- Limit branch access to `main`
- Require PR reviews
- Use branch protection rules
- Enable signed commits

## 🚨 Troubleshooting

### Workspace Creation Fails

**Symptoms:**
- GitHub Actions shows workspace creation error
- New account PRs fail validation

**Solutions:**
1. Verify TFC API token permissions
2. Check TFC organization name in variables
3. Confirm OAuth token ID is correct
4. Ensure repository VCS connection is active

### Apply Failures

**Symptoms:**
- TFC workspace shows apply errors
- AWS authentication failures

**Solutions:**
1. Verify SecurityGroupApplierRole exists in target account
2. Check role trust relationship
3. Confirm TFC run role ARN is correct
4. Test assume-role manually with AWS CLI

### Variable Configuration Issues

**Symptoms:**
- Wrong account targeted
- Region mismatches

**Solutions:**
1. Check `account_id` variable in workspace
2. Verify `aws_region` setting
3. Ensure variables are set as Terraform (not Environment) type

## 📊 Monitoring

### Workspace Health
- Monitor workspace run success rates
- Set up notifications for failures
- Regular drift detection runs

### Cost Tracking
- Tag workspaces by team/environment
- Monitor TFC usage costs
- Track AWS resource costs per account

### Access Auditing
- Review workspace access permissions
- Monitor API token usage
- Track cross-account role assumptions

## 🔗 Related Resources

- [Terraform Cloud Documentation](https://developer.hashicorp.com/terraform/cloud-docs)
- [AWS IAM Cross-Account Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html)
- [GitHub Actions with TFC](https://developer.hashicorp.com/terraform/cloud-docs/vcs/github-actions)
- [Team Guide](team-guide.md) - For end users
- [Setup Script](../scripts/setup-tfc-workspaces.sh) - Automated setup

---

**Questions?** Contact the platform team or open an issue in this repository.