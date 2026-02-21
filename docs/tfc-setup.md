# Terraform Cloud Setup Guide

This guide explains how to set up Terraform Cloud (TFC) workspaces for the AWS Security Group platform after migrating from GitHub Actions.

## 🏗️ Architecture Overview

The platform now uses:
- **GitHub Actions**: YAML validation, guardrail checks, quota pre-checks, naming conventions
- **Terraform Cloud**: Terraform plan/apply operations with VCS-driven workspaces
- **Per-Account Workspaces**: Each AWS account gets its own TFC workspace

```
┌─────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   PR/Push   │───▶│ GitHub Actions   │    │ Terraform Cloud     │
│             │    │ (Validation)     │    │ (Plan/Apply)        │
└─────────────┘    └──────────────────┘    └─────────────────────┘
                            │                        │
                            │                        ▼
                            │              ┌─────────────────────┐
                            │              │  VCS-Triggered      │
                            │              │  Speculative Plans  │
                            │              │  & Auto-Apply       │
                            │              └─────────────────────┘
                            │                        │
                            ▼                        ▼
                   ┌─────────────────┐    ┌─────────────────────┐
                   │  Validation     │    │  AWS Resources      │
                   │  (Pass/Fail)    │    │  (Security Groups)  │
                   └─────────────────┘    └─────────────────────┘
```

## 📋 Workspace Naming Convention

- **Baseline workspace**: `sg-platform-baseline`
- **Account workspaces**: `sg-platform-<ACCOUNT_ID>`

Examples:
- `sg-platform-baseline`
- `sg-platform-123456789012`
- `sg-platform-987654321098`

## 🔧 Workspace Configuration

### VCS Trigger Paths

Each workspace should be configured with the following VCS trigger paths:

| Workspace Type | Trigger Path | Example |
|---------------|-------------|---------|
| Baseline | `baseline/` | All changes to baseline profiles |
| Account-specific | `accounts/<ACCOUNT_ID>/` | `accounts/123456789012/` |

### Recommended Workspace Settings

```yaml
# Per workspace configuration
Auto Apply: true                    # Apply after merge to main
Speculative Plans: true            # Plan on PRs
Working Directory: "baseline/"     # For baseline workspace
Working Directory: ""              # For account workspaces (root)
```

## 🔐 OIDC/Dynamic Credentials Setup

### Prerequisites

1. **AWS IAM Identity Provider** configured in each target account
2. **IAM Role** for Terraform Cloud with appropriate permissions
3. **TFC Variables** configured for AWS authentication

### Step 1: Configure AWS IAM OIDC Provider

In each AWS account, create an OIDC identity provider:

```bash
aws iam create-open-id-connect-provider \
  --url https://app.terraform.io \
  --client-id-list aws.workload.identity \
  --thumbprint-list 9e99a48a9960b14926bb7f3b02e22da2b0ab7280
```

### Step 2: Create IAM Role

Create an IAM role that TFC can assume:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/app.terraform.io"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "app.terraform.io:aud": "aws.workload.identity"
        },
        "StringLike": {
          "app.terraform.io:sub": "organization:YOUR_ORG_NAME:project:*:workspace:sg-platform-*:run_phase:*"
        }
      }
    }
  ]
}
```

Attach the following policy (customize as needed):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*SecurityGroup*",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribePrefixLists",
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "ec2:DescribeTags"
      ],
      "Resource": "*"
    }
  ]
}
```

### Step 3: Configure TFC Workspace Variables

In each TFC workspace, set the following environment variables:

| Variable Name | Type | Sensitive | Value |
|--------------|------|-----------|--------|
| `TFC_AWS_PROVIDER_AUTH` | Environment | No | `true` |
| `TFC_AWS_RUN_ROLE_ARN` | Environment | No | `arn:aws:iam::ACCOUNT_ID:role/TerraformCloudRole` |
| `AWS_DEFAULT_REGION` | Environment | No | `us-east-1` (or your preferred region) |

## 🏠 Workspace Variables

### Required Variables (All Workspaces)

| Variable | Type | Description | Example |
|----------|------|-------------|---------|
| `AWS_DEFAULT_REGION` | Environment | AWS region | `us-east-1` |
| `TFC_AWS_PROVIDER_AUTH` | Environment | Enable AWS dynamic credentials | `true` |
| `TFC_AWS_RUN_ROLE_ARN` | Environment | IAM role ARN | `arn:aws:iam::123456789012:role/TerraformCloudRole` |

### Account-Specific Variables

For account workspaces, also set:

| Variable | Type | Description | Example |
|----------|------|-------------|---------|
| `account_id` | Terraform | AWS Account ID | `123456789012` |

### Baseline Variables

For the baseline workspace:

| Variable | Type | Description | Example |
|----------|------|-------------|---------|
| `account_id` | Terraform | Target account ID | Set per run or use default |

## 🚀 Workspace Setup Helper

Use the included helper script to create workspaces in bulk:

```bash
# Make the script executable
chmod +x scripts/setup-tfc-workspaces.sh

# Run the setup (interactive)
./scripts/setup-tfc-workspaces.sh

# Or provide parameters directly
./scripts/setup-tfc-workspaces.sh \
  --org "my-tfc-org" \
  --token "$TFC_TOKEN" \
  --repo-identifier "my-org/aws-security-groups" \
  --oauth-token-id "ot-abc123"
```

## 🔄 Migration Workflow

1. **Create TFC Organization** (if not exists)
2. **Connect GitHub Repository** to TFC
3. **Run workspace setup script** to create all workspaces
4. **Configure OIDC** in each AWS account
5. **Set workspace variables** for AWS authentication
6. **Test with a small change** to verify everything works

## 🔍 Workspace Settings Deep Dive

### Auto Apply Settings

| Setting | Recommended Value | Reason |
|---------|------------------|---------|
| Auto Apply | `true` | Automatic deployment after merge |
| Auto Apply on pull requests | `false` | Only speculative plans on PRs |

### Execution Settings

| Setting | Recommended Value | Reason |
|---------|------------------|---------|
| Execution Mode | Remote | Use TFC's infrastructure |
| Terraform Version | Latest compatible | Usually `~> 1.6` |

### VCS Settings

| Setting | Value | Notes |
|---------|-------|-------|
| VCS Provider | GitHub | Connected to your GitHub repo |
| Repository | `org/aws-security-groups` | Your repo identifier |
| Branch | `main` | Primary branch for deployments |

## 🛠️ Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify OIDC provider thumbprint: `9e99a48a9960b14926bb7f3b02e22da2b0ab7280`
   - Check IAM role trust policy conditions
   - Ensure workspace has correct `TFC_AWS_RUN_ROLE_ARN`

2. **Permission Denied**
   - Review IAM role permissions
   - Check if account ID in role ARN matches workspace

3. **VCS Trigger Not Working**
   - Verify working directory setting
   - Check VCS trigger paths configuration
   - Ensure OAuth token has repository access

4. **State Lock Issues**
   - TFC handles state locking automatically
   - No DynamoDB table needed
   - Clear any manual locks in TFC UI

### Debug Steps

1. **Check Workspace Logs** in TFC UI
2. **Verify Variables** are set correctly
3. **Test AWS Credentials** with a simple plan
4. **Review VCS Configuration** and trigger paths

## 📚 Additional Resources

- [Terraform Cloud Documentation](https://developer.hashicorp.com/terraform/cloud-docs)
- [AWS Provider Dynamic Credentials](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication-and-configuration)
- [VCS-driven Workflow](https://developer.hashicorp.com/terraform/cloud-docs/vcs)
- [Workspace Variables](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/variables)