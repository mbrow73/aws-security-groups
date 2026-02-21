# AWS Security Group Platform - Team Guide

Welcome to the AWS Security Group self-service platform! This guide will help you create and manage security groups for your AWS accounts through Infrastructure as Code.

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Creating Your Account Configuration](#creating-your-account-configuration)
3. [YAML Configuration Format](#yaml-configuration-format)
4. [Submitting Changes](#submitting-changes)
5. [Understanding Validation](#understanding-validation)
6. [Deployment Process](#deployment-process)
7. [Monitoring and Status](#monitoring-and-status)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

## 🚀 Quick Start

The new simplified process:

1. **Create directory**: `mkdir accounts/YOUR-ACCOUNT-ID`
2. **Add YAML file**: Copy `accounts/_example/security-groups.yaml` and customize
3. **Submit Pull Request** - TFC workspace is auto-created!
4. **Get approval** from security team
5. **Merge** - deployed automatically via Terraform Cloud

That's it! No Terraform files to manage.

## 📁 Creating Your Account Configuration

### Step 1: Identify Your Account ID

Find your 12-digit AWS Account ID from:
- AWS Console → Top-right menu → Account ID
- AWS CLI: `aws sts get-caller-identity --query Account --output text`
- AWS SDK in your applications

### Step 2: Create Account Directory

```bash
# Create directory for your account (replace 123456789012 with your account ID)
mkdir accounts/123456789012

# Navigate to your new account directory
cd accounts/123456789012
```

### Step 3: Create security-groups.yaml

Copy the example configuration and customize it:

```bash
# Copy the example file
cp ../accounts/_example/security-groups.yaml .

# Edit with your preferred editor
vim security-groups.yaml
```

That's it! No backend.tf, providers.tf, or other Terraform files needed.

## 📝 YAML Configuration Format

The security-groups.yaml file contains your complete security group configuration:

```yaml
# Required: Your 12-digit AWS Account ID
account_id: "123456789012"

# Optional: Environment designation
environment: "production"

# Optional: VPC configuration
vpc:
  vpc_id: "auto"  # Auto-discover, or specify VPC ID
  filter_tags:
    Environment: "production"

# Optional: Global tags for all resources
tags:
  Team: "platform"
  CostCenter: "engineering"

# Optional: Baseline security group profiles
baseline_profiles:
  - vpc-endpoints
  - eks-standard

# Security Groups Configuration
security_groups:
  web-servers:
    description: "Security group for web servers"
    ingress:
      - description: "HTTPS from load balancer"
        from_port: 443
        to_port: 443
        protocol: "tcp"
        security_groups: ["alb-web"]
    
    egress:
      - description: "HTTPS to internet"
        from_port: 443
        to_port: 443
        protocol: "tcp"
        cidr_blocks: ["0.0.0.0/0"]
```

### Required Fields

- **account_id**: Your 12-digit AWS account ID
- **security_groups**: Dictionary of security group definitions

### Optional Fields

- **environment**: Environment name (dev, staging, production)
- **vpc**: VPC configuration (defaults to auto-discovery)
- **tags**: Additional tags to apply to all resources
- **baseline_profiles**: Pre-built security group profiles to include

## 📤 Submitting Changes

### Step 1: Create Pull Request

```bash
git add accounts/123456789012/security-groups.yaml
git commit -m "Add security groups for account 123456789012"
git push origin feature/account-123456789012
```

Create a Pull Request on GitHub.

### Step 2: Automated Workspace Creation

When you submit a PR with a new account directory, the GitHub Actions pipeline will:

1. **Detect** the new account directory
2. **Create** a Terraform Cloud workspace automatically
3. **Configure** the workspace with:
   - Working directory: `terraform/`
   - Account ID variable set
   - VCS trigger paths configured
   - Auto-apply enabled

### Step 3: Validation

The PR will trigger validation checks:

- ✅ **YAML Schema**: Validates your configuration format
- ✅ **Naming Conventions**: Ensures compliance with org standards
- ✅ **Guardrails**: Checks against security policies
- ✅ **Quota Check**: Verifies AWS account limits won't be exceeded

## 🔍 Understanding Validation

### YAML Schema Validation

Checks that your YAML file follows the correct structure and includes required fields.

Common issues:
- Missing `account_id` field
- Invalid security group rule format
- Incorrect data types (string vs number)

### Naming Conventions

Security group names must follow organizational standards:
- Use lowercase letters and hyphens
- Include purpose/service identifier
- Follow patterns: `service-purpose`, `tier-role`

Examples:
- ✅ `web-servers`, `api-gateway`, `db-primary`
- ❌ `WebServers`, `SG_API`, `database123`

### Guardrails Validation

Automatically enforces security policies:
- No unrestricted inbound access (0.0.0.0/0 on sensitive ports)
- Management ports (SSH/RDP) must be restricted
- Egress rules should be specific where possible

### Quota Checks

Validates that your changes won't exceed AWS limits:
- Security groups per VPC
- Rules per security group
- Security groups per ENI

## 🚀 Deployment Process

### After PR Approval and Merge

1. **Terraform Cloud Detects** changes via VCS webhook
2. **Plan Phase**: TFC runs `terraform plan`
   - Reads your YAML file using `yamldecode()`
   - Shows what will be created/changed
3. **Auto-Apply**: If plan is clean, automatically applies changes
4. **Notification**: Status posted to PR/Slack (if configured)

### Monitoring Deployments

Check Terraform Cloud workspace for your account:
- Workspace name: `sg-platform-YOUR-ACCOUNT-ID`
- URL: `https://app.terraform.io/app/ORG-NAME/workspaces/sg-platform-YOUR-ACCOUNT-ID`

## 📊 Monitoring and Status

### Workspace Status

Each account has its own TFC workspace where you can:
- View current state
- See deployment history
- Check for drift detection
- Review plan/apply logs

### GitHub Integration

- PR status checks show validation results
- Merge triggers automatic deployment
- Comments provide detailed feedback

## 🛠 Troubleshooting

### Common Issues

#### 1. Workspace Creation Failed
**Symptom**: PR shows workspace creation error

**Solution**: 
- Verify TFC API token has workspace management permissions
- Check that organization name is correct
- Ensure OAuth connection is properly configured

#### 2. Account ID Validation Error
**Symptom**: "Account ID mismatch" error during apply

**Solution**:
- Verify the SecurityGroupApplierRole exists in target account
- Check cross-account trust relationship
- Ensure TFC has assume-role permissions

#### 3. YAML Validation Fails
**Symptom**: Schema validation errors in PR

**Solution**:
- Check YAML syntax using online validator
- Ensure all required fields are present
- Verify data types match schema

#### 4. Guardrails Violations
**Symptom**: Security policy violations block PR

**Solution**:
- Review guardrails.yaml for specific rules
- Contact security team for exceptions
- Modify rules to comply with policies

### Getting Help

1. **Documentation**: Check this guide and `accounts/_example/security-groups.yaml`
2. **Security Team**: For guardrails exceptions or security questions
3. **Platform Team**: For technical issues or feature requests
4. **GitHub Issues**: Report bugs or request features

## 📚 Best Practices

### 1. Security Group Design

- **Least Privilege**: Only allow necessary ports/protocols
- **Descriptive Names**: Use clear, purposeful naming
- **Group by Function**: Separate web/app/db tiers
- **Use References**: Reference other security groups instead of IP ranges

### 2. YAML Organization

- **Comments**: Document complex rules
- **Consistent Format**: Follow the example structure
- **Validation**: Test locally before submitting PR
- **Version Control**: Use meaningful commit messages

### 3. Change Management

- **Small Changes**: Submit focused, single-purpose PRs
- **Testing**: Verify in lower environments first
- **Rollback Plan**: Document how to revert if needed
- **Documentation**: Update descriptions when changing rules

### 4. Baseline Profiles

Use baseline profiles for common patterns:
- `vpc-endpoints`: For accessing AWS services
- `eks-standard`: For Kubernetes workloads
- `internet-ingress`: For load balancer traffic

### 5. Monitoring

- **Regular Reviews**: Audit security groups periodically
- **Drift Detection**: Monitor TFC for configuration drift
- **Access Logs**: Review VPC Flow Logs for unusual traffic
- **Compliance**: Track against organizational policies

## 🔗 Related Resources

- [`accounts/_example/security-groups.yaml`](../accounts/_example/security-groups.yaml) - Complete example
- [`docs/naming-conventions.md`](naming-conventions.md) - Naming standards
- [`guardrails.yaml`](../guardrails.yaml) - Security policies
- [`prefix-lists.yaml`](../prefix-lists.yaml) - Reusable IP ranges
- [Terraform Cloud Documentation](https://developer.hashicorp.com/terraform/cloud-docs)

---

**Questions?** Contact the platform team or open an issue in this repository.