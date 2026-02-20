# AWS Security Group Platform - Team Guide

Welcome to the AWS Security Group self-service platform! This guide will help you create and manage security groups for your AWS accounts through Infrastructure as Code.

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Creating Your Account Directory](#creating-your-account-directory)
3. [YAML Configuration Format](#yaml-configuration-format)
4. [Submitting Changes](#submitting-changes)
5. [Understanding Validation](#understanding-validation)
6. [Deployment Process](#deployment-process)
7. [Monitoring and Status](#monitoring-and-status)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

## 🚀 Quick Start

1. **Fork/Clone** this repository
2. **Create** your account directory: `accounts/123456789012/`
3. **Copy** the example configuration: `cp accounts/_example/security-groups.yaml accounts/123456789012/`
4. **Edit** your `security-groups.yaml` file
5. **Submit** a Pull Request
6. **Review** validation results and fix any issues
7. **Merge** to deploy your changes

## 📁 Creating Your Account Directory

### Step 1: Identify Your Account ID

Find your 12-digit AWS Account ID from:
- AWS Console → Top-right menu → Account ID
- AWS CLI: `aws sts get-caller-identity --query Account --output text`
- AWS SDK in your applications

### Step 2: Create Directory Structure

```bash
# Create your account directory (replace with your account ID)
mkdir -p accounts/123456789012

# Copy the example configuration
cp accounts/_example/security-groups.yaml accounts/123456789012/

# Edit the configuration
vim accounts/123456789012/security-groups.yaml
```

### Step 3: Customize the Configuration

Edit `accounts/123456789012/security-groups.yaml`:

```yaml
# Update with your actual account ID
account_id: "123456789012"

# Set your environment
environment: "production"  # or "staging", "development"

# Configure your security groups
security_groups:
  my-app-servers:
    description: "Security group for my application servers"
    # ... add your rules
```

## 📝 YAML Configuration Format

### Basic Structure

```yaml
account_id: "123456789012"          # Required: Your AWS Account ID
environment: "production"           # Optional: Environment name
vpc:                               # Optional: VPC configuration
  vpc_id: "auto"                   # "auto" or specific VPC ID
tags:                              # Optional: Global tags
  Team: "backend"
  Project: "microservices"

baseline_profiles:                 # Optional: Opt-in to baseline security groups
  - vpc-endpoints                  # Enables VPC endpoint access
  - internet-ingress               # Enables WAF/CDN → NLB traffic
  - eks-standard                   # Enables EKS cluster communication

security_groups:
  group-name:                      # Your security group name
    description: "Purpose of this security group"  # Required
    tags:                          # Required tags
      Team: "your-team"
      Environment: "production"
      Application: "your-app"
    ingress:                       # Inbound rules
      - protocol: "tcp"
        from_port: 80
        to_port: 80
        cidr_blocks: ["10.0.0.0/8"]
        description: "HTTP from internal"
    egress:                        # Outbound rules (optional)
      - protocol: "tcp"
        from_port: 443
        to_port: 443
        cidr_blocks: ["0.0.0.0/0"]
        description: "HTTPS outbound"
```

### Required Fields

| Field | Level | Description | Example |
|-------|-------|-------------|---------|
| `account_id` | Root | 12-digit AWS Account ID | `"123456789012"` |
| `description` | Security Group | Purpose of the security group | `"Web servers for API"` |
| `Team` | Tag | Owning team name | `"backend"` |
| `Environment` | Tag | Environment designation | `"production"` |
| `Application` | Tag | Application name | `"order-service"` |
| `ManagedBy` | Tag | Always "sg-platform" | `"sg-platform"` (auto-added) |

### Rule Configuration

#### Basic Rule Structure

```yaml
ingress:
  - protocol: "tcp"              # tcp, udp, icmp, icmpv6, gre, ah, esp, all, -1
    from_port: 80                # Port number (0-65535)
    to_port: 80                  # Port number (0-65535)
    description: "HTTP traffic"   # Required description
    # One or more sources:
    cidr_blocks: ["10.0.0.0/8"]           # IPv4 CIDR blocks
    ipv6_cidr_blocks: ["::/0"]             # IPv6 CIDR blocks
    security_groups: ["sg-12345678"]       # Security group IDs or names
    prefix_list_ids: ["corporate-networks"] # Prefix list references
    self: true                             # Allow within same SG
```

#### Source Types

**CIDR Blocks** - Specify IP ranges:
```yaml
cidr_blocks: 
  - "10.0.0.0/8"        # Internal network
  - "192.168.1.0/24"    # Specific subnet
```

**Security Groups** - Reference other security groups:
```yaml
security_groups:
  - "sg-0123456789abcdef0"    # By security group ID
  - "alb-production"          # By name (if in same account)
```

**Prefix Lists** - Use managed IP ranges:
```yaml
prefix_list_ids:
  - "corporate-networks"      # Custom prefix list
  - "pl-12345678"            # AWS managed prefix list
  - "waf-saas-providers"     # WAF provider IPs
```

**Self Reference** - Allow communication within the security group:
```yaml
self: true  # Allows instances in this SG to communicate with each other
```

### VPC Configuration

Control which VPC your security groups are deployed to:

```yaml
vpc:
  # Automatic VPC discovery (default)
  vpc_id: "auto"
  
  # Or specify a particular VPC
  vpc_id: "vpc-0123456789abcdef0"
  
  # Filter VPCs during auto-discovery
  filter_tags:
    Environment: "production"
    Name: "main-vpc"
  
  # Requirements for auto-discovery
  require_internet_access: true
  require_private_subnets: true
  min_availability_zones: 2
```

### Environment-Specific Configurations

The platform applies different rules based on environment:

**Production** (`environment: "production"`):
- Stricter CIDR validation (max /24)
- All changes require approval
- Enhanced monitoring

**Staging** (`environment: "staging"`):
- Moderate restrictions (max /16)
- Changes require approval
- Standard monitoring

**Development** (`environment: "development"`):
- Relaxed restrictions (max /8)
- No approval required
- Basic monitoring
- Additional allowed ports for dev tools

## 🛡️ Baseline Security Group Profiles

The platform provides optional **baseline security group profiles** that contain common security patterns used across the organization. These are opt-in per account, allowing teams to choose which baseline patterns they need.

### Available Baseline Profiles

#### `vpc-endpoints` - VPC Endpoint Access
Enables secure access to AWS VPC endpoints (S3, ECR, EKS API, etc.)

**What it provides:**
- HTTPS (443) access from VPC CIDR to VPC endpoints
- HTTP (80) access from VPC CIDR to VPC endpoints (for S3)
- Configurable additional ports for custom VPC endpoints

**When to use:**
- Applications need to access AWS services privately through VPC endpoints
- Required for EKS clusters using ECR for container images
- Applications using S3, SSM, CloudWatch, or other AWS services

#### `internet-ingress` - WAF/CDN to NLB Traffic  
Enables WAF and CDN providers (Cloudflare, Fastly, etc.) to reach Network Load Balancers

**What it provides:**
- HTTP (80) and HTTPS (443) access from WAF/CDN provider IPs
- Configurable custom ports for specific applications
- Uses managed prefix lists for WAF provider IP ranges

**When to use:**
- Public-facing applications behind Network Load Balancers
- Using WAF services like Cloudflare, Fastly, or AWS WAF
- Need to restrict ingress to known CDN/WAF provider IPs

#### `eks-standard` - EKS Cluster Communication
Provides baseline security for EKS cluster API and node communication

**What it provides:**
- EKS API (443) access from private subnets (for worker nodes)
- EKS API (443) access from corporate networks (for kubectl)
- Standard EKS control plane communication patterns

**When to use:**
- Running EKS clusters in the account
- Need standard EKS security group patterns
- kubectl access from corporate networks required

### How to Enable Baseline Profiles

Add the `baseline_profiles` section to your `security-groups.yaml`:

```yaml
account_id: "123456789012"
environment: "production"

# Opt into baseline security group profiles
baseline_profiles:
  - vpc-endpoints      # Enable VPC endpoint access patterns
  - internet-ingress   # Enable WAF/CDN → NLB patterns  
  - eks-standard       # Enable EKS cluster patterns

security_groups:
  # Your custom security groups...
```

### Using Baseline Security Groups in Rules

Once enabled, you can reference baseline security groups in your custom security group rules:

```yaml
security_groups:
  my-app-servers:
    description: "Application servers with baseline access"
    ingress:
      # Allow access from baseline internet-ingress SG
      - protocol: tcp
        from_port: 8080
        to_port: 8080
        security_groups: ["baseline-waf-to-nlb"]
        description: "App access from WAF/CDN"
      
      # Custom rules...
    
    # Inherit VPC endpoint access
    egress:
      - protocol: tcp
        from_port: 443
        to_port: 443
        security_groups: ["baseline-vpc-endpoints"]
        description: "HTTPS to AWS services via VPC endpoints"
```

### Baseline Profile Configuration

You can customize baseline profile behavior using additional variables:

```yaml
baseline_profiles:
  - vpc-endpoints
  - internet-ingress
  - eks-standard

# Optional: Customize baseline profile settings
baseline_config:
  vpc_endpoints:
    additional_ports:
      - port: 8080
        service: "custom-api"
  
  internet_ingress:
    custom_ports: [8080, 8443, 9000]
  
  eks_standard:
    cluster_name: "production-cluster"
```

### Important Notes

- **Opt-in Only**: Baseline profiles are never deployed automatically
- **Account-specific**: Each account chooses which profiles to enable
- **Managed by Platform**: Baseline security groups are managed by the security team
- **Automatic Updates**: When baseline profiles change, only opted-in accounts are updated
- **No Conflicts**: Baseline security groups use reserved names starting with `baseline-`

## 🔄 Submitting Changes

### Step 1: Create a Branch

```bash
git checkout -b update-security-groups-myteam
```

### Step 2: Make Changes

Edit your `accounts/123456789012/security-groups.yaml` file with your desired security group configuration.

### Step 3: Test Locally (Optional)

```bash
# Validate your configuration
python scripts/validate.py accounts/123456789012

# Check quota limits
python scripts/check-quotas.py 123456789012

# Generate Terraform (to preview)
python scripts/generate-terraform.py accounts/123456789012 --dry-run
```

### Step 4: Commit and Push

```bash
git add accounts/123456789012/security-groups.yaml
git commit -m "Add security groups for myteam production environment"
git push origin update-security-groups-myteam
```

### Step 5: Create Pull Request

1. Go to GitHub and create a Pull Request
2. Fill out the PR template with:
   - Purpose of the changes
   - Security justification for any open rules
   - Testing plan
3. Wait for validation checks to complete

## ✅ Understanding Validation

Every Pull Request triggers automatic validation checks:

### Schema Validation

Ensures your YAML follows the correct structure:
- ✅ Required fields present
- ✅ Data types correct
- ✅ Account ID format (12 digits)
- ✅ Security group names follow conventions

### Guardrail Validation

Enforces security policies:
- ❌ **Blocked CIDRs**: `0.0.0.0/0`, `169.254.169.254/32`
- ⚠️ **Warning Ports**: SSH (22), RDP (3389), Database ports
- ❌ **Blocked Ports**: Telnet (23), NetBIOS (139), SMB (445)
- ✅ **Port Range Limits**: Max 1000 ports per rule
- ✅ **Rule Count Limits**: Max 60 ingress + 60 egress rules

### Naming Validation

Enforces consistent naming:
- Must be lowercase alphanumeric with hyphens
- Must start and end with alphanumeric characters
- Maximum 63 characters
- Required tags must be present

### Quota Validation

Prevents AWS quota violations:
- Security groups per VPC (default: 2500)
- Rules per security group (default: 120)
- Warns at 80% utilization

### Example Validation Output

```
🔍 Validating AWS Security Groups for account: 123456789012
📁 Directory: accounts/123456789012

❌ Errors:
   • Security group 'web-servers' is missing required tag 'Team' [security_group.web-servers] (sg_required_tags)
   • Port 22 is blocked by policy in app-servers ingress[0] [security_group.app-servers.ingress[0]] (rule_blocked_port)

⚠️  Warnings:
   • Port 22 requires special attention in web-servers ingress[1] - consider using bastion/Session Manager [security_group.web-servers.ingress[1]] (rule_warning_port)

📊 Summary:
   Errors: 2
   Warnings: 1

❌ Validation failed with errors
```

## 🚀 Deployment Process

### Automatic Deployment Flow

1. **PR Created** → Validation runs
2. **PR Approved** → Ready for merge
3. **Merge to Main** → Deployment starts
4. **Terraform Apply** → Resources created/updated
5. **Status Update** → Results posted to Slack/GitHub

### Deployment Order

The platform deploys accounts in priority order:
1. **Development** accounts first (lower risk)
2. **Staging** accounts second (testing)
3. **Production** accounts last (highest care)

### What Gets Deployed

When you merge changes, the platform:

1. **Generates Terraform** from your YAML
2. **Plans Changes** showing what will be modified
3. **Applies Changes** to your AWS account
4. **Updates State** in centralized Terraform state
5. **Reports Results** via Slack and GitHub

### Rollback Process

If issues occur:
1. **Automatic Detection** of failed deployments
2. **Manual Rollback** via GitHub Actions
3. **Emergency Procedures** documented in runbooks

## 📊 Monitoring and Status

### Checking Deployment Status

**GitHub Actions**:
- Go to the repository's Actions tab
- Find your deployment run
- Review logs and status

**Slack Notifications**:
- `#security-groups` channel gets deployment updates
- Includes success/failure status and links

**AWS Console**:
- Check EC2 → Security Groups in your account
- Verify the security groups were created/updated

### Common Status Messages

- ✅ **"Deployment successful"** - Changes applied
- ⏳ **"Deployment in progress"** - Currently applying
- ❌ **"Validation failed"** - Fix YAML and retry
- ⚠️ **"Quota warning"** - Approaching AWS limits
- 🔄 **"Plan generated"** - Ready for approval

### Troubleshooting Deployments

If your deployment fails:

1. **Check validation errors** in the PR comments
2. **Review GitHub Actions logs** for detailed error messages
3. **Verify AWS permissions** are correct for your account
4. **Check quota limits** with `scripts/check-quotas.py`
5. **Ask for help** in `#security-groups` Slack channel

## ⚠️ Troubleshooting

### Common Issues

#### "Account ID mismatch"
```
Account ID mismatch: expected 123456789012, got 987654321098
```
**Solution**: Verify you're deploying to the correct AWS account or update the `account_id` field.

#### "VPC not found"
```
VPC vpc-12345678 not found in account
```
**Solution**: Check the VPC ID exists or use `vpc_id: "auto"` for automatic discovery.

#### "Security group limit exceeded"
```
Would exceed security groups per VPC limit (2500)
```
**Solution**: Clean up unused security groups or request quota increase.

#### "Invalid CIDR block"
```
Invalid CIDR block '10.0.0.0/33' in web-servers ingress[0]
```
**Solution**: Fix the CIDR notation (valid range: /0 to /32 for IPv4).

#### "Missing required tag"
```
Security group 'api-servers' is missing required tag 'Team'
```
**Solution**: Add all required tags: `Team`, `Environment`, `Application`, `ManagedBy`.

### Getting Help

1. **Check this documentation** for common patterns
2. **Review the example** in `accounts/_example/`
3. **Ask in Slack** `#security-groups` channel
4. **Create a GitHub issue** for bugs or feature requests
5. **Contact the platform team** for urgent issues

## 🏆 Best Practices

### Security Best Practices

1. **Principle of Least Privilege**
   ```yaml
   # Good: Specific CIDR
   cidr_blocks: ["10.100.0.0/24"]
   
   # Avoid: Open to internet unless necessary
   cidr_blocks: ["0.0.0.0/0"]
   ```

2. **Use Prefix Lists**
   ```yaml
   # Good: Managed prefix list
   prefix_list_ids: ["corporate-networks"]
   
   # Avoid: Hard-coded IPs
   cidr_blocks: ["203.0.113.1/32", "203.0.113.2/32"]
   ```

3. **Meaningful Descriptions**
   ```yaml
   # Good: Clear purpose
   description: "HTTPS from ALB to backend API servers"
   
   # Avoid: Vague descriptions
   description: "Web traffic"
   ```

4. **Avoid SSH/RDP Direct Access**
   ```yaml
   # Better: Use bastion/Session Manager
   security_groups: ["bastion-production"]
   
   # Avoid: Direct SSH from internet
   cidr_blocks: ["0.0.0.0/0"]  # Port 22
   ```

### Naming Conventions

1. **Security Group Names**
   ```yaml
   # Good examples:
   eks-nodes-production
   alb-api-staging
   rds-postgres-dev
   
   # Follow pattern: service-purpose-environment
   ```

2. **Consistent Tagging**
   ```yaml
   tags:
     Team: "backend"              # Owning team
     Environment: "production"    # Environment tier
     Application: "order-api"     # Application name
     Purpose: "web-servers"       # Specific purpose
     CostCenter: "engineering"    # Optional: billing
   ```

### YAML Organization

1. **Group Related Rules**
   ```yaml
   ingress:
     # Application traffic
     - protocol: "tcp"
       from_port: 8080
       to_port: 8080
       description: "Application HTTP"
     
     # Health checks
     - protocol: "tcp"
       from_port: 8081
       to_port: 8081
       description: "Health check endpoint"
     
     # Administrative access
     - protocol: "tcp"
       from_port: 22
       to_port: 22
       description: "SSH from bastion"
   ```

2. **Use Comments**
   ```yaml
   security_groups:
     # Production web servers behind ALB
     web-production:
       description: "Production web servers"
       # ... configuration
     
     # Staging environment for testing
     web-staging:
       description: "Staging web servers"
       # ... configuration
   ```

### Change Management

1. **Small, Incremental Changes**
   - Add one security group per PR
   - Test in development first
   - Deploy to staging before production

2. **Clear Commit Messages**
   ```bash
   # Good
   git commit -m "Add security group for Redis cache servers in production"
   
   # Avoid
   git commit -m "Update security groups"
   ```

3. **Document Security Justifications**
   - Include reasoning for open rules in PR description
   - Reference security reviews or approvals
   - Document temporary rules with expiration dates

### Performance Optimization

1. **Minimize Rule Count**
   ```yaml
   # Good: Use port ranges
   from_port: 8000
   to_port: 8099
   
   # Avoid: Multiple single-port rules
   ```

2. **Use Security Group References**
   ```yaml
   # Good: Reference other security groups
   security_groups: ["alb-production"]
   
   # Avoid: Hard-coding CIDR blocks when possible
   ```

3. **Leverage Prefix Lists**
   ```yaml
   # Good: Centrally managed IP ranges
   prefix_list_ids: ["database-subnets"]
   
   # Better: Than listing all individual subnets
   ```

### Environment Strategy

1. **Environment Separation**
   ```
   accounts/
   ├── 111111111111/  # Production account
   ├── 222222222222/  # Staging account  
   └── 333333333333/  # Development account
   ```

2. **Promote Changes Through Environments**
   - Develop → Stage → Production
   - Test thoroughly in each environment
   - Use identical configurations when possible

---

## 📚 Additional Resources

- [Naming Conventions](naming-conventions.md)
- [Example Configurations](examples/)
- [Troubleshooting Runbook](#troubleshooting)
- [Security Guidelines](https://wiki.company.com/security)
- [AWS Security Group Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html)

---

**Need help?** Reach out to the platform team:
- Slack: `#security-groups`
- Email: platform-team@company.com
- On-call: PagerDuty "AWS Platform"