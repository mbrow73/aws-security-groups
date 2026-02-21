# Account Template for AWS Security Group Platform

This template provides a starting point for onboarding a new AWS account to the Security Group Platform.

## Quick Start

1. **Copy this template directory to your account**:
   ```bash
   cp -r accounts/_template accounts/123456789012
   cd accounts/123456789012
   ```

2. **Update the configuration files**:

   ### backend.tf
   - Replace `YOUR_ORG_NAME` with your Terraform Cloud organization
   - Replace `YOUR_ACCOUNT_ID` with your 12-digit AWS account ID

   ### providers.tf  
   - Replace `YOUR_ACCOUNT_ID` with your 12-digit AWS account ID
   - Configure assume_role if needed for cross-account deployment

   ### security-groups.yaml
   - Replace `YOUR_ACCOUNT_ID` with your 12-digit AWS account ID
   - Replace `YOUR_TEAM_NAME` with your team name
   - Update the environment (production, staging, development)
   - Add your security group configurations

3. **Test your configuration**:
   ```bash
   # From the repo root
   python scripts/validate.py accounts/123456789012
   ```

4. **Submit a PR**:
   - No code generation needed!
   - Terraform will read your YAML file directly using `yamldecode()`

## What's Different from the Old Approach

### Before (with generate-terraform.py):
1. Teams wrote YAML files
2. Generated .tf files using `python scripts/generate-terraform.py`
3. Committed generated files or generated them at runtime
4. Terraform ran the generated .tf files

### Now (with yamldecode):
1. Teams write YAML files
2. Terraform reads YAML directly using `yamldecode(file(...))`
3. No code generation step needed
4. Terraform processes everything natively

## Files in this Template

- **main.tf**: Calls the account module with your YAML file
- **backend.tf**: Terraform Cloud backend configuration
- **providers.tf**: AWS provider with account validation
- **variables.tf**: Input variables for the deployment
- **security-groups.yaml**: Your security group configuration

## Configuration Options

### Basic Configuration (security-groups.yaml)
```yaml
account_id: "123456789012"
environment: "production"
tags:
  Team: "platform"

security_groups:
  web-app:
    description: "Web application servers"
    # ... rules here
```

### Advanced Options (main.tf)
```hcl
module "account" {
  source = "../../modules/account"
  
  yaml_file = "${path.module}/security-groups.yaml"
  
  # Enable additional features:
  enable_detailed_monitoring = true
  create_flow_logs          = true
  compliance_mode          = "sox"
}
```

## Baseline Profiles

Enable baseline security groups in your YAML:

```yaml
baseline_profiles:
  - vpc-endpoints      # AWS service access (S3, ECR, EKS API)
  - internet-ingress   # WAF/CDN → NLB (Cloudflare, Fastly)
  - eks-standard       # EKS cluster communication
```

## Validation

Your YAML file will be automatically validated for:
- ✅ Schema compliance
- ✅ Naming conventions  
- ✅ Guardrails policy
- ✅ Account ID consistency
- ✅ Security best practices

## Terraform Cloud Workspace

Once you submit your PR and it's approved:

1. Terraform Cloud workspace `sg-platform-123456789012` will be created
2. TFC will run `terraform plan` automatically
3. After manual approval, TFC will run `terraform apply`
4. Your security groups will be deployed!

## Need Help?

- 📖 See [Team Guide](../../docs/team-guide.md) for detailed instructions
- 📋 Review [examples](../../accounts/_example/security-groups.yaml) for configuration patterns
- 💬 Ask questions in #aws-security-groups Slack channel

## Migration from Old Approach

If you have existing generated Terraform files:

1. Keep your existing `security-groups.yaml` file (no changes needed!)
2. Delete any generated `.tf` files in your account directory
3. Copy the new template files (main.tf, backend.tf, providers.tf, variables.tf)
4. Update the template files with your account information
5. Submit a PR - the platform will use the YAML directly now