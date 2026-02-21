# AWS Security Group Platform

A self-service platform for managing AWS Security Groups across multiple accounts using GitOps principles. Teams define their security group requirements in simple YAML files, and Terraform reads them directly using `yamldecode()` - no code generation needed!

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  Team YAML      │    │  GitHub Actions  │    │  Terraform Cloud    │
│  Configuration  │───▶│  (Validation)    │    │  yamldecode() +     │
└─────────────────┘    └──────────────────┘    │  Plan/Apply         │
        │                        │              └─────────────────────┘
        │                        ▼                        │
        │              ┌──────────────────┐               ▼
        │              │  Guardrails &    │    ┌─────────────────────┐
        │              │  Validation      │    │  VCS-Driven         │
        │              └──────────────────┘    │  Workspaces         │
        │                        │              └─────────────────────┘
        ▼                        ▼                        │
┌─────────────────┐    ┌──────────────────┐               ▼
│  Baseline       │    │  Speculative     │    ┌─────────────────────┐
│  Profiles       │    │  Plans on PR     │    │  AWS Security       │
│  (Opt-In)       │    │                  │    │  Groups             │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
```

### Key Features

- **🎯 Team-Centric**: Simple YAML interface for security group definitions
- **🚀 No Code Generation**: Terraform reads YAML directly with `yamldecode()` 
- **🔒 Secure by Default**: Built-in guardrails and validation
- **📊 GitOps Driven**: All changes via Pull Requests with approval workflows
- **☁️ Terraform Cloud**: VCS-driven workspaces with speculative plans and auto-apply
- **🏠 Multi-Account**: Isolated TFC workspaces per AWS account
- **⚡ Baseline + Custom**: Opt-in baseline security group profiles, plus team-specific ones
- **🔍 Dynamic Discovery**: VPC information discovered at runtime, no manual registry
- **📋 Prefix Lists**: Reusable CIDR blocks for common services
- **🎛️ EKS-Optimized**: Predefined patterns for Kubernetes workloads

## 📁 Repository Structure

```
aws-security-groups/
├── README.md                      # This file
├── guardrails.yaml               # Validation rules as configuration
├── prefix-lists.yaml             # Managed prefix list definitions
├── terraform/                    # Shared Terraform configuration (all workspaces)
│   ├── main.tf                   # Calls account module with dynamic YAML path
│   ├── backend.tf                # Generic TFC cloud backend
│   ├── providers.tf              # AWS provider with account-specific assume role
│   └── variables.tf              # account_id and aws_region variables
├── .github/workflows/            # GitHub Actions pipelines
│   └── validate-pr.yml           # PR validation + auto workspace creation
├── baseline/                     # Baseline security group profiles (opt-in)
│   ├── profiles/                 # Modular baseline profiles
│   │   ├── vpc-endpoints/        # VPC endpoint access profile
│   │   ├── internet-ingress/     # WAF/CDN → NLB traffic profile
│   │   └── eks-standard/         # EKS cluster communication profile
│   ├── main.tf
│   ├── prefix-lists.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── providers.tf
│   └── backend.tf
├── modules/                      # Reusable Terraform modules
│   ├── account/                  # Main account module (uses yamldecode)
│   ├── security-group/           # Security group creation module
│   └── vpc-discovery/            # VPC information discovery
├── scripts/                      # Python automation scripts
│   ├── validate.py               # YAML and guardrail validation
│   ├── check-quotas.py          # AWS quota pre-checks
│   ├── discover-accounts.py     # Account discovery helper
│   └── setup-tfc-workspaces.sh  # Bulk TFC workspace setup
├── accounts/                     # Team security group definitions (YAML only)
│   ├── _example/                 # Example configuration
│   │   └── security-groups.yaml # Reference implementation
│   ├── 123456789012/            # Account-specific directory
│   │   └── security-groups.yaml # Team's YAML file (that's it!)
│   └── 234567890123/            # Another account
│       └── security-groups.yaml # Another team's YAML file
└── docs/                        # Documentation
    ├── team-guide.md            # Step-by-step guide for teams
    ├── tfc-setup.md             # TFC workspace configuration
    ├── naming-conventions.md    # Naming standards
    └── examples/               # Copy-paste examples
        └── eks-standard.yaml
```

## 🚀 Quick Start for Teams

1. **Create directory**: `mkdir accounts/YOUR-ACCOUNT-ID`
2. **Add YAML file**: Copy and customize `accounts/_example/security-groups.yaml`
3. **Submit Pull Request** - TFC workspace auto-created, validation runs automatically!
4. **Get approval** from the security team  
5. **Merge** - security groups are deployed automatically via `yamldecode()`

That's it! No Terraform files to manage - just one YAML file per account.

See [`docs/team-guide.md`](docs/team-guide.md) for detailed instructions.

## 📝 YAML Configuration Format

Teams define security groups using a simple YAML format:

```yaml
# accounts/123456789012/security-groups.yaml
account_id: "123456789012"
region: "us-east-1"
vpc_id: "auto"  # Auto-discover single VPC, or specify explicit VPC ID

security_groups:
  - name: "my-app-eks-nodes"
    type: "eks-nodes"  # Predefined type with common rules
    description: "EKS worker nodes for my-app cluster"
    tags:
      Team: "my-team"
      Environment: "production"
      Application: "my-app"
    
    ingress:
      - from_port: 80
        to_port: 80
        protocol: "tcp"
        source_security_groups: ["baseline-alb-sg"]  # Reference baseline SG
        description: "HTTP from ALB"
      
      - from_port: 443
        to_port: 443
        protocol: "tcp"
        cidr_blocks: ["10.0.0.0/8"]
        description: "HTTPS from internal networks"

    egress:  # EKS-nodes type has predefined egress rules
      - from_port: 6379
        to_port: 6379
        protocol: "tcp"
        prefix_list_ids: ["database-subnets"]  # Use managed prefix list
        description: "Redis access"
```

## 🛡️ Security & Compliance

### Guardrails

The platform enforces security best practices through configurable guardrails:

- **Blocked CIDRs**: Prevents overly permissive rules (0.0.0.0/0)
- **Port Restrictions**: Warns on sensitive ports, blocks insecure protocols
- **Rule Limits**: Enforces AWS quota limits
- **Naming Standards**: Consistent naming conventions
- **Required Tags**: Ensures proper resource tagging

### Approval Workflow

All changes require:
1. **Automated validation** - syntax, guardrails, quota checks, naming conventions
2. **Speculative plan** - Terraform Cloud shows exact changes on PR
3. **Human approval** - security team review (required by compliance)
4. **Auto-deployment** - Terraform Cloud applies changes after merge

### Audit Trail

- **Git history** serves as the system of record
- **PR discussions** capture decision rationale  
- **Deployment logs** track all changes
- **State files** stored in S3 with versioning

## 🔧 Architecture Decisions

### Why YAML over JSON/HCL?
- **Human-readable** and **team-friendly**
- **Comments** for documenting decisions
- **Simpler** than raw Terraform for non-infrastructure teams

### Why Dynamic VPC Discovery?
- **No manual registry** to maintain
- **Auto-adapts** to infrastructure changes
- **Reduces** configuration errors
- **Simpler** for teams (just provide account ID)

### Why Baseline Profiles?
- **Common patterns** available on opt-in basis
- **Team autonomy** to choose needed patterns
- **Reduced duplication** of standard rules
- **Modular approach** - select only what you need
- **Easier compliance** - standard patterns maintained centrally

### Why Terraform State per Account?
- **Blast radius isolation** - changes in one account don't affect others
- **Parallel deployment** - faster operations
- **Account-level permissions** - proper separation of concerns

## 🏃 Operations

### Adding a New Account

1. **Copy template**: `cp -r accounts/_template accounts/NEW-ACCOUNT-ID`
2. **Update files**: Replace placeholder values in `backend.tf`, `providers.tf`, and `security-groups.yaml`
3. **Submit PR**: Terraform Cloud workspace created automatically
4. **Deploy**: Account-specific groups deployed via `yamldecode()` on merge

### Updating Guardrails

1. Edit `guardrails.yaml` in the root
2. No code changes required - rules are configuration-driven
3. Changes take effect on next PR validation

### Managing Prefix Lists

1. Update `prefix-lists.yaml` in the root
2. Baseline sync workflow updates accounts using affected profiles
3. Teams can reference in their YAML immediately

### Emergency Changes

1. **Direct Terraform** - manual application via TFC UI or CLI for urgent fixes
2. **Follow-up PR** - must sync the YAML to match reality
3. **Audit flags** - emergency changes are tracked in TFC logs

## 📊 Monitoring & Alerting

### What We Monitor

- **TFC deployment failures** - failed Terraform Cloud applies
- **Quota exhaustion** - approaching AWS limits  
- **Guardrail violations** - teams pushing boundaries
- **Drift detection** - manual changes outside the platform

### Key Metrics

- **PR to deployment time** - platform efficiency
- **Validation failure rate** - guardrail effectiveness
- **Account coverage** - platform adoption
- **Rule complexity** - security group health

## 🤝 Contributing

### For Platform Engineers

1. **Scripts** - enhance validation, quota checking, or generation
2. **Modules** - improve Terraform modules
3. **TFC Setup** - optimize Terraform Cloud workspaces and automation
4. **Documentation** - keep guides current

### For Security Engineers

1. **Guardrails** - update security rules in `guardrails.yaml`
2. **Prefix Lists** - maintain service IP ranges
3. **Baseline Profiles** - evolve opt-in security patterns
4. **Review Process** - participate in PR approvals

### For Teams

1. **Examples** - contribute working patterns in `docs/examples/`
2. **Feedback** - report issues, suggest improvements
3. **Adoption** - migrate existing security groups to the platform

## 📞 Support

### Get Help

- **Documentation**: Start with [`docs/team-guide.md`](docs/team-guide.md)
- **Examples**: Check [`docs/examples/`](docs/examples/) for copy-paste templates
- **Issues**: Create GitHub issues for bugs or feature requests
- **Slack**: `#aws-security-groups` for quick questions

### Common Issues

- **VPC Discovery Failures**: Check account permissions, VPC tags
- **Quota Errors**: Review rule complexity, consider consolidation
- **Validation Failures**: Check guardrails.yaml for current rules
- **Deployment Timeout**: Large rule sets may need account-specific tuning

## ⚙️ Setup & Migration

### Terraform Cloud Setup

The platform uses Terraform Cloud for deployment. See the setup guide:

1. **[TFC Setup Guide](docs/tfc-setup.md)** - Complete migration and workspace setup
2. **[Workspace Script](scripts/setup-tfc-workspaces.sh)** - Automated workspace creation
3. **Organization Setup** - Replace `ORGANIZATION_NAME` in backend configs

### New Team Onboarding

1. **Copy template**: `cp -r accounts/_template accounts/123456789012/`
2. **Configure**: Update `backend.tf`, `providers.tf`, and `security-groups.yaml` with your account details
3. **Submit PR**: TFC workspace is auto-created when PR is merged
4. **AWS Setup**: Configure OIDC/dynamic credentials in AWS account for Terraform Cloud

## 🗂️ Related Documentation

- [Team Guide](docs/team-guide.md) - Step-by-step instructions for teams
- [Naming Conventions](docs/naming-conventions.md) - Required naming standards
- [EKS Examples](docs/examples/eks-standard.yaml) - Common Kubernetes patterns
- [Terraform Modules](modules/README.md) - Technical implementation details

---

**Managed by the Platform Security Team** | **Questions? #aws-security-groups**