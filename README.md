# AWS Security Group Platform

A self-service platform for managing AWS Security Groups across multiple accounts using GitOps principles. Teams define their security group requirements in simple YAML files, and the platform handles the Terraform generation, validation, and deployment.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  Team YAML      │    │  GitHub Actions  │    │  AWS Accounts       │
│  Configuration  │───▶│  Pipeline        │───▶│  Security Groups    │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
        │                        │                        │
        │                        ▼                        │
        │              ┌──────────────────┐               │
        │              │  Guardrails &    │               │
        │              │  Validation      │               │
        │              └──────────────────┘               │
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  Baseline SGs   │    │  Terraform       │    │  VPC Discovery      │
│  (All Accounts) │    │  Generation      │    │  (Runtime)          │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
```

### Key Features

- **🎯 Team-Centric**: Simple YAML interface for security group definitions
- **🔒 Secure by Default**: Built-in guardrails and validation
- **📊 GitOps Driven**: All changes via Pull Requests with approval workflows
- **🏠 Multi-Account**: Isolated Terraform state per AWS account
- **⚡ Baseline + Custom**: Common security groups applied everywhere, plus team-specific ones
- **🔍 Dynamic Discovery**: VPC information discovered at runtime, no manual registry
- **📋 Prefix Lists**: Reusable CIDR blocks for common services
- **🎛️ EKS-Optimized**: Predefined patterns for Kubernetes workloads

## 📁 Repository Structure

```
aws-security-groups/
├── README.md                      # This file
├── guardrails.yaml               # Validation rules as configuration
├── prefix-lists.yaml             # Managed prefix list definitions
├── .github/workflows/            # GitHub Actions pipelines
│   ├── validate-pr.yml           # PR validation workflow
│   ├── apply.yml                 # Deployment on merge
│   └── baseline-sync.yml         # Baseline synchronization
├── baseline/                     # Common SGs applied to all accounts
│   ├── main.tf
│   ├── prefix-lists.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── providers.tf
│   └── backend.tf
├── modules/                      # Reusable Terraform modules
│   ├── security-group/           # Security group creation module
│   └── vpc-discovery/            # VPC information discovery
├── scripts/                      # Python automation scripts
│   ├── validate.py               # YAML and guardrail validation
│   ├── check-quotas.py          # AWS quota pre-checks
│   ├── generate-terraform.py    # YAML to Terraform conversion
│   └── discover-accounts.py     # Account discovery helper
├── accounts/                     # Team security group definitions
│   ├── _example/                 # Example configuration
│   ├── 123456789012/            # Account-specific SGs
│   └── 234567890123/            # Account-specific SGs
└── docs/                        # Documentation
    ├── team-guide.md            # Step-by-step guide for teams
    ├── naming-conventions.md    # Naming standards
    └── examples/               # Copy-paste examples
        └── eks-standard.yaml
```

## 🚀 Quick Start for Teams

1. **Create your account directory**: `accounts/YOUR-ACCOUNT-ID/`
2. **Add `security-groups.yaml`** with your security group definitions
3. **Create a Pull Request** - validation runs automatically
4. **Get approval** from the security team
5. **Merge** - security groups are deployed automatically

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
1. **Automated validation** - syntax, guardrails, quota checks
2. **Terraform plan** - shows exact changes
3. **Human approval** - security team review (required by financial regulations)
4. **Deployment** - baseline first, then account-specific

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

### Why Baseline + Per-Account?
- **Common patterns** applied consistently
- **Team autonomy** for specific needs
- **Reduced duplication** of standard rules
- **Easier compliance** - baseline ensures standards

### Why Terraform State per Account?
- **Blast radius isolation** - changes in one account don't affect others
- **Parallel deployment** - faster operations
- **Account-level permissions** - proper separation of concerns

## 🏃 Operations

### Adding a New Account

1. Create `accounts/NEW-ACCOUNT-ID/security-groups.yaml`
2. Baseline security groups are applied automatically
3. Account-specific groups deployed on first PR

### Updating Guardrails

1. Edit `guardrails.yaml` in the root
2. No code changes required - rules are configuration-driven
3. Changes take effect on next PR validation

### Managing Prefix Lists

1. Update `prefix-lists.yaml` in the root
2. Baseline sync workflow updates all accounts
3. Teams can reference in their YAML immediately

### Emergency Changes

1. **Direct Terraform** - manual application for urgent fixes
2. **Follow-up PR** - must sync the YAML to match reality
3. **Audit flags** - emergency changes are tracked

## 📊 Monitoring & Alerting

### What We Monitor

- **Deployment failures** - failed Terraform applies
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
3. **Workflows** - optimize GitHub Actions
4. **Documentation** - keep guides current

### For Security Engineers

1. **Guardrails** - update security rules in `guardrails.yaml`
2. **Prefix Lists** - maintain service IP ranges
3. **Baseline** - evolve common security patterns
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

## 🗂️ Related Documentation

- [Team Guide](docs/team-guide.md) - Step-by-step instructions for teams
- [Naming Conventions](docs/naming-conventions.md) - Required naming standards
- [EKS Examples](docs/examples/eks-standard.yaml) - Common Kubernetes patterns
- [Terraform Modules](modules/README.md) - Technical implementation details

---

**Managed by the Platform Security Team** | **Questions? #aws-security-groups**