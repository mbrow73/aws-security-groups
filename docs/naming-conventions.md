# Naming Conventions

## Security Group Names

| Pattern | Example | Used By |
|---|---|---|
| `baseline-{component}` | `baseline-eks-workers` | Baseline profiles |
| `{team}-{app}-{purpose}` | `payments-api-db-access` | Team SGs |

## Prefix List Names

| Pattern | Example |
|---|---|
| `{category}-{scope}` | `corporate-networks`, `database-subnets` |
| `waf-{provider}` | `waf-saas-providers`, `waf-nat-ips` |

## Tags (Required)

| Tag | Description | Example |
|---|---|---|
| `Team` | Owning team | `payments` |
| `Environment` | Deployment environment | `prod` |
| `Application` | Application name | `order-service` |
| `ManagedBy` | Always `sg-platform` | `sg-platform` |

Baseline SGs also include:
| Tag | Description | Example |
|---|---|---|
| `Profile` | Baseline profile name | `eks-standard` |
| `Type` | Always `baseline` | `baseline` |

## Repository Structure

```
aws-security-groups/
├── accounts/
│   └── {account-id}/
│       └── security-groups.yaml
# Baselines: see terraform-aws-eks-baseline-sgs repo
│   ├── main.tf                  # Orchestrator
│   ├── profiles/                # Baseline SG definitions
│   ├── prefix-lists.tf          # Org-wide prefix lists
│   └── tests/                   # Orchestrator-level tests
├── modules/
│   ├── account/                 # Per-account deployment
│   ├── security-group/          # Generic SG from YAML
│   └── vpc-discovery/           # VPC auto-discovery
├── scripts/
│   └── validate.py              # PR validation
├── tests/
│   └── test_validate.py         # Pytest suite
├── guardrails.yaml              # Validation rules
└── prefix-lists.yaml            # Prefix list definitions
```

## TFE Workspace Names

> Workspaces are auto-provisioned via CloudIaC API. See [TFE Setup](tfe-setup.md).

| Pattern | Example |
|---|---|
| `sg-{account_id}` | `sg-111222333444` |
| `sg-account-{account_id}` | `sg-account-111222333444` |
