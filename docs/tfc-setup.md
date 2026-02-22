# Terraform Cloud Setup Guide

## Architecture

Each AWS account gets its own TFC workspace:

```
TFC Organization
├── sg-baseline-111222333444    → baseline/ (profiles + prefix lists)
├── sg-baseline-555666777888    → baseline/
├── sg-account-111222333444     → modules/account (team SGs)
└── sg-account-555666777888     → modules/account
```

## Workspace Configuration

### Baseline Workspace (per account)

| Setting | Value |
|---|---|
| Name | `sg-baseline-{account_id}` |
| Working Directory | `baseline/` |
| VCS Branch | `main` |
| Trigger Paths | `baseline/**`, `prefix-lists.yaml` |
| Auto Apply | No (require approval) |

**Variables:**

| Variable | Type | Value |
|---|---|---|
| `account_id` | terraform | `123456789012` |
| `vpc_id` | terraform | `vpc-0abc123...` or `auto` |
| `baseline_profiles` | terraform | `["eks-standard"]` |
| `region` | terraform | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | env (sensitive) | From account's deploy role |
| `AWS_SECRET_ACCESS_KEY` | env (sensitive) | From account's deploy role |

### Account Workspace (per account)

| Setting | Value |
|---|---|
| Name | `sg-account-{account_id}` |
| Working Directory | `modules/account` |
| VCS Branch | `main` |
| Trigger Paths | `accounts/{account_id}/**`, `guardrails.yaml`, `prefix-lists.yaml` |
| Auto Apply | No |

**Variables:**

| Variable | Type | Value |
|---|---|---|
| `yaml_file` | terraform | Path to account's `security-groups.yaml` |
| `AWS_ACCESS_KEY_ID` | env (sensitive) | From account's deploy role |
| `AWS_SECRET_ACCESS_KEY` | env (sensitive) | From account's deploy role |

## Speculative Plans on PR

TFC automatically runs speculative plans when a PR modifies files in a workspace's trigger path. Reviewers see the plan output directly on the PR.

## IAM Role for TFC

Each account needs a deploy role that TFC assumes. The role should have:
- `ec2:*SecurityGroup*` — create/modify/delete SGs and rules
- `ec2:*PrefixList*` — manage prefix lists
- `ec2:DescribeVpcs` — VPC discovery
- `sts:GetCallerIdentity` — account validation

Lock this role down via SCP so only the TFC workspace can assume it (see [Anti-Patterns](anti-patterns-and-mitigations.md#risk-2-additive-rules-blow-open-baselines)).
