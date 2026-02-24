# Terraform Enterprise Setup Guide

## Architecture

Each AWS account gets its own TFE workspace, provisioned automatically via the CloudIaC API when a new account directory is merged:

```
TFE Organization
├── sg-111222333444     → accounts/111222333444/ (team SGs)
├── sg-555666777888     → accounts/555666777888/
└── sg-999888777666     → accounts/999888777666/
```

Baseline SGs are deployed separately via [`terraform-aws-eks-baseline-sgs`](https://github.com/mbrow73/terraform-aws-eks-baseline-sgs) through AFT account customizations.

## Workspace Provisioning

Workspaces are auto-provisioned by `.github/workflows/tfe-provision.yml` on merge to main via the CloudIaC API (`scripts/tfe_workspace.py`).

### What happens on merge:

1. Detect which account directories changed
2. For each changed account, create a TFE workspace via CloudIaC:
   - Name: `sg-{account_id}`
   - Environment: read from account YAML (`prod`, `test`, `dev`)
   - VCS: attached to this repository
   - Trigger patterns: `accounts/{id}/**`, `modules/**`, `prefix-lists.yaml`, `guardrails.yaml`
3. VCS-driven runs auto-trigger on workspace creation and subsequent merges

### Required Secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `CLDIAC_URL` | Yes | CloudIaC API base URL |
| `CLDIAC_AUTH_URL` | Yes | Auth service URL |
| `CLDIAC_USER` | Yes | AD service account ID |
| `CLDIAC_PASSWORD` | Yes | AD service account key |
| `CLDIAC_CAR_ID` | Yes | Cloud account reference |
| `CLDIAC_PROJECT_ID` | Yes | TFE project ID |
| `CLDIAC_REPOSITORY` | Yes | Repo to attach |
| `CLDIAC_AUTH_ENV` | No | Auth environment header (default: E1) |
| `CLDIAC_CREDS_PROVIDER` | No | Dynamic credentials provider (default: aws) |
| `CLDIAC_CREDS_AUTH` | No | IAM role ARN for TFE |

## IAM Role for TFE

Each account needs a deploy role that TFE assumes. The role should have:

- `ec2:*SecurityGroup*` — create, modify, delete SGs and rules
- `ec2:DescribeVpcs` — VPC auto-discovery
- `ec2:*PrefixList*` — manage prefix lists (if applicable)

Lock this role down via SCP so only the TFE workspace can assume it (see [Anti-Patterns](anti-patterns-and-mitigations.md#risk-2-additive-rules-blow-open-baselines)).

## Speculative Plans

TFE automatically runs speculative plans when a PR modifies files in a workspace's trigger path. Reviewers see the plan output directly on the PR.
