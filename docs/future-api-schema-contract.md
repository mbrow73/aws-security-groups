# Future API / Schema Contract

This document defines the target contract for the future API/UI front door.

It is **not active runtime behavior yet**. The current supported production model remains documented in [Current Supported Model](current-supported-model.md): one account directory with one `security-groups.yaml` file.

The future API should be a thin orchestration layer over GitHub PRs, validation, and Terraform Enterprise. It should not become a separate source of truth.

## Design Goals

- Keep Git/PR/Terraform as the execution backbone.
- Make request intent explicit and machine-validatable.
- Support future ownership and review automation.
- Prepare for multi-tenant accounts without enabling tenant-split behavior prematurely.
- Keep requestor inputs simple.
- Make API-generated YAML compatible with the existing Terraform input model for as long as possible.

## Non-Goals

The future API should not:

- bypass GitHub PR review
- bypass Terraform Enterprise
- maintain a separate mutable security group database as source of truth
- introduce cross-account security group references as the preferred model
- require requestors to understand Terraform internals
- expose tenant-split layout until the platform explicitly enables it

## Core Resources

### Account

Represents one managed AWS account.

Required fields:

```yaml
account_id: "123456789012"
environment: "prod"
carid: "600001725"
```

Optional / future fields:

```yaml
account_name: "payments-prod"
default_region: "us-east-1"
regions:
  - "us-east-1"
  - "us-west-2"
owner_team: "payments-platform"
service_name: "payments-api"
tenant: null
lifecycle_state: "active"
```

Notes:

- `account_id`, `environment`, and `carid` are current required fields.
- `owner_team`, `service_name`, and `tenant` are future-facing metadata fields.
- `tenant` should remain optional and dormant until tenant support is explicitly enabled.

### Security Group

Represents one self-service security group intent.

Target shape:

```yaml
name: "app-backend"
description: "Backend API service"
regions:
  - "us-east-1"
owner_team: "payments-platform"
service_name: "payments-api"
tags:
  cost-center: "example"
ingress: []
egress: []
```

Current YAML compatibility:

```yaml
security_groups:
  app-backend:
    description: "Backend API service"
    ingress: []
    egress: []
```

Notes:

- API objects may use explicit `name`; current YAML uses the security group map key as the name.
- API should render current-compatible YAML until the runtime model changes.
- `owner_team` and `service_name` may initially be account-level metadata before becoming SG-level metadata.

### Rule

Represents one ingress or egress rule.

Target shape:

```yaml
direction: "egress"
protocol: "tcp"
from_port: 443
to_port: 443
description: "HTTPS to approved on-prem services"
destinations:
  cidr_blocks:
    - "10.0.0.0/8"
  prefix_list_ids: []
  security_groups: []
  baseline_refs: []
  self: false
```

Current YAML compatibility:

```yaml
- protocol: "tcp"
  from_port: 443
  to_port: 443
  cidr_blocks:
    - "10.0.0.0/8"
  description: "HTTPS to approved on-prem services"
```

Rules:

- each rule must have a clear business / technical description
- each rule should use one primary selector type where practical
- cross-account connectivity should use CIDR or prefix-list based selectors
- same-account SG references are allowed when supported by current validation and account topology
- cross-account SG references are not the preferred model

## Ownership Metadata

Future ownership metadata should be designed around stable slugs, not free-text prose.

Recommended future fields:

```yaml
owner_team: "payments-platform"
service_name: "payments-api"
data_classification: "internal"
change_risk: "standard"
```

Ownership metadata should eventually map to a lightweight registry:

```yaml
owners:
  payments-platform:
    github_reviewers:
      - "org/payments-platform-approvers"
    slack_channel: "payments-platform-netsec"
```

Implementation guidance:

- start optional and warning-only
- validate against registry after registry exists
- move from warning to error only after metadata quality is good
- derive review hints from ownership metadata before enforcing hard owner approval

## Tenant Metadata

Tenant support is future-only. The API/schema should reserve the concept now without activating tenant layout.

Potential future fields:

```yaml
tenant: "payments"
tenant_enabled: false
```

Tenant rules:

- tenant slugs must be platform-defined, not free-text invented by requestors
- tenant split should remain disabled by default
- tenant support should be feature-flagged per account
- no account should mix legacy single-file layout and tenant-split layout unless explicitly supported by the platform
- cross-tenant references must be validated and may require multiple owner approvals

## Lifecycle / Status Fields

Future API responses should expose lifecycle and workflow state, even if the source of truth remains GitHub/TFE.

Recommended API response fields:

```yaml
request_id: "sgreq-2026-000123"
status: "pr_open"
account_id: "123456789012"
branch: "sgreq/payments-api-egress"
pull_request_url: "https://github.com/org/repo/pull/123"
tfe_run_url: "https://app.terraform.io/app/org/workspaces/ws/runs/run-abc"
validation_status: "passed"
plan_status: "pending"
created_by: "user@example.com"
created_at: "2026-05-03T00:00:00Z"
updated_at: "2026-05-03T00:05:00Z"
```

Possible statuses:

- `draft`
- `validation_failed`
- `pr_open`
- `review_required`
- `plan_pending`
- `plan_failed`
- `ready_to_merge`
- `merged`
- `applied`
- `rejected`
- `closed`

## API Operations

Future API operations should map to Git operations and PR workflow.

Recommended operations:

- `GET /accounts`
- `GET /accounts/{account_id}`
- `GET /accounts/{account_id}/security-groups`
- `POST /security-group-requests`
- `GET /security-group-requests/{request_id}`
- `POST /security-group-requests/{request_id}/validate`
- `POST /security-group-requests/{request_id}/submit`
- `POST /security-group-requests/{request_id}/close`

The `submit` action should create or update a GitHub branch and PR. It should not apply directly.

## Request Example

Example future request payload:

```yaml
account_id: "123456789012"
environment: "prod"
carid: "600001725"
owner_team: "payments-platform"
service_name: "payments-api"
security_groups:
  - name: "app-backend"
    description: "Backend API service"
    regions:
      - "us-east-1"
      - "us-west-2"
    egress:
      - protocol: "tcp"
        from_port: 443
        to_port: 443
        prefix_list_ids:
          - "shared-onprem-networks"
        description: "HTTPS to approved on-prem services"
```

Rendered current-compatible YAML:

```yaml
account_id: "123456789012"
environment: "prod"
carid: "600001725"
regions:
  - "us-east-1"
  - "us-west-2"
security_groups:
  app-backend:
    description: "Backend API service"
    egress:
      - protocol: "tcp"
        from_port: 443
        to_port: 443
        prefix_list_ids:
          - "shared-onprem-networks"
        description: "HTTPS to approved on-prem services"
```

## Compatibility Requirements

Until the runtime model changes, the API must render YAML compatible with:

- `accounts/<account-id>/security-groups.yaml`
- current `scripts/validate.py`
- current Terraform module input shape
- current TFE workspace deployment flow

Future-only fields should either:

- be omitted from rendered YAML, or
- be added only after validator and Terraform compatibility are updated

## Development Order

Recommended implementation order:

1. document current single-tenant contract
2. document future API/schema contract
3. add optional ownership metadata to current YAML
4. add lightweight owner registry
5. validate metadata against registry
6. improve PR/Slack summary output
7. add owner-aware review hints
8. design dormant tenant model
9. add tenant split tests behind internal fixtures
10. feature-flag tenant split per account
11. migrate only when a real multi-tenant account appears
12. enforce owner review
13. build thin API/UI front door
