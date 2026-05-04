# Tenant / Owner Registry Design

This document defines the target registry model for tenant ownership and review metadata.

It is a design contract for future implementation. The current runtime remains single-tenant-per-account until registry validation and tenant support are explicitly enabled.

## Goals

- Make tenant ownership discoverable and reviewable.
- Avoid free-text owner drift in security group YAML.
- Support future owner-aware review automation.
- Keep current single-tenant accounts compatible through an implicit `default` tenant.
- Give new teams a clear onboarding path.
- Let future API/UI users find valid tenants by account, CARID, owner team, or display name.

## Design Principles

- Tenants are **platform ownership domains**, not random app names.
- Tenant slugs are platform-defined and stable.
- Requestors should not invent tenant slugs inside SG requests.
- CARID is a lookup key, not the only ownership source of truth.
- Allowed accounts should eventually scope where a tenant can request SGs.
- New tenant onboarding starts as a GitHub issue and becomes a reviewed registry PR.

## Future Registry File

Recommended future path:

```text
registry/tenants.yaml
```

Initial shape:

```yaml
tenants:
  default:
    display_name: "Default Single-Tenant Account"
    description: "Compatibility tenant for legacy single-file account configs."
    status: "legacy"
    owner_team: null
    review_authority: "platform-sg"
    github_reviewers: []
    slack_channel: null
    carids: []
    allowed_accounts: []

  payments-platform:
    display_name: "Payments Platform"
    description: "Payments platform ownership domain."
    status: "active"
    owner_team: "payments-platform"
    review_authority: "payments-sg"
    github_reviewers:
      - "org/payments-platform-approvers"
    slack_channel: "payments-platform-netsec"
    carids:
      - "600001725"
    allowed_accounts:
      - "123456789012"
    reference_grants:
      - name: "allow-https-to-shared-api"
        description: "Shared API accepts HTTPS from internal tenant SGs."
        target_sgs:
          - "shared-api"
        source_tenants:
          - "*"
        protocols:
          - "tcp"
        ports:
          - 443
        directions:
          - "egress"
        decision: "auto_approved"
        expires: null
```

## Field Definitions

### `tenant` / map key
Stable slug used by API, validation, review routing, and future tenant paths.

Rules:
- lowercase
- kebab-case
- platform ownership domain, not temporary project name
- stable across team display-name changes

### `display_name`
Human-friendly name shown in docs/API/UI.

### `description`
Short explanation of what the ownership domain covers.

### `status`
Lifecycle state.

Suggested values:
- `active`
- `legacy`
- `deprecated`
- `disabled`

### `owner_team`
Stable internal owner slug. This may match the tenant slug when that is cleanest.

### `review_authority`
Named authority from `registry/review-authorities.yaml`.

Review Gate uses this field for enforcement. It resolves the authority to actual GitHub Enterprise team membership using `SG_FRAMEWORK_PAT`.

### `github_reviewers`
GitHub users or teams to request for native reviewer UX.

Prefer GitHub teams over individual users. Enforcement should use `review_authority`, not this field.

### `slack_channel`
Optional notification target for future Slack/PR summary routing.

### `carids`
CARIDs associated with this tenant. Used for discovery and sanity checks.

### `allowed_accounts`
AWS account IDs where this tenant is allowed to manage SGs.

This should be optional at first and stricter later. It prevents a tenant from accidentally or casually requesting SGs in unrelated accounts.

### `reference_grants`
Target-owned grants that pre-approve specific cross-tenant SG references under constrained conditions.

Use this only when the referenced tenant intentionally accepts common references, for example HTTPS to a shared service SG.

See [Reference Grants](reference-grants.md).

## Discovery Model

Requestors should be able to find their tenant by checking:

- tenant slug
- display name
- review authority / GitHub reviewer team
- CARID
- AWS account ID

Docs and the future API should point users to:

```text
registry/tenants.yaml
```

Future API discovery endpoints may include:

```text
GET /tenants
GET /tenants?account_id=123456789012
GET /tenants?carid=600001725
GET /tenants?owner_team=payments-platform
```

## New Tenant Onboarding

If a team cannot find its tenant, it should open a GitHub issue using the tenant onboarding template.

The issue should collect:

- requested tenant slug
- display name
- business / platform ownership domain
- owner team
- GitHub reviewer team
- CARID(s)
- allowed account(s)
- Slack channel
- justification / workload context

Platform/security reviews the issue and creates or approves a PR to update the registry.

Requestors should not bypass onboarding by inventing a tenant in SG YAML.

## Legacy Compatibility

Current single-file accounts:

```text
accounts/<account-id>/security-groups.yaml
```

resolve conceptually as:

```yaml
tenant: "default"
```

This is an internal compatibility rule. Current requestors do not need to type `tenant: default` in YAML.

## Future Tenant-Split Compatibility

Future tenant-split path:

```text
accounts/<account-id>/<tenant>/security-groups.yaml
```

resolves tenant from the path. The API should own path rendering so requestors express tenant intent once.

The dormant tenant-split layout contract is tracked in [Tenant-Split Layout Contract](tenant-split-layout-contract.md).

## Review Semantics

Future owner-aware review should use the registry as input.

Suggested review classes:

1. **Platform built-in SG references**
   - platform-owned SGs such as `vpc-endpoints`
   - requestors reference them with normal `security_groups` syntax
   - may become auto-approval eligible after a separate trust/reference policy is defined

2. **Same-tenant references**
   - normal owner review for the tenant

3. **Cross-tenant references**
   - review required from requester tenant and target tenant

4. **Cross-account references**
   - should remain CIDR/prefix-list based unless explicitly approved by platform/security

## Current Warning-Only Validation

The first implementation phase creates `registry/tenants.yaml` and validates the current legacy layout against the implicit `default` tenant.

Current behavior:

- `accounts/<account-id>/security-groups.yaml` resolves as tenant `default`
- malformed `registry/tenants.yaml` is an error
- missing `default` tenant is a warning
- account not listed in `default.allowed_accounts` is a warning
- deprecated/disabled tenant status is a warning

Warnings are non-blocking in PR validation.

PR and Slack summaries use the shared tenant context resolver and include current registry context for each changed account:

- implicit legacy tenant slug (`default`) for `accounts/<account-id>/security-groups.yaml`
- future path tenant slug for `accounts/<account-id>/<tenant>/security-groups.yaml`
- tenant display name / status
- owner team when present
- whether the changed account is listed under tenant `allowed_accounts`

## Out of Scope for This Step

This registry design does not yet implement:

- hard validator enforcement
- owner-aware PR review requests
- auto-approval logic
- tenant-split deployment

Those belong to later steps.

## Future Follow-Up: Trust / Reference Policy

A separate policy should define low-risk reference classes and auto-approval candidates.

Example future candidate:

```yaml
egress:
  - protocol: "tcp"
    from_port: 443
    to_port: 443
    security_groups:
      - "vpc-endpoints"
    description: "Access AWS VPC endpoints"
```

This should not be implemented as part of tenant registry design, but the registry should support the ownership metadata needed for later review automation.

## Registry Validation

The validator checks tenant registry structure before relying on it for ownership or review policy.

It validates:

- tenant slug format
- tenant status values
- `review_authority` references
- AWS account ID format
- CARID format
- reference grant schema

Malformed registry metadata fails validation so review and reference policy cannot silently drift.
