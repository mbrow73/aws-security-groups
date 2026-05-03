# Tenant-Split Layout Contract

This document defines the dormant V2 tenant layout contract.

It does **not** enable tenant-split deployment. The current supported runtime remains the legacy single-file account model until tenant split is explicitly feature-flagged.

## Current legacy layout

Supported today:

```text
accounts/<account-id>/security-groups.yaml
```

This resolves internally as tenant `default`.

## Future tenant-split layout

Future tenant-enabled accounts may use:

```text
accounts/<account-id>/<tenant>/security-groups.yaml
```

Example:

```text
accounts/123456789012/payments-platform/security-groups.yaml
accounts/123456789012/data-platform/security-groups.yaml
```

The tenant slug is resolved from the path and must exist in `registry/tenants.yaml`.

## Activation rule

Tenant split is dormant by default.

An account must not use tenant subdirectories unless tenant mode is explicitly enabled for that account by a future feature flag.

Until that flag exists, tenant-path support is only a parsing/resolution contract for validation, summaries, tests, and API design.

## Layout exclusivity

Once tenant mode is enabled for an account, the account should use one layout at a time:

- legacy mode: `accounts/<account-id>/security-groups.yaml`
- tenant mode: `accounts/<account-id>/<tenant>/security-groups.yaml`

Mixed active layouts in the same account should be rejected or blocked by validation once tenant mode is implemented.

A migration may temporarily stage both layouts in a dedicated migration branch, but Terraform/runtime should consume only one normalized account config.

## Account metadata model

Tenant files should repeat the existing required account metadata so each tenant file remains independently readable and reviewable:

```yaml
account_id: "123456789012"
environment: "prod"
carid: "600001725"
default_region: "us-east-1"
regions:
  - "us-east-1"

security_groups:
  app-web:
    description: "Tenant-owned web SG"
```

During merge, account-level metadata across tenant files for the same account must agree.

Conflicting values should be validation errors for:

- `account_id`
- `environment`
- `default_region`
- `regions`

`carid` may eventually be checked against tenant registry `carids`, but it should not become the sole ownership source of truth.

## Tenant ownership model

Tenant ownership comes from `registry/tenants.yaml`, not free-text owner fields inside SG files.

For tenant-path files:

```text
accounts/<account-id>/<tenant>/security-groups.yaml
```

validation should resolve:

- account ID from path
- tenant slug from path
- tenant metadata from registry
- account scope from `tenant.allowed_accounts`

Requestors should not add `tenant:` to the YAML file.

## Security group namespace

Within a tenant file, SG names remain local YAML keys:

```yaml
security_groups:
  app-web:
  app-db:
```

When multiple tenant files are merged for one account, SG names must be globally unique within the account.

Duplicate SG names across tenants should be validation errors unless a future explicit namespace/rendering strategy is created.

## Normalized internal shape

The internal loader should merge tenant files into the same shape Terraform consumes today:

```yaml
account_id: "123456789012"
environment: "prod"
carid: "600001725"
default_region: "us-east-1"
regions:
  - "us-east-1"
security_groups:
  app-web: {}
  app-db: {}
```

Terraform modules should not need to understand tenant directories initially.

Tenant metadata may be carried separately for validation, summaries, API responses, and future review routing.

## Reference rules

Initial tenant-split support should keep reference behavior conservative:

- CIDR references are allowed under existing guardrails.
- Prefix-list references are allowed under existing guardrails.
- Baseline references are allowed only for known baseline refs.
- Same-account SG references need tenant-aware classification before enforcement changes.
- Cross-tenant SG references should be explicit review-policy work, not implicit side effects.
- Cross-account SG references remain discouraged; use CIDR or prefix-list boundaries by default.

## Loader requirements

The tenant-aware loader in `scripts/account_config.py` should:

1. discover active layout for an account
2. reject mixed active layouts unless migration mode is explicitly enabled
3. resolve tenant context through `scripts/tenant_context.py`
4. validate each tenant against `registry/tenants.yaml`
5. verify account metadata consistency across tenant files
6. detect duplicate SG names across tenants
7. produce the current Terraform-compatible normalized account config
8. expose tenant/source metadata to PR summaries and future API responses

The loader is foundation code only. Validation now uses the loader as its input layer for legacy accounts, but tenant-split layout still returns a clear disabled-mode error until a future feature flag enables tenant validation/runtime for a specific account.

## Non-goals

This contract does not implement:

- tenant split deployment
- tenant split feature flags
- tenant owner review enforcement
- cross-tenant approval policy
- API/UI rendering
- automatic tenant onboarding workflow

Those are separate future steps.
