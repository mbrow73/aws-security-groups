# Auto-Merge Eligibility Policy

Auto-merge is for low-risk, mechanically validated SG changes that do not require human judgment.

This policy defines eligibility only. It does not yet enable bot auto-merge.

## Goals

- reduce unnecessary NetSec/platform touch points
- keep tenant-owned ring-fencing with the tenant where possible
- avoid human review for known-safe platform built-in references such as `vpc-endpoints`
- preserve platform review for framework and ownership-control changes
- fail closed when the policy cannot prove a change is safe

## Non-goals

Auto-merge must not bypass:

- schema validation
- guardrail validation
- registry validation
- TFE/plan checks
- branch protection

Auto-merge is only considered after required checks pass.

## Change categories

### Platform / registry changes

Examples:

```text
.github/**
scripts/**
modules/**
registry/**
guardrails.yaml
known-prefix-lists.yaml
shared-prefix-lists.yaml
```

Policy:

- not auto-merge eligible
- requires platform review

Reason: these files control framework behavior, ownership, approval routing, and shared guardrails.

### Tenant registry changes

Changes to tenant metadata, review authorities, platform SG registry, or reference grants are platform-governed changes.

Policy:

- not auto-merge eligible
- requires platform review

Tenant teams should request these through the tenant registry issue template, but platform/security owns the registry PR.

### Tenant SG changes

Tenant SG intent lives at:

```text
accounts/<account-id>/<tenant>/security-groups.yaml
```

Policy depends on what changed.

## Auto-merge eligible, initial scope

A PR may be auto-merge eligible when all are true:

1. only tenant SG files changed
2. no legacy/default account file changed
3. no framework, workflow, module, registry, guardrail, or prefix-list files changed
4. validation passes with no errors
5. TFE/plan checks pass
6. changed SG references are only same-tenant refs or platform built-ins that explicitly allow requestor references
7. initial platform built-in scope is `vpc-endpoints`
8. no cross-tenant SG refs are introduced or changed
9. no unknown SG refs exist
10. no CIDR or prefix-list auto-merge path is used yet

Initial auto-merge classes:

```text
- same-tenant SG refs through normal security_groups syntax
- platform built-in vpc-endpoints refs through normal security_groups syntax
```

Example:

```yaml
egress:
  - protocol: "tcp"
    from_port: 443
    to_port: 443
    security_groups:
      - "vpc-endpoints"
    description: "HTTPS to interface VPC endpoints"
```

These should not require platform review or tenant review once the automation is trusted. Same-tenant SG refs keep application blast-radius ownership with the tenant team.

## Tenant authority review

Tenant authority review is required for tenant-owned SG changes that are not auto-merge eligible but remain inside the tenant boundary.

Examples:

- tenant-owned CIDR or prefix-list changes that pass guardrails but still need owner judgment
- tenant SG rule changes that alter exposure but do not cross tenant boundaries

Policy:

- nonprod: 1 tenant authority approval
- prod: 2 tenant authority approvals
- no platform review by default

Reason: same-tenant ring-fencing is tenant/application ownership, not a NetSec bottleneck, as long as validation and guardrails pass.

## Platform built-in references

Platform built-ins live in:

```text
registry/platform-security-groups.yaml
```

Current built-in:

```text
vpc-endpoints
```

Policy:

- referencing a platform built-in adds no extra reviewer
- platform built-ins may be auto-merge eligible when they are the only meaningful reference change
- creating/changing the platform built-in registry itself requires platform review

## Cross-tenant references

Cross-tenant SG references are not auto-merge eligible by default.

Policy:

- if the target tenant has a matching `reference_grants` entry, no extra target-owner approval is required
- if no grant matches, require 1 approval from the referenced/target tenant authority
- requester-side review should not sprawl beyond the source tenant's normal policy

## Unknown references

Unknown SG references are validation errors.

Policy:

- not auto-merge eligible
- cannot be approved by review alone
- must be fixed in YAML or platform registry

## Future automation shape

The policy summary artifact should eventually emit:

```json
{
  "auto_merge_eligible": true,
  "auto_merge_reason": "only platform built-in vpc-endpoints refs changed"
}
```

Bot auto-merge should only act when:

- `auto_merge_eligible` is true
- required validation/checks pass
- branch protection allows merge
- no human review requirement remains

## Rollout recommendation

Start with the narrowest class:

```text
same-tenant and vpc-endpoints-only tenant SG changes
```

CIDR/prefix-list auto-merge is intentionally out of scope for the initial rollout. A later version may allow it through an explicit allowlist file of approved destinations plus approved ports/protocols.

Do not auto-merge cross-tenant refs unless the target-owned grant model has been proven safe and leadership explicitly accepts that behavior.
