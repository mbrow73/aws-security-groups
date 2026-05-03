# Target-Owned Reference Grants

Reference grants let a referenced tenant pre-approve specific cross-tenant SG references under tightly-scoped conditions.

The grant is owned by the **target tenant**, not the requester.

This avoids review spam while preserving the target owner's control over who can depend on its security groups.

## Problem

Default cross-tenant behavior:

```text
source tenant references target tenant SG -> target tenant approval required
```

That is correct, but some shared SGs are intentionally exposed for common patterns.

Example:

> Any internal tenant may connect to `shared-api` on TCP/443.

Without a grant, every PR referencing that SG would require another target-owner approval forever. That's needless ticket spam.

## Design

Tenants may publish `reference_grants` in `registry/tenants.yaml`.

Example:

```yaml
tenants:
  shared-services:
    display_name: "Shared Services"
    review_authority: "shared-services-sg"

    reference_grants:
      - name: "allow-https-to-shared-api"
        description: "Shared API intentionally accepts HTTPS from internal tenant SGs."
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

Meaning:

> Other tenants may reference `shared-api` with TCP/443 egress without extra target-owner approval.

## Matching rules

A grant matches only when all configured fields match:

- target SG name
- source tenant
- protocol
- port range / port
- direction
- active expiration window

No partial fuzzy matching. No regex. No arbitrary expressions.

## Field definitions

### `name`
Stable grant slug, unique within the tenant.

### `description`
Human-readable reason for the grant.

### `target_sgs`
SGs owned by this tenant that may be referenced under the grant.

### `source_tenants`
Tenants allowed to use the grant.

Supported values:

- explicit tenant slugs, e.g. `payments-platform`
- `*` for all tenants

### `protocols`
Allowed protocols.

Initial supported values should stay boring:

- `tcp`
- `udp`
- `icmp`, only if the validator already supports it safely

### `ports`
Allowed destination ports.

Initial shape:

```yaml
ports:
  - 443
```

Future range shape can be added later if needed:

```yaml
port_ranges:
  - from: 443
    to: 443
```

### `directions`
Rule direction where this grant applies.

Supported values:

- `ingress`
- `egress`

For the common pattern where source tenant egress references target tenant SG, use:

```yaml
directions:
  - "egress"
```

### `decision`
Initial supported value:

```yaml
auto_approved
```

This means no extra target-tenant approval is required when the grant matches.

### `expires`
Optional ISO date for temporary grants.

```yaml
expires: "2026-12-31"
```

`null` means durable until changed by registry PR.

## Review behavior

For cross-tenant SG references:

1. classify source tenant and target tenant
2. check target tenant `reference_grants`
3. if grant matches: no extra target authority approval
4. if no grant matches: require 1 approval from target tenant `review_authority`

The requester tenant's normal approval policy still applies to its own SG change.

## Platform built-ins

Platform built-in SGs such as `vpc-endpoints` do not need reference grants.

They are handled by `registry/platform-security-groups.yaml` and add no extra reviewer when referenced.

## Guardrails

Reference grants should be reviewed like other registry changes.

Do not allow grants to:

- bypass validation for unknown SGs
- create cross-account SG references
- grant broad protocols/ports without a clear reason
- use free-form expressions or regex
- live forever by accident when they are temporary

## Non-goals

This document does not implement grant matching yet. It defines the schema/policy contract before Review Gate and validation consume it.

## Implementation status

Reference grant matching is implemented in validation and Review Gate:

- validation emits `sg_ref_cross_tenant_granted` info when a cross-tenant SG ref matches a target-owned grant
- Review Gate skips the extra target-tenant approval for matching grants
- unmatched cross-tenant refs still require 1 approval from the referenced tenant's `review_authority`
