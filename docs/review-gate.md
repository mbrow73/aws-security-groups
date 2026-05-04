# Review Gate

The Review Gate workflow enforces reviewer authority, not just raw approval count.

CODEOWNERS can still be used for native GitHub reviewer UX, but Review Gate is the deterministic enforcement layer.

## Authority registry

`registry/review-authorities.yaml` maps authority names to GitHub Enterprise teams.

Initial platform SG authority:

- authority: `platform-sg`
- GHE host: `github.aexp.com`
- org: `amex-eng`
- team slug: `nsae`

The workflow expects a repository or organization Actions secret named:

```text
REVIEW_GATE_PAT
```

The token must be able to read GitHub Enterprise team membership for configured authorities. For a classic PAT, that means the token owner must be a member of the org and the token must include org-read capability, for example `read:org`.

## Tenant authority

Tenants should reference an authority by name:

```yaml
tenants:
  payments-platform:
    review_authority: "payments-sg"
```

The authority itself resolves to the GHE team:

```yaml
authorities:
  payments-sg:
    ghe_host: "github.aexp.com"
    org: "amex-eng"
    team_slug: "payments-platform"
```

This keeps GHE team details centralized and avoids repeating raw team URLs in tenant metadata.

## Policy

| Change class | Required authority approvals |
|---|---:|
| Nonprod legacy/default account change | 1 `platform-sg` |
| Prod legacy/default account change | 2 `platform-sg` |
| Nonprod tenant SG change | 1 tenant `review_authority` |
| Prod tenant SG change | 2 tenant `review_authority` |
| Framework / registry / workflow change | 2 `platform-sg` |
| Platform built-in SG ref, e.g. `vpc-endpoints` | no extra reviewer |
| Same-tenant SG ref | no extra reviewer |
| Cross-tenant SG ref with matching target-owned reference grant | no extra reviewer |
| Cross-tenant SG ref without matching grant | 1 referenced/target tenant `review_authority` |
| Unknown SG ref | validation error |

Review Gate combines requirements by authority and uses the highest required count for each authority.

Example: if a prod tenant change requires 2 approvals from `payments-sg` and also references a `data-platform` SG, the gate requires:

- 2 approvals from `payments-sg`
- 1 approval from `data-platform` authority

It does not add requester-side review sprawl for cross-tenant references; only the referenced owner is mandatory beyond the source change's normal policy. If the target tenant publishes a matching [Reference Grant](reference-grants.md), the extra target-owner approval is skipped.

## Tenant onboarding

The tenant onboarding issue template should collect either:

- an existing `review_authority`, or
- the GitHub Enterprise team URL/slug needed to create one.

Platform/security converts approved onboarding requests into registry PRs for:

- `registry/tenants.yaml`
- `registry/review-authorities.yaml`, when a new authority is needed

## Registry validation

`registry/review-authorities.yaml` is validated by the SG validator. Authority slugs, required fields, rule authority references, and approval counts must be valid before Review Gate policy should be trusted.
