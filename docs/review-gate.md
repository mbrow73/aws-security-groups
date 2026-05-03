# Review Gate

The Review Gate workflow enforces reviewer authority, not just raw approval count.

## Current authority

`registry/review-authorities.yaml` defines the initial platform SG authority:

- GHE host: `github.aexp.com`
- org: `amex-eng`
- team slug: `nsae`

This authority owns current framework/default-account review decisions, including CIDR, prefix-list, baseline-reference, and legacy single-tenant account changes.

## Required secret

The workflow expects a repository or organization Actions secret named:

```text
REVIEW_GATE_PAT
```

The token must be able to read GitHub Enterprise team membership for the configured authority. For a classic PAT, that means the token owner must be a member of the org and the token must include org-read capability, for example `read:org`.

## Policy

Current rules:

| Change class | Required authority approvals |
|---|---:|
| Nonprod account change | 1 |
| Prod account change | 2 |
| Framework / registry / workflow change | 2 |

Only approvals from members of the configured authority team count toward this gate.

CODEOWNERS can still be used for native GitHub reviewer UX, but Review Gate is the deterministic enforcement layer.

## Future tenant model

Future tenant-specific authorities can be added to the registry and referenced by tenant metadata. The gate should continue to resolve actual approvers against GitHub Enterprise teams using the configured PAT instead of relying only on CODEOWNERS.
