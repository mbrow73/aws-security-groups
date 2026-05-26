# ADR-001: AWS Security Group Self-Service Framework

## Status
Proposed for presentation

## Date
2026-05-06

## Decision

Use a GitHub PR based self-service framework for AWS security group requests, backed by validation, review gates, Terraform Enterprise execution, and curated paved paths for repeated/common enterprise destinations.

The current production-ready scope is intentionally the **single-tenant-per-account** model:

```text
accounts/
  <account-id>/
    security-groups.yaml
```

Each managed AWS account has one `security-groups.yaml` file that represents the account's workload ownership boundary. Teams request new workload security groups or rule changes by opening pull requests against that file.

## Context

Application teams need a repeatable way to request AWS security groups without manual ticket handoffs for every routine change. Platform and NetSec need guardrails, auditability, and a deployment path that does not bypass Terraform or account-level controls.

A fully source-of-record driven verdict engine was considered, but current enterprise metadata sources are not reliable enough to be the only runtime authority for access intent, ownership, PCI/environment boundaries, or destination classification. Source-of-record enrichment may still be valuable, but it should be advisory and confidence-scored rather than treated as policy truth on day one.

## Goals

- Keep requestor YAML simple and reviewable.
- Validate common SG anti-patterns before merge.
- Preserve GitHub PRs as the audit and approval trail.
- Deploy through Terraform Enterprise, not ClickOps.
- Separate platform baseline SGs from team-owned SGs.
- Automate low-risk, repeated, known-good paths over time.
- Route unknown, broad, risky, or ambiguous requests to human review.

## Non-goals

- Replacing all NetSec review with zero-touch automation.
- Using stale or incomplete SoR metadata as the sole authorization source.
- Supporting multi-tenant account folder layouts in the initial production model.
- Making service mesh `ServiceEntry` objects the hard network enforcement boundary for EKS.
- Preferentially using cross-account security group references as the default connectivity model.

## Current Operating Model

### Request path

1. Requestor edits `accounts/<account-id>/security-groups.yaml`.
2. GitHub Actions detect changed accounts.
3. Validation checks schema and guardrails.
4. PR comments summarize the rule delta and validation results.
5. Review Gate / branch protection enforce required approvals and checks.
6. Merge triggers Terraform Enterprise plan/apply workflow for the changed account.

### Supported targets today

Rules may target:

- CIDR blocks
- prefix lists
- same-account SG references
- self references
- platform built-in SG references where explicitly modeled

Cross-account connectivity should be represented with CIDR or prefix-list based rules unless a future platform exception explicitly supports another model.

### Baselines vs team SGs

Platform-owned baseline SGs remain separate from team SGs.

- Baseline SGs define EKS/node/platform networking contracts.
- Team SGs define workload-specific access.
- AWS evaluates attached SGs additively, so team SGs attach alongside baselines instead of modifying baselines.

## Review and Automation Model

The framework should not try to verdict every possible enterprise path on day one. Instead:

1. Start strict for unknowns.
2. Capture structured request data from every PR.
3. Identify repeated destinations and access patterns.
4. Promote safe/common patterns into curated paved paths.
5. Auto-approve future requests that match those paved paths.
6. Keep rare, broad, ambiguous, or regulated-boundary requests human-reviewed.

This approach automates what is known and repeated without pretending enterprise source-of-record data is perfect.

## Paved Path Direction

A future registry can define common enterprise destinations:

```yaml
enterprise_services:
  splunk-hec:
    cidrs:
      - 10.10.20.0/24
    allowed_ports:
      tcp:
        - 8088
    owner: observability-platform
    review: platform-approved
```

A request matching `splunk-hec` on `tcp/8088` can be treated as low-risk once reviewed and promoted. New or unknown destinations continue through normal review.

The framework can also report promotion candidates, for example:

```text
12 PRs requested 10.10.20.0/24 tcp/8088 in the last 30 days.
Consider promoting this to enterprise_services.splunk-hec.
```

## Source-of-Record / Beacon Integration

Source-of-record systems and Beacon-style enrichment may provide useful context:

- app/account ownership hints
- PCI or regulatory flags
- environment labels
- FQDN/GTM/VIP resolution
- zone classification
- confidence scores

These inputs should enrich PR comments and policy hints. They should not be the only authorization source unless confidence and non-repudiation are proven.

A safe model is:

```text
request YAML -> optional SoR enrichment -> validation/policy hints -> PR review or paved-path automation -> TFE deployment
```

If SoR confidence is low, conflicting, or missing, the system should ask for human review or future ownership assertion rather than silently authorizing access.

## EKS Enforcement Position

For AWS/EKS hard network boundaries, Security Groups for Pods are the preferred enforcement primitive where scale and CNI constraints allow. Service mesh entries can help with routing, mTLS, observability, and L7 intent, but they are not a replacement for SG enforcement unless runtime bypass is impossible.

## Consequences

### Positive

- Simple requestor experience.
- Strong Git/Terraform audit trail.
- Lower blast radius than broad account-level/manual changes.
- Clear separation between baseline and team-owned SGs.
- Automation grows from observed demand instead of speculative SoR perfection.
- NetSec review focuses on ambiguous/risky cases instead of every routine request.

### Negative / tradeoffs

- Some human review remains necessary.
- Unknown destinations are not automatically approved.
- Cross-account and on-prem ownership remain harder problems.
- Curated paved paths require platform stewardship.
- SoR/Beacon integration still needs careful confidence and evidence handling.

## Alternatives Considered

### Fully source-of-record driven verdict engine

Rejected as the initial foundation. Enterprise SoR data is not currently reliable enough to infer all access intent, destination ownership, and policy boundaries without a fallback review path.

### Tenant/owned-network/reference-grant registry

Explored and prototyped, but paused. The model captured real non-repudiation needs, but the user experience exposed too many internal policy objects. A future version should be service-oriented if revisited.

### Service mesh `ServiceEntry` as primary control

Rejected as the hard AWS enforcement boundary. Service entries are useful intent/routing objects, but host or pod processes are not necessarily constrained by them unless traffic is forced through the mesh/proxy.

## Open Questions

- Which destinations should be seeded as initial paved paths?
- What promotion threshold should flag a destination as an enterprise-service candidate?
- Which branch protection checks are mandatory in GHE?
- How will TFE/CloudIaC credentials be wired in the enterprise repo?
- Which SoR fields are reliable enough to show as advisory evidence in PR comments?

## Related Documents

- [Current Supported Model](../current-supported-model.md)
- [Operational Model](../operational-model.md)
- [Review Gate](../review-gate.md)
- [GHE Cutover Checklist](../ghe-cutover-checklist.md)
- [Anti-patterns and Mitigations](../anti-patterns-and-mitigations.md)
