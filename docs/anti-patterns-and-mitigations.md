# Anti-Patterns, Risks & Mitigations


> **Note:** Baseline SG code lives in `terraform-aws-eks-baseline-sgs`. This doc covers risks for both baselines and team SGs.
## Risk 1: SG Attachment is Out-of-Band

**Risk:** The platform creates SGs but doesn't attach them to resources. A team could get an SG approved and attach it incorrectly, or not at all.

**Current mitigation:** None — attachment is manual.

**Future mitigation:** Platform becomes the attachment point. Team YAML includes `attach_to` metadata (node group ARN, RDS identifier, ALB ARN), and Terraform handles both SG creation and attachment in a single apply. This closes the gap entirely but adds complexity to the module design.

**Status:** Deferred — tackle after core platform stabilizes.

---

## Risk 2: Additive Rules Blow Open Baselines

**Risk:** AWS SGs are allow-only and additive. A rogue SG attached to the same ENI as a baseline can widen access beyond what the baseline intended (e.g., adding `0.0.0.0/0` egress).

**Mitigation (layered):**

| Layer | Control | Prevents |
|---|---|---|
| **SCP** | Only the TFE workspace role can call `CreateSecurityGroup`, `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, `ModifySecurityGroupRules`, `RevokeSecurityGroupIngress`, `RevokeSecurityGroupEgress` | Console/CLI SG creation or modification by anyone outside TFE |
| **Sentinel** | TFE policy-as-code enforces guardrails at plan time | Overly permissive rules making it through even via Terraform |
| **CloudTrail** | Alert on any SG mutation not originating from the TFE role ARN | Catch anything that bypasses SCP (break-glass, misconfigured SCPs) |
| **Guardrails** | `validate.py` blocks `0.0.0.0/0`, wide port ranges, blocked ports at PR time | Bad rules never reach TFE |

**Key detail:** The SCP must cover ALL SG mutation actions, not just `CreateSecurityGroup`. Without locking `ModifySecurityGroupRules`, someone could alter an existing SG's rules via console without creating a new one.

**Status:** SCP + Sentinel implementation required. Guardrails already in place.

---

## Risk 3: Shared Node Groups = Shared Blast Radius

**Risk:** If multiple teams share a node group, a team SG attached to that node group grants access to all pods — not just that team's.

**Mitigation (already in place):**

1. **Single-tenant accounts** — each AWS account belongs to one team. A team SG on a shared node group only affects that team's workloads.
2. **Istio service entry verdict engine** — L7 authorization policies control which services can communicate, independent of SG rules. SGs are the L3/L4 backstop; Istio handles application-level access.

These two layers together provide defense in depth. SGs don't need pod-level granularity because Istio handles it.

**Status:** Mitigated by architecture. No additional work needed.

---

## Risk 4: Baseline Updates Hit All Accounts

**Risk:** A baseline profile change applies to every account using that profile. A bad change could break clusters across the org.

**Mitigation:**

1. **Formal risk acceptance** — platform team owns baselines and accepts responsibility for blast radius.
2. **Impact discovery required** — before any baseline PR, platform team must document:
   - Which accounts use the affected profile
   - What the change modifies (new ports, removed rules, SG additions)
   - Rollback plan
3. **Canary account** — apply baseline changes to a designated canary account first, validate, then roll out org-wide.
4. **PR template** — baseline changes require a `## Baseline Impact` section documenting affected accounts and rollback steps.

**Status:** Process to be formalized. Canary account pattern to be implemented.

---

## Risk 5: Drift Between YAML and Reality

**Risk:** Console changes to SGs (ClickOps) cause drift from Terraform state. Next TFE apply reverts the manual change.

**Mitigation:**

This is actually **desired behavior** — Terraform auto-heals drift on every apply. The only scenario where this is a problem is break-glass incident response:

1. **Normal operations:** All SG changes go through Terraform. Console access for SG modification is blocked by SCP (Risk 2).
2. **Break-glass:** During a Terraform outage or critical incident, an engineer uses emergency console access to modify an SG. CloudTrail alerts fire. After the incident, the team PRs the change into YAML so the next TFE run preserves it instead of reverting it.
3. **Post-incident:** TFE apply reconciles desired state. If the emergency rule wasn't PR'd, it gets reverted — which is the correct behavior (temporary emergency access should be temporary).

**Status:** Mitigated by SCP (prevents casual drift) + CloudTrail (catches break-glass). No additional work needed.

---

## Risk 6: Cross-Account SG References Don't Work

**Risk:** `referenced_security_group_id` (SG chaining) only works within the same VPC. Cross-account or cross-VPC references fail.

**Mitigation:**

This is expected behavior, not a bug. The platform uses:
- **SG chaining** for intra-VPC rules (baseline SGs referencing each other)
- **CIDRs or prefix lists** for cross-account/cross-VPC access (over TGW, peering, or PrivateLink)

Teams requesting cross-account access use CIDRs in their YAML. The validation pipeline doesn't need to resolve SG IDs against the AWS API because cross-account rules always use CIDRs.

**Status:** By design. No mitigation needed.

---

## Summary

| Risk | Severity | Status |
|---|---|---|
| Out-of-band attachment | Medium | Deferred (future: platform-managed attachment) |
| Additive blow-open | High | Requires SCP + Sentinel implementation |
| Shared blast radius | Low | Mitigated (single-tenant accounts + Istio L7) |
| Baseline blast radius | Medium | Requires process formalization |
| Console drift | Low | Mitigated (SCP + CloudTrail + auto-heal) |
| Cross-account refs | None | By design (CIDRs for cross-account) |
