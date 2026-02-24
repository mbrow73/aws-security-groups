# ADR-001: Centralized Security Group Management Platform

| Field | Value |
|-------|-------|
| **Status** | Proposed |
| **Date** | 2026-02-23 |
| **Proposed by** | Maximilian Browne |
| **Stakeholders** | Cloud Platform Engineering, Security, Application Teams |
| **Supersedes** | Manual SG management via AFT policy modules |

---

## Context

Security group management across our AWS organization has historically been fragmented. Teams either create security groups ad-hoc through ClickOps, embed them in application Terraform alongside business logic, or rely on AFT account customizations to deploy policy-layer SGs during provisioning. This has led to:

- **Inconsistent naming and tagging** across accounts, making audit and inventory unreliable
- **Overly permissive rules** that go unreviewed (wide port ranges, broad CIDR scopes)
- **Custom SGs coupled to AFT**, turning an account factory into a policy deployment engine - a single SG template leaks identical rules to every account regardless of workload requirements
- **No visibility** into what security groups exist, who owns them, or why they were created
- **Drift** between what was intended and what's deployed, with no detection mechanism

As we scale EKS adoption with strict mTLS via Istio service mesh, the need for precise, zero-trust security group configurations has become critical. A single misconfigured rule can break mesh traffic or expose internal services.

## Decision

We will implement a **two-layer security group management platform** consisting of:

1. **Baseline Security Groups** - platform-owned, immutable EKS networking SGs published as a versioned Terraform module on the TFE private registry
2. **Team Security Groups** - self-service, PR-driven SG requests with automated validation, deployed via Terraform Enterprise

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 1: BASELINES                       │
│              (Platform Team Owned & Operated)               │
│                                                             │
│   terraform-aws-eks-baseline-sgs (TFE Private Registry)    │
│   ┌───────────────┐ ┌───────────────┐ ┌────────────────┐   │
│   │ eks-standard  │ │ eks-internet  │ │ vpc-endpoints  │   │
│   │ (5 SGs)       │ │ (7 SGs)       │ │ (1 SG)         │   │
│   │ Intranet EKS  │ │ Internet EKS  │ │ Standalone     │   │
│   └───────┬───────┘ └───────┬───────┘ └───────┬────────┘   │
│           │  auto-includes  │  auto-includes   │            │
│           └────────►VPCe◄───┘                  │            │
│                                                             │
│   Consumed by: AFT Account Customizations                  │
│   Changed via: PR → Review → Version Tag → Registry        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                 LAYER 2: TEAM SECURITY GROUPS               │
│                (Team Owned, Platform Validated)              │
│                                                             │
│   aws-security-groups (GitHub)                              │
│   ┌─────────┐    ┌──────────┐    ┌─────┐    ┌─────────┐   │
│   │ Team    │───►│ GitHub   │───►│ TFE │───►│ AWS SGs │   │
│   │ YAML PR │    │ Actions  │    │     │    │         │   │
│   └─────────┘    │Validation│    │Plan/│    └─────────┘   │
│                  └──────────┘    │Apply│                   │
│                                  └─────┘                   │
│   Changed via: PR → Automated Validation → TFE Deploy      │
└─────────────────────────────────────────────────────────────┘
```

### Team SG Request Flow

```
Developer                    Platform                        AWS
   │                            │                              │
   │  1. Create YAML PR         │                              │
   │  (accounts/<id>/sg.yaml)   │                              │
   │───────────────────────────►│                              │
   │                            │                              │
   │  2. GitHub Actions runs    │                              │
   │     validate.py            │                              │
   │     - Schema checks        │                              │
   │     - Guardrails           │                              │
   │     - Naming conventions   │                              │
   │     - Tag compliance       │                              │
   │     - Duplicate detection  │                              │
   │◄───────────────────────────│                              │
   │  3. PR comment with        │                              │
   │     validation results     │                              │
   │                            │                              │
   │  4. Fix issues (if any),   │                              │
   │     get approval           │                              │
   │───────────────────────────►│                              │
   │                            │                              │
   │  5. Merge to main          │                              │
   │───────────────────────────►│  6. TFE workspace triggered  │
   │                            │────────────────────────────►│
   │                            │  7. terraform apply          │
   │                            │  8. SG created with rules    │
   │                            │◄────────────────────────────│
   │                            │                              │
   │  9. Team references SG ID  │                              │
   │     in their own infra     │                              │
   │─────────────────────────────────────────────────────────►│
   │                            │  10. SG attached to resource │
   │                            │                              │
```

### Automatic TFE Workspace Provisioning

When a PR introducing a new account is merged to main, the platform automatically provisions a TFE workspace:

```
New Account PR                Platform                        TFE
   │                            │                              │
   │  1. PR creates             │                              │
   │  accounts/<new-id>/sg.yaml │                              │
   │───────────────────────────►│                              │
   │                            │                              │
   │  2. Validation runs on PR  │                              │
   │     (schema, guardrails)   │                              │
   │◄───────────────────────────│                              │
   │                            │                              │
   │  3. NetSec reviews,        │                              │
   │     approves, merges       │                              │
   │───────────────────────────►│                              │
   │                            │                              │
   │  4. Post-merge workflow    │                              │
   │     detects new account    │                              │
   │     directory in diff      │                              │
   │                            │  5. TFE API: create workspace│
   │                            │  (per-account state isolation)│
   │                            │────────────────────────────►│
   │                            │                              │
   │                            │  6. Configure VCS trigger,   │
   │                            │     working directory,       │
   │                            │     OIDC auth, variables     │
   │                            │────────────────────────────►│
   │                            │                              │
   │                            │  7. New workspace triggers   │
   │                            │     first apply              │
   │                            │────────────────────────────►│
   │                            │                              │
```

Each AWS account gets an isolated TFE workspace with its own state. Workspace creation is triggered post-merge by the presence of a new `accounts/<id>/` directory in the diff. No workspace is provisioned until NetSec has reviewed and approved the PR. No manual TFE setup required.

### Baseline Change Flow

```
Platform Engineer              Module Repo                    TFE / Registry
   │                              │                              │
   │  1. PR with rule changes     │                              │
   │────────────────────────────►│                              │
   │                              │                              │
   │  2. TFE speculative plan     │                              │
   │     validates changes        │                              │
   │◄────────────────────────────│                              │
   │                              │                              │
   │  3. NetSec review + approval │                              │
   │────────────────────────────►│                              │
   │                              │                              │
   │  4. Merge + version tag      │                              │
   │────────────────────────────►│  5. Registry picks up tag    │
   │                              │────────────────────────────►│
   │                              │                              │
   │  6. Bump version pin in      │                              │
   │     canary account first     │                              │
   │                              │                              │
   │  7. Validate, then roll out  │                              │
   │     to remaining accounts    │                              │
   │                              │                              │
```

## Baseline Security Group Profiles

### eks-standard - Intranet-Only EKS

5 security groups, 37 rules. All cross-SG traffic uses security group references (SG chaining).

| Security Group | Purpose | Attached To |
|----------------|---------|-------------|
| `baseline-eks-cluster` | Control plane ↔ node communication | EKS cluster |
| `baseline-eks-workers` | Worker mesh, DNS, kubelet, VPC endpoints | Node group launch template |
| `baseline-istio-nodes` | Istio gateway: ingress from NLB SG, egress to worker mesh SG | Istio node group launch template |
| `baseline-intranet-nlb` | Ingress from corporate prefix list, forwarding to Istio nodes SG | Intranet NLB |
| `baseline-vpc-endpoints` | VPC endpoint access from all nodes | VPC interface endpoints |

**Traffic flow:**
```
Corporate Network → Intranet NLB → Istio Nodes → Worker Pods (via envoy sidecar)
                                                       │
                                              EKS Cluster (API server)
                                                       │
                                              VPC Endpoints (ECR, S3, STS)
```

### eks-internet - Internet + Intranet EKS

7 security groups, ~57 rules. NLB client IP preservation enabled - Istio targets see the WAF's outbound NAT IPs (the true upstream source) rather than the NLB's private IPs, enabling security group rules scoped to WAF origin.

| Security Group | Purpose | Attached To |
|----------------|---------|-------------|
| `baseline-eks-cluster` | Control plane (shared, serves both paths) | EKS cluster |
| `baseline-eks-workers` | Worker mesh (shared, ingress from both istio SGs) | Node group launch template |
| `baseline-istio-intranet-nodes` | Intranet istio gateways | Intranet istio node group |
| `baseline-intranet-nlb` | Corporate prefix list ingress | Intranet NLB |
| `baseline-istio-inet-nodes` | Internet istio gateways | Internet istio node group |
| `baseline-internet-nlb` | WAF NAT IP ingress (client IP preserved) | Internet NLB |
| `baseline-vpc-endpoints` | VPC endpoint access | VPC interface endpoints |

**Traffic flow:**
```
Internet → WAF → NAT IPs → Internet NLB → Istio Inet Nodes ─┐
                                                               ├─► Worker Pods
Corporate → Intranet NLB → Istio Intranet Nodes ─────────────┘      │
                                                              EKS Cluster
                                                                     │
                                                              VPC Endpoints
```

### vpc-endpoints - Standalone

1 security group, 1 rule. For non-EKS accounts needing VPC endpoint access.

| Security Group | Purpose | Attached To |
|----------------|---------|-------------|
| `baseline-vpc-endpoints` | HTTPS (443) from VPC CIDR to interface endpoint ENIs. Requires `vpc_cidr` input variable. | VPC interface endpoints |

## Alternatives Considered

### Alternative 1: Continue with AFT-Managed Security Groups

**Description:** Keep security groups as AFT account customization modules. Teams request changes through the AFT pipeline.

| Pros | Cons |
|------|------|
| Already in place, no migration needed | Custom SGs are coupled to the account factory lifecycle - SG changes require a full AFT customization pipeline run |
| Single pipeline for account provisioning | Single SG template applied uniformly - the same rules leak to every account regardless of workload requirements |
| Git-backed with PR reviews (inherits AFT workflow) | No per-account customization without forking the template or adding conditional logic |
| Teams can submit customization requests (self-service exists) | No workload-level guardrails - AFT validates account structure, not SG rule quality |
| Familiar to the team | Blast radius of template changes is every account using that customization |
| | No separation between baseline (platform networking) and team (workload access) SGs - everything is one flat layer |
| | Difficult to version and roll out SG changes independently of account provisioning |

**Decision:** Rejected. AFT provides a functional delivery mechanism, but the single-template model cannot express per-account workload requirements. Custom SGs need their own lifecycle independent of account provisioning, and baseline networking SGs need independent versioning and rollout control that AFT customizations don't support. Baselines remain in AFT as a versioned module consumer; custom SGs move to a dedicated platform.

### Alternative 2: AWS Firewall Manager

**Description:** Use AWS Firewall Manager to centrally manage security group policies across the organization.

| Pros | Cons |
|------|------|
| AWS-native, integrates with AWS Organizations | SG chaining requires dynamic, per-VPC security group ID references - FMS replicates SGs but cannot resolve cross-SG references to VPC-local IDs, making multi-SG relationship models impractical |
| Automatic remediation - can enforce and revert non-compliant SGs | Coarse-grained policy model - "common SG" policies apply uniformly to all matching resources, not per-workload |
| Built-in compliance reporting and audit SG policies | Limited rule-level guardrails - policies operate at the SG level, not individual rule validation |
| Can be managed via Terraform (`aws_fms_policy`) - GitOps is possible | "Audit" policies detect violations but cannot express complex rules like "block port ranges >1000" |
| "Common security group" policies can deploy SGs to matching resources automatically | No separation of baseline vs team SGs - policies apply organization-wide by resource tag or type |
| | Cost: per-policy per-region pricing scales with org complexity |

**Decision:** Rejected. Firewall Manager provides strong compliance auditing and can be IaC-managed, but its policy model is too coarse for our requirements. FMS can replicate SGs containing security group references, but those references are static SG IDs - they don't resolve to VPC-local SGs in each target account. Our baseline requires 5-7 SGs per VPC with cross-references that are unique per deployment, which is foundational to our zero-trust EKS networking model. Its strength is enforcing uniform policies across the org - useful for guardrails, but insufficient as the primary SG management platform where per-workload customization is required.

### Alternative 3: Service Catalog

**Description:** Publish security group products in AWS Service Catalog. Teams launch products to get pre-approved SGs.

| Pros | Cons |
|------|------|
| AWS-native self-service with built-in approval workflows | Traditional products are CloudFormation - adds a CFN maintenance layer |
| Portfolio-level access control and governance | Terraform Enterprise Engine for Service Catalog exists but adds architectural complexity (SC → TFE → AWS) |
| Can be managed via Terraform (`aws_servicecatalog_*`) for GitOps | Validation is limited to CFN constraints or launch constraints - no custom guardrail logic (blocked ports, naming, PCI warnings) |
| Built-in product versioning and constraint management | Self-service UX defaults to the Service Catalog console - Git-native PR workflow requires additional tooling |
| Can be provisioned by consumers via Terraform (`aws_servicecatalog_provisioned_product`) | Difficult to express SG chaining in product parameters without complex nested stacks |
| | Adds an abstraction layer between the team and the SG - debugging requires tracing through SC → product → resources |

**Decision:** Rejected. Service Catalog provides governance and self-service capabilities, but adds an abstraction layer that increases complexity without meaningful benefit over a direct Git-to-Terraform pipeline. Custom validation logic (blocked ports, naming conventions, PCI DSS warnings, duplicate detection) would need to be reimplemented outside of SC's native constraints. The direct PR workflow provides equivalent self-service with better auditability and simpler debugging.

### Alternative 4: Centralized Transit Gateway with AWS Network Firewall

**Description:** Route all inter-VPC and egress traffic through a centralized inspection VPC using Transit Gateway and AWS Network Firewall. Enforce security policy at the network layer rather than per-resource security groups.

**Intended model:** Single-tenant application VPCs with open intra-VPC access (broad baseline SGs like 10.0.0.0/8) and Network Firewall at the TGW segmenting inter-application traffic. Each VPC is one app, so intra-VPC trust is acceptable. The firewall enforces app-to-app boundaries - "payments VPC can reach auth VPC on 443, nothing else."

| Pros | Cons |
|------|------|
| Clean two-tier model: SGs for intra-VPC, firewall for inter-VPC | **NAT gateways obscure source identity** - traffic arrives at the firewall with the NAT gateway's private IP, not the originating workload's IP. Workload-level attribution becomes impractical without significant additional complexity (e.g., per-workload NAT pools). |
| Centralized inter-app segmentation at the VPC boundary | Loses practical ability to write meaningful L4 rules based on source workload identity without additional architectural workarounds |
| Deep packet inspection, IDS/IPS for cross-VPC flows | Intra-VPC security becomes entirely dependent on broad SGs with no chaining - acceptable for single-tenant, but loses defense-in-depth |
| Single-tenant VPCs mean intra-VPC trust is a reasonable tradeoff | TGW routing complexity grows with every VPC and peering relationship |
| Unified cross-VPC traffic logging and visibility | Firewall becomes a single point of failure for all inter-app communication |

**Decision:** Rejected. This would be the preferred architecture if NAT gateways did not obscure source identity. The model is sound - single-tenant VPCs with a centralized firewall segmenting inter-app traffic. However, NAT gateways rewrite the source IP on egress, making it impractical for Network Firewall to attribute traffic to specific workloads without additional complexity (per-workload NAT pools, custom routing). Without source identity, firewall rules degrade from "workers in payments VPC can reach auth VPC" to "the NAT IP in payments VPC can reach auth VPC" - significantly reducing the value of centralized inspection.

The SG chaining approach preserves source identity at every hop (security group references, not CIDRs), which is why we chose per-VPC security group management over centralized firewall inspection.

## Consequences

### Positive

- **Zero-trust by default** - baseline SGs use SG chaining exclusively. New EKS clusters start with least-privilege networking.
- **Self-service without sacrificing security** - teams get SGs in minutes via PR, not days via ticket. Guardrails prevent dangerous configs automatically.
- **Immutable baselines** - platform team controls EKS networking SGs. Teams cannot modify them. Changes are versioned and rolled out via registry.
- **Full audit trail** - every SG and every rule change is a Git commit with PR review, author attribution, and approval history.
- **Validated at every stage** - PR validation catches schema and guardrail violations, TFE speculative plans catch Terraform errors, and SCP enforcement prevents out-of-band changes.
- **Separation of concerns** - baselines (platform) and team SGs (self-service) have independent lifecycles, repos, and deployment pipelines.

### Negative

- **Two repos to maintain** - baseline module and team SG platform are separate codebases. Mitigated by clear ownership boundaries: Platform Engineering owns baselines, Network Security owns self-service.
- **SG attachment is out-of-band** - the platform creates SGs but does not attach them to resources. Attachment is the consumer's responsibility. Mitigated by tagging and AWS Config detection.
- **Prefix list management is centralized** - adding a new prefix list entry requires a baseline module PR. This is intentional (security control) but adds friction for urgent changes.
- **Learning curve** - teams must learn the YAML schema and PR workflow. Mitigated by the team guide, example templates, and clear validation error messages.

### Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Rogue SG attached alongside baseline widens access | Medium | High | SGs are additive (allow-only), but guardrails ensure team SGs are scoped. AWS Config detects unexpected attachments. |
| Baseline change breaks clusters org-wide | Low | Critical | Version pinning, canary account rollout, terraform test suite, PR review requirement. |
| Team bypasses platform, creates SGs directly | Medium | Medium | SCP restricts SG creation/modification to TFE workspace roles. Detective controls via AWS Config. |
| Stale prefix list entries | Low | Medium | Centralized management ensures consistency. Periodic review process. |
| TFE outage blocks SG deployments | Low | Medium | Break-glass procedure documented. Emergency changes via CLI with audit trail. |

## Implementation

### Repositories

| Repository | Purpose | Owner | CODEOWNERS |
|------------|---------|-------|------------|
| `terraform-aws-eks-baseline-sgs` | Baseline SG module (TFE private registry) | Platform Engineering | Network Security (policy review) |
| `aws-security-groups` | Team self-service SG platform | Network Security | Network Security |

**Ownership model:**
- **Platform Engineering** owns baseline SG operations - they deploy, version, and are responsible for outages caused by rule changes.
- **Network Security** reviews all baseline policy changes as CODEOWNERS and owns the self-service platform (guardrails, validation, team PR approvals).
- **Application Teams** submit PRs to the self-service repo. They own their workload-level SGs but cannot modify baselines.

### Validation Pipeline

The team SG platform includes automated validation that runs on every PR:

| Check | Description | Blocking |
|-------|-------------|----------|
| Schema validation | Required fields, correct types, unknown key detection, invalid character filtering | Yes |
| Guardrails | Blocked ports (telnet, SMB, NetBIOS), overly permissive ingress, broad port ranges | Yes |
| Naming conventions | Pattern enforcement for SG names | Yes |
| Tag compliance | Required tags: ManagedBy, Team, Environment, Application | Yes |
| Duplicate detection | Identical rules within the same SG | Yes |
| Environment validation | Must be prod, test, or dev | Yes |
| PCI DSS warnings | Advisory warnings for relevant configurations | No (warning only) |

### Rollout Plan

| Phase | Scope | Timeline |
|-------|-------|----------|
| 1. Module publication | Publish baseline module to TFE private registry | Week 1 |
| 2. Canary deployment | Deploy baselines to one non-production account via AFT | Week 2 |
| 3. Production baselines | Roll out to all EKS accounts, replace AFT-managed SGs | Weeks 3-4 |
| 4. Team onboarding | Enable self-service for first team, iterate on docs | Week 5 |
| 5. SCP enforcement | Restrict direct SG creation to TFE workspace roles | Week 6 |
| 6. Full rollout | All teams onboarded, AFT SG modules decommissioned | Weeks 7-8 |

## References

- [Operational Model](./operational-model.md) - Detailed two-layer SG model documentation
- [Anti-Patterns & Mitigations](./anti-patterns-and-mitigations.md) - Risk analysis and layered defenses
- [Team Guide](./team-guide.md) - How to request security groups
- Baseline Profiles (BASELINE-PROFILES.md in baseline module repo) - Complete SG rule tables
