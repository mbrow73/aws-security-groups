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
- **Overly permissive rules** that go unreviewed (e.g., `0.0.0.0/0` ingress, wide port ranges)
- **No guardrails** preventing dangerous configurations before they reach AWS
- **Baseline SGs coupled to AFT**, turning an account factory into a policy deployment engine
- **No visibility** into what security groups exist, who owns them, or why they were created
- **Drift** between what was intended and what's deployed, with no detection mechanism

As we scale EKS adoption with strict mTLS via Istio service mesh, the need for precise, zero-trust security group configurations has become critical. A single misconfigured rule can break mesh traffic or expose internal services.

## Decision

We will implement a **two-layer security group management platform** consisting of:

1. **Baseline Security Groups** - platform-owned, immutable EKS networking SGs published as a versioned Terraform module on the TFC private registry
2. **Team Security Groups** - self-service, PR-driven SG requests with automated validation, deployed via Terraform Cloud

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 1: BASELINES                       │
│              (Platform Team Owned & Operated)               │
│                                                             │
│   terraform-aws-eks-baseline-sgs (TFC Private Registry)    │
│   ┌───────────────┐ ┌───────────────┐ ┌────────────────┐   │
│   │ eks-standard  │ │ eks-internet  │ │ vpc-endpoints  │   │
│   │ (4 SGs)       │ │ (6 SGs)       │ │ (1 SG)         │   │
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
│   │ Team    │───►│ GitHub   │───►│ TFC │───►│ AWS SGs │   │
│   │ YAML PR │    │ Actions  │    │     │    │         │   │
│   └─────────┘    │Validation│    │Plan/│    └─────────┘   │
│                  └──────────┘    │Apply│                   │
│                                  └─────┘                   │
│   Changed via: PR → Automated Validation → TFC Deploy      │
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
   │───────────────────────────►│  6. TFC workspace triggered  │
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

### Baseline Change Flow

```
Platform Engineer              Module Repo                    Registry
   │                              │                              │
   │  1. PR with rule changes     │                              │
   │────────────────────────────►│                              │
   │                              │                              │
   │  2. Terraform test suite     │                              │
   │     (mock_provider, no AWS)  │                              │
   │◄────────────────────────────│                              │
   │                              │                              │
   │  3. Peer review + approval   │                              │
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

5 security groups, 38 rules. All cross-SG traffic uses security group references (SG chaining).

| Security Group | Purpose | Attached To |
|----------------|---------|-------------|
| `baseline-eks-cluster` | Control plane ↔ node communication | EKS cluster |
| `baseline-eks-workers` | Worker mesh, DNS, kubelet, VPC endpoints | Node group launch template |
| `baseline-istio-nodes` | Istio gateway ↔ worker mesh, NLB ingress | Istio node group launch template |
| `baseline-intranet-nlb` | Corporate/on-prem ingress | Intranet NLB |
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

7 security groups, ~58 rules. Client IP preservation enabled - istio sees WAF NAT IPs, not NLB private IPs.

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

1 security group, 2 rules. For non-EKS accounts needing VPC endpoint access.

| Security Group | Purpose | Attached To |
|----------------|---------|-------------|
| `baseline-vpc-endpoints` | HTTPS/HTTP from VPC CIDR to endpoint ENIs | VPC interface endpoints |

## Alternatives Considered

### Alternative 1: Continue with AFT-Managed Security Groups

**Description:** Keep security groups as AFT account customization modules. Teams request changes through the AFT pipeline.

| Pros | Cons |
|------|------|
| Already in place, no migration needed | AFT is an account factory, not a policy engine |
| Single pipeline for account provisioning | SG changes require full AFT pipeline run |
| Familiar to the team | No PR-level validation or guardrails |
| | No self-service - platform team bottleneck |
| | No versioning of SG configurations |
| | Blast radius of AFT changes is entire account |

**Decision:** Rejected. AFT should provision accounts, not manage ongoing security policy.

### Alternative 2: AWS Firewall Manager

**Description:** Use AWS Firewall Manager to centrally manage security group policies across the organization.

| Pros | Cons |
|------|------|
| AWS-native, no custom tooling | Coarse-grained - applies policies to all resources matching criteria |
| Automatic remediation | Cannot express SG chaining (security group references) |
| Built-in compliance reporting | Limited rule logic - no port-level guardrails |
| Integrates with AWS Organizations | No GitOps workflow, ClickOps management |
| | Cost: per-policy per-region pricing |
| | Doesn't support the two-layer (baseline + team) model |

**Decision:** Rejected. Firewall Manager cannot express the SG chaining model required for zero-trust EKS networking. It's designed for broad organizational policies, not precise per-cluster security group configurations.

### Alternative 3: Service Catalog with CloudFormation

**Description:** Publish security group products in AWS Service Catalog. Teams launch products to get pre-approved SGs.

| Pros | Cons |
|------|------|
| AWS-native self-service with approval workflows | Products are CloudFormation under the hood - adds a CFN layer on top of Terraform |
| Can be provisioned via Terraform (`aws_servicecatalog_provisioned_product`) | Limited validation - only what CFN constraints and launch constraints support natively |
| Portfolio-level access control and governance | No SG chaining support in CF parameters - difficult to express security group references |
| Built-in versioning of products | Product updates require maintaining both CFN templates and Terraform consumers |
| | Self-service UX is the Service Catalog console, not a Git-native PR workflow |

**Decision:** Rejected. While Service Catalog products can be consumed via Terraform, the underlying products are still CloudFormation templates. This creates a dual-IaC maintenance burden (CFN for products, Terraform for consumers) without adding validation capabilities beyond what we achieve with the PR-based pipeline. The Git-native workflow provides better auditability, team familiarity, and guardrail flexibility.

### Alternative 4: Centralized Transit Gateway with AWS Network Firewall

**Description:** Route all inter-VPC and egress traffic through a centralized inspection VPC using Transit Gateway and AWS Network Firewall. Enforce security policy at the network layer rather than per-resource security groups.

**Intended model:** Single-tenant application VPCs with open intra-VPC access (broad baseline SGs like 10.0.0.0/8) and Network Firewall at the TGW segmenting inter-application traffic. Each VPC is one app, so intra-VPC trust is acceptable. The firewall enforces app-to-app boundaries - "payments VPC can reach auth VPC on 443, nothing else."

| Pros | Cons |
|------|------|
| Clean two-tier model: SGs for intra-VPC, firewall for inter-VPC | **NAT gateways destroy source identity** - traffic arrives at the firewall with the NAT gateway's private IP, not the originating workload's IP. Firewall rules degrade to "allow NAT IP" instead of "allow this service." |
| Centralized inter-app segmentation at the VPC boundary | Loses the ability to write meaningful L4 rules based on source workload identity |
| Deep packet inspection, IDS/IPS for cross-VPC flows | Intra-VPC security becomes entirely dependent on broad SGs with no chaining - acceptable for single-tenant, but loses defense-in-depth |
| Single-tenant VPCs mean intra-VPC trust is a reasonable tradeoff | TGW routing complexity grows with every VPC and peering relationship |
| Unified cross-VPC traffic logging and visibility | Firewall becomes a single point of failure for all inter-app communication |

**Decision:** Rejected. This would be the preferred architecture if NAT gateways did not obscure source identity. The model is sound - single-tenant VPCs with a centralized firewall segmenting inter-app traffic. However, NAT gateways rewrite the source IP on egress, making it impossible for Network Firewall to attribute traffic to specific workloads. Without source identity, firewall rules cannot express "workers in payments VPC can reach auth VPC" - only "the NAT IP in payments VPC can reach auth VPC." This eliminates the primary value of centralized inspection.

The SG chaining approach preserves source identity at every hop (security group references, not CIDRs), which is why we chose per-VPC security group management over centralized firewall inspection.

## Consequences

### Positive

- **Zero-trust by default** - baseline SGs use SG chaining exclusively. New EKS clusters start with least-privilege networking.
- **Self-service without sacrificing security** - teams get SGs in minutes via PR, not days via ticket. Guardrails prevent dangerous configs automatically.
- **Immutable baselines** - platform team controls EKS networking SGs. Teams cannot modify them. Changes are versioned and rolled out via registry.
- **Full audit trail** - every SG and every rule change is a Git commit with PR review, author attribution, and approval history.
- **Testable without AWS credentials** - Terraform test suite uses `mock_provider`, enabling CI validation and local development without cloud access.
- **Separation of concerns** - baselines (platform) and team SGs (self-service) have independent lifecycles, repos, and deployment pipelines.

### Negative

- **Two repos to maintain** - baseline module and team SG platform are separate codebases. Increases surface area for maintenance.
- **SG attachment is out-of-band** - the platform creates SGs but does not attach them to resources. Attachment is the consumer's responsibility. Mitigated by tagging and AWS Config detection.
- **Prefix list management is centralized** - adding a new prefix list entry requires a baseline module PR. This is intentional (security control) but adds friction for urgent changes.
- **Learning curve** - teams must learn the YAML schema and PR workflow. Mitigated by the team guide, example templates, and clear validation error messages.

### Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Rogue SG attached alongside baseline widens access | Medium | High | SGs are additive (allow-only), but guardrails ensure team SGs are scoped. AWS Config detects unexpected attachments. |
| Baseline change breaks clusters org-wide | Low | Critical | Version pinning, canary account rollout, terraform test suite, PR review requirement. |
| Team bypasses platform, creates SGs directly | Medium | Medium | SCP restricts SG creation/modification to TFC workspace roles. Detective controls via AWS Config. |
| Stale prefix list entries | Low | Medium | Centralized management ensures consistency. Periodic review process. |
| TFC outage blocks SG deployments | Low | Medium | Break-glass procedure documented. Emergency changes via CLI with audit trail. |

## Implementation

### Repositories

| Repository | Purpose | Owner | CODEOWNERS |
|------------|---------|-------|------------|
| [`terraform-aws-eks-baseline-sgs`](https://github.com/mbrow73/terraform-aws-eks-baseline-sgs) | Baseline SG module (TFC private registry) | Platform Engineering | Network Security (policy review) |
| [`aws-security-groups`](https://github.com/mbrow73/aws-security-groups) | Team self-service SG platform | Network Security | Network Security |

**Ownership model:**
- **Platform Engineering** owns baseline SG operations - they deploy, version, and are responsible for outages caused by rule changes.
- **Network Security** reviews all baseline policy changes as CODEOWNERS and owns the self-service platform (guardrails, validation, team PR approvals).
- **Application Teams** submit PRs to the self-service repo. They own their workload-level SGs but cannot modify baselines.

### Validation Pipeline

The team SG platform includes automated validation that runs on every PR:

| Check | Description | Blocking |
|-------|-------------|----------|
| Schema validation | Required fields, correct types, unknown key detection | Yes |
| Guardrails | Blocked ports (telnet, SMB, NetBIOS), overly permissive ingress, broad port ranges | Yes |
| Naming conventions | Pattern enforcement for SG names | Yes |
| Tag compliance | Required tags: ManagedBy, Team, Environment, Application | Yes |
| Duplicate detection | Identical rules within the same SG | Yes |
| Environment validation | Must be prod, test, or dev | Yes |
| PCI DSS warnings | Advisory warnings for relevant configurations | No (warning only) |

### Rollout Plan

| Phase | Scope | Timeline |
|-------|-------|----------|
| 1. Module publication | Publish baseline module to TFC private registry | Week 1 |
| 2. Canary deployment | Deploy baselines to one non-production account via AFT | Week 2 |
| 3. Production baselines | Roll out to all EKS accounts, replace AFT-managed SGs | Weeks 3-4 |
| 4. Team onboarding | Enable self-service for first team, iterate on docs | Week 5 |
| 5. SCP enforcement | Restrict direct SG creation to TFC workspace roles | Week 6 |
| 6. Full rollout | All teams onboarded, AFT SG modules decommissioned | Weeks 7-8 |

## References

- [Operational Model](./operational-model.md) - Detailed two-layer SG model documentation
- [Anti-Patterns & Mitigations](./anti-patterns-and-mitigations.md) - Risk analysis and layered defenses
- [Team Guide](./team-guide.md) - How to request security groups
- [Baseline Profiles](https://github.com/mbrow73/terraform-aws-eks-baseline-sgs/blob/main/BASELINE-PROFILES.md) - Complete SG rule tables
