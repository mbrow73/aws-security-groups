# Operational Model — Baselines vs Team Security Groups

## TL;DR

> **Note:** Baseline SG code lives in [`terraform-aws-eks-baseline-sgs`](https://github.com/mbrow73/terraform-aws-eks-baseline-sgs) (TFC private registry). This repo manages team SGs only.

- **Baselines are immutable.** Platform team owns them. Teams don't touch them.
- **Teams create new SGs** for their workloads via PR.
- **AWS merges rules additively** when multiple SGs attach to the same ENI.

---

## Two Layers of Security Groups

### Layer 1: Baselines (Platform-Owned)

Baseline SGs define the **node-level networking contract** between EKS infrastructure components:

| SG | Owns |
|---|---|
| `baseline-eks-cluster` | Control plane ↔ node communication |
| `baseline-eks-workers` | Worker mesh, DNS, kubelet, VPC endpoints |
| `baseline-istio-*` | Gateway ↔ worker mesh traffic, NLB ingress |
| `baseline-*-nlb` | NLB ingress from corporate or WAF |
| `baseline-vpc-endpoints` | VPC endpoint access from all nodes |

These are:
- **Deployed once** per account when the EKS profile is selected
- **Attached to node groups** by the platform team (launch template / managed node group config)
- **Never modified by application teams**
- **Updated only** when the platform networking pattern changes (new mesh version, new ports, etc.)

### Layer 2: Team SGs (Team-Owned)

Team SGs define **workload-level access** — the stuff unique to each application:

```yaml
# accounts/123456789012/security-groups.yaml
security_groups:
  payments-db-access:
    description: "Payments service database connectivity"
    tags:
      Team: "payments"
      Environment: "production"
      Application: "payments-api"
      ManagedBy: "sg-platform"
    egress:
      - protocol: "tcp"
        from_port: 5432
        to_port: 5432
        security_groups: ["sg-rds-payments-prod"]
        description: "PostgreSQL to payments RDS"
      - protocol: "tcp"
        from_port: 6379
        to_port: 6379
        security_groups: ["sg-redis-payments-prod"]
        description: "Redis session cache"
```

These are:
- **Requested via PR** by the application team
- **Validated** against guardrails automatically
- **Attached as secondary SGs** alongside baselines on the same resources
- **Owned and maintained** by the requesting team

---

## How It Works on the ENI

AWS evaluates all security groups attached to an ENI as a **union** (additive). A node with two SGs:

```
ENI attached SGs:
  1. baseline-eks-workers  → mesh ports, DNS, kubelet, VPC endpoints
  2. payments-db-access    → port 5432 to RDS, port 6379 to Redis
```

The node can do everything in both SGs. No conflicts — rules only **allow**, never deny.

---

## Attachment Model

### EKS Worker Nodes

```
Node Group Launch Template:
  security_groups:
    - baseline-eks-workers     ← platform team (baseline)
    - payments-db-access       ← payments team (PR)
    - logging-export           ← SRE team (PR)
```

### Istio Gateway Nodes

```
Istio Node Group Launch Template:
  security_groups:
    - baseline-istio-nodes     ← platform team (baseline)
```

Istio gateways typically don't need team SGs — they route traffic, they don't originate app-specific connections.

### Non-EKS Resources (RDS, ALB, etc.)

Teams request SGs and attach them directly. No baselines involved.

```
RDS Instance:
  security_groups:
    - payments-rds-access      ← payments team (PR)

ALB:
  security_groups:
    - api-alb-ingress          ← backend team (PR)
```

---

## When to Modify Baselines

Baselines change **only** when the platform networking pattern changes:

| Change | Who | Example |
|---|---|---|
| New istio port | Platform team | Mesh upgrade adds port 15090 for telemetry |
| New VPC endpoint type | Platform team | Adding PrivateLink for a new AWS service |
| Node group restructure | Platform team | Splitting GPU nodes into separate SG |
| mTLS config change | Platform team | Switching from PERMISSIVE to STRICT |

This is a **platform PR**, reviewed by the platform/security team. Never a team self-service request.

---

## Anti-Patterns

| ❌ Don't | ✅ Do Instead |
|---|---|
| Add app-specific rules to `baseline-eks-workers` | Create a new team SG and attach alongside baseline |
| Widen baseline egress to `0.0.0.0/0` for one app | Create a team SG with scoped egress for that app |
| Copy baseline rules into a team SG | Attach baseline SG + team SG together (additive) |
| Request baseline changes for one team's needs | Team creates their own SG for their specific access |
| Attach team SGs to istio gateway nodes | Route through the mesh — istio handles app routing |

---

## Lifecycle

```
Account Onboarding:
  1. Team selects baseline profile (eks-standard or eks-internet)
  2. Platform team deploys baselines via TFC
  3. Baselines attach to node groups in launch templates

Day-to-Day Operations:
  1. Team needs new access (database, external API, cross-service)
  2. Team opens PR adding SG to their account YAML
  3. Validation runs, platform team reviews
  4. Merge → TFC creates the SG
  5. Team attaches SG to their resources (node group, RDS, ALB, etc.)

Baseline Updates (Rare):
  1. Platform team identifies networking change needed
  2. Platform PR updates baseline profile code
  3. Orchestrator tests validate the change
  4. Merge → TFC applies across all accounts using that profile
```
