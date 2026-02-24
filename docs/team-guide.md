# Team Guide — Requesting Security Groups

## Quick Start

1. Copy the example:
   ```bash
   cp -r accounts/_example accounts/<your-account-id>
   ```

2. Edit `accounts/<your-account-id>/security-groups.yaml`:
   ```yaml
   account_id: "123456789012"
   environment: "prod"
   baseline_profiles:
     - eks-standard

   security_groups:
     my-app-db-access:
       description: "My app database connectivity"
       tags:
         Team: "my-team"
         Environment: "prod"
         Application: "my-app"
         ManagedBy: "sg-platform"
       egress:
         - protocol: "tcp"
           from_port: 5432
           to_port: 5432
           prefix_list_ids: ["database-subnets"]
           description: "PostgreSQL access"
   ```

3. Open a PR to `main`.

4. Validation runs automatically — fix any errors and push.

5. Once approved and merged, Terraform Enterprise deploys your SGs.

## YAML Schema

```yaml
account_id: "123456789012"          # Required: 12-digit AWS account ID
environment: "prod"            # Required: prod | test | dev

baseline_profiles:                   # Optional: pre-built SG sets
  - eks-standard                     # Intranet-only EKS (auto-includes vpc-endpoints)
  # - eks-internet                   # Internet + intranet EKS (mutually exclusive with eks-standard)

security_groups:
  sg-name:                           # Name becomes the SG name prefix
    description: "What this SG is for"
    tags:
      Team: "your-team"              # Required
      Environment: "prod"      # Required
      Application: "your-app"        # Required
      ManagedBy: "sg-platform"       # Required
    ingress:                         # Inbound rules
      - protocol: "tcp"
        from_port: 443
        to_port: 443
        cidr_blocks: ["10.0.0.0/8"]             # CIDR source
        # security_groups: ["sg-abc123"]         # OR SG reference
        # prefix_list_ids: ["corporate-networks"] # OR prefix list
        # self: true                              # OR self-reference
        description: "Why this rule exists"
    egress:                          # Outbound rules (same format as ingress)
      - protocol: "tcp"
        from_port: 443
        to_port: 443
        prefix_list_ids: ["aws-vpc-endpoints"]
        description: "VPC endpoint access"
```

## Available Prefix Lists

| Name | Description |
|---|---|
| `corporate-networks` | Corporate offices + VPN |
| `waf-saas-providers` | Cloudflare, Fastly ranges |
| `aws-vpc-endpoints` | AWS service endpoint ranges |
| `database-subnets` | RDS subnet CIDRs |
| `alb-subnets` | ALB subnet CIDRs |
| `ci-cd-systems` | GitHub Actions, Jenkins runners |
| `monitoring-services` | DataDog, New Relic |

## Baseline Profiles

See [BASELINE-PROFILES.md](https://github.com/mbrow73/terraform-aws-eks-baseline-sgs/blob/main/BASELINE-PROFILES.md) for full SG/rule tables.

| Profile | What You Get |
|---|---|
| `eks-standard` | 4 EKS SGs + vpc-endpoints (intranet only) |
| `eks-internet` | 6 EKS SGs + vpc-endpoints (internet + intranet) |
| `vpc-endpoints` | 1 SG for VPC endpoint access (standalone) |

Baselines are platform-managed. Don't add app-specific rules to them — create your own SG instead. See [Operational Model](operational-model.md).

## What Gets Blocked

- `0.0.0.0/0` ingress or egress
- Ports 22 (SSH), 3389 (RDP) — use Session Manager
- Database ports open to wide CIDRs
- Missing required tags
- Duplicate rules

## Validation

Run locally before pushing:
```bash
python scripts/validate.py accounts/<your-account-id>/security-groups.yaml
```
